<?php

namespace App\Console\Commands;

use App\Models\ActivityLog;
use Illuminate\Console\Command;
use Throwable;

class RedactActivityLog extends Command
{
    protected $signature = 'security:redact-activity-log
        {--backup= : Absolute JSONL evidence path outside the application directory}
        {--apply : Redact the snapshotted rows only after the backup has been verified}';

    protected $description = 'Preserve restricted audit evidence, then optionally redact credential values without deleting events';

    public function handle(): int
    {
        $file = null;
        $oldUmask = umask(0077);
        try {
            $path = $this->option('backup');
            if (!is_string($path) || !str_starts_with($path, DIRECTORY_SEPARATOR)) {
                throw new \RuntimeException('An absolute backup path is required');
            }
            $directory = realpath(dirname($path));
            $application = realpath(base_path());
            if ($directory === false || $directory === $application || str_starts_with($directory . '/', $application . '/')) {
                throw new \RuntimeException('Backup directory must exist outside the application');
            }
            $path = $directory . DIRECTORY_SEPARATOR . basename($path);
            if (file_exists($path) || is_link($path) || file_exists($path . '.sha256') || is_link($path . '.sha256')) {
                throw new \RuntimeException('Evidence files must not already exist');
            }
            $file = fopen($path, 'x+b');
            if ($file === false || !chmod($path, 0600)) {
                throw new \RuntimeException('Cannot create restricted evidence file');
            }
            $model = new ActivityLog();
            $connection = $model->getConnection();
            $table = $model->getTable();
            $upperId = $connection->table($table)->max('id') ?? 0;
            $count = 0;
            $connection->table($table)->where('id', '<=', $upperId)->orderBy('id')->chunkById(100, function ($rows) use ($file, &$count) {
                foreach ($rows as $row) {
                    $line = json_encode($row, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
                    if (fwrite($file, $line) !== strlen($line)) {
                        throw new \RuntimeException('Incomplete evidence write');
                    }
                    $count++;
                }
            });
            if (!fflush($file) || !fsync($file)) {
                throw new \RuntimeException('Evidence flush failed');
            }
            $digest = hash_file('sha256', $path);
            $checksum = fopen($path . '.sha256', 'x');
            if ($checksum === false) {
                throw new \RuntimeException('Cannot create evidence checksum');
            }
            try {
                if (fwrite($checksum, $digest . "\n") !== 65 || !fflush($checksum) || !fsync($checksum)) {
                    throw new \RuntimeException('Evidence checksum write failed');
                }
            } finally {
                fclose($checksum);
            }
            rewind($file);
            $hash = hash_init('sha256');
            hash_update_stream($hash, $file);
            if (!hash_equals($digest, hash_final($hash))) {
                throw new \RuntimeException('Evidence verification failed');
            }
            $this->info("Verified restricted evidence for $count audit rows: $path");
            if (!$this->option('apply')) {
                $this->info('Backup only; audit records were not changed.');
                return self::SUCCESS;
            }

            rewind($file);
            $updated = $conflicts = 0;
            while (($line = fgets($file)) !== false) {
                $row = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
                $activity = (new ActivityLog())->newFromBuilder($row);
                $activity->redactSensitiveData(true);
                $dirty = array_intersect_key($activity->getDirty(), array_flip(['properties', 'description']));
                if ($dirty === []) {
                    continue;
                }
                $changed = $connection->transaction(function () use ($connection, $table, $row, $dirty) {
                    $query = $connection->table($table)->where('id', $row['id']);
                    $current = $query->lockForUpdate()->first();
                    // Byte-exact PHP comparison avoids case-insensitive SQL collations.
                    if ($current === null || (array) $current !== $row) {
                        return false;
                    }
                    return $query->update($dirty) === 1;
                });
                if ($changed) {
                    $updated++;
                } else {
                    $conflicts++;
                }
            }
            $this->info("Redacted $updated audit rows; concurrent conflicts: $conflicts. No events were deleted.");
            return $conflicts === 0 ? self::SUCCESS : self::FAILURE;
        } catch (Throwable $exception) {
            // Database exceptions may include the old credential-bearing row bindings.
            $this->error('Audit redaction stopped (' . $exception::class . '). Preserve any evidence file; no automatic deletion or rollback was performed.');
            return self::FAILURE;
        } finally {
            if (is_resource($file)) {
                fclose($file);
            }
            umask($oldUmask);
        }
    }
}
