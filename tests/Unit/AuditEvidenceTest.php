<?php

namespace Tests\Unit;

use App\Console\Commands\RedactActivityLog;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\Support\IsolatedActivityTestCase;

class AuditEvidenceTest extends IsolatedActivityTestCase
{
    public function testCaseOnlyConcurrentEditIsNotOverwritten(): void
    {
        $this->app['db']->table('users')->insert(['id' => 1, 'username' => 'test', 'auth_key' => 'race-canary']);
        $this->app['db']->table('activity_log')->insert([
            'subject_type' => \App\Models\User::class, 'subject_id' => 1,
            'description' => 'updated race-canary', 'event' => 'updated',
            'properties' => json_encode(['auth_key' => 'race-canary']),
        ]);
        // The subject is resolved after the snapshot, before the attempted update.
        $this->app['events']->listen('eloquent.retrieved: ' . \App\Models\User::class, function () {
            $this->app['db']->table('activity_log')->update(['description' => 'UPDATED race-canary']);
        });
        $directory = sys_get_temp_dir() . '/audit-race-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        try {
            $command = new RedactActivityLog();
            $command->setLaravel($this->app);
            $tester = new CommandTester($command);
            self::assertSame(1, $tester->execute(['--backup' => $directory . '/audit.jsonl', '--apply' => true]));
            self::assertSame('UPDATED race-canary', $this->app['db']->table('activity_log')->value('description'));
        } finally {
            foreach (glob($directory . '/*') as $file) unlink($file);
            rmdir($directory);
        }
    }

    public function testEvidenceIsVerifiedBeforeRedactionAndEventsAreRetained(): void
    {
        $this->app['db']->table('activity_log')->insert([
            'description' => 'updated', 'event' => 'updated', 'subject_type' => null,
            'properties' => json_encode(['old' => ['auth_key' => 'historical-canary'], 'attributes' => ['username' => 'keep-name']]),
            'created_at' => '2026-01-01 00:00:00', 'updated_at' => '2026-01-01 00:00:00',
        ]);
        $directory = sys_get_temp_dir() . '/audit-evidence-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        $path = $directory . '/audit.jsonl';
        try {
            $command = new RedactActivityLog();
            $command->setLaravel($this->app);
            $tester = new CommandTester($command);
            self::assertSame(0, $tester->execute(['--backup' => $path, '--apply' => true]));
            self::assertSame(0600, fileperms($path) & 0777);
            self::assertSame(hash_file('sha256', $path), trim(file_get_contents($path . '.sha256')));
            self::assertStringContainsString('historical-canary', file_get_contents($path));
            self::assertStringNotContainsString('historical-canary', $this->auditBytes());
            self::assertStringContainsString('keep-name', $this->auditBytes());
            self::assertSame(1, $this->app['db']->table('activity_log')->count());
            self::assertSame('2026-01-01 00:00:00', $this->app['db']->table('activity_log')->value('created_at'));
            self::assertSame(1, $tester->execute(['--backup' => $path, '--apply' => true]));
            self::assertStringContainsString('historical-canary', file_get_contents($path));
        } finally {
            foreach (glob($directory . '/*') as $file) unlink($file);
            rmdir($directory);
        }
    }

    public function testPublicBackupPathIsRejectedWithoutChangingRows(): void
    {
        $command = new RedactActivityLog();
        $command->setLaravel($this->app);
        $tester = new CommandTester($command);
        self::assertSame(1, $tester->execute(['--backup' => base_path('public/evidence.jsonl'), '--apply' => true]));
        self::assertFileDoesNotExist(base_path('public/evidence.jsonl'));
    }
}
