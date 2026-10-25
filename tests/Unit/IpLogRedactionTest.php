<?php

namespace Tests\Unit;

use App\Repositories\IpLogRepository;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

class IpLogRedactionTest extends TestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCredentialPathsNeverEnterTheRedisToDatabaseBuffer(): void
    {
        define('IN_NEXUS', true);
        require_once dirname(__DIR__, 2) . '/include/constants.php';
        require_once dirname(__DIR__, 2) . '/include/globalfunctions.php';
        $directory = sys_get_temp_dir() . '/ip-log-test-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        putenv('NEXUS_LOG_DIR=' . $directory);
        $redis = new class {
            public array $fields = [];
            public function hincrby($key, $field, $count) { $this->fields[] = $field; return 1; }
            public function expire($key, $ttl) { return true; }
        };
        $GLOBALS['Cache'] = new class($redis) {
            public function __construct(private object $redis) {}
            public function getRedis() { return $this->redis; }
        };
        try {
            $_SERVER['REQUEST_URI'] = '/login-secret-canary/passkey-canary';
            IpLogRepository::saveToCache(101, null, ['127.0.0.1']);
            IpLogRepository::saveToCache(101, '/torrents.php?auth_key=query-canary', ['127.0.0.1']);
            IpLogRepository::saveToCache(101, '/nexusphp/users/123', ['127.0.0.1']);
            self::assertSame([
                '101|127.0.0.1|/[dynamic-route]',
                '101|127.0.0.1|/torrents.php',
                '101|127.0.0.1|/[dynamic-route]',
            ], $redis->fields);
            foreach (glob($directory . '/*') as $file) {
                self::assertStringNotContainsString('canary', file_get_contents($file));
            }
        } finally {
            foreach (glob($directory . '/*') as $file) unlink($file);
            rmdir($directory);
        }
    }
}
