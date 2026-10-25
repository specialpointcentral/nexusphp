<?php

namespace Tests\Unit;

use App\Logging\NexusFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\PreserveGlobalState;

class SensitiveLogTest extends TestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testEmergencyFallbackAlsoRedactsCredentials(): void
    {
        $app = require dirname(__DIR__, 2) . '/bootstrap/app.php';
        $file = tempnam(sys_get_temp_dir(), 'nexus-emergency-');
        $app->instance('config', new \Illuminate\Config\Repository([
            'logging' => ['channels' => ['emergency' => ['path' => $file]]],
        ]));
        try {
            $app['log']->channel('missing-test-channel')->warning('Fallback diagnostic', [
                'auth_key' => 'emergency-secret-canary', 'operation' => 'test',
            ]);
            $bytes = file_get_contents($file);
            self::assertStringNotContainsString('emergency-secret-canary', $bytes);
            self::assertStringContainsString('Fallback diagnostic', $bytes);
            self::assertStringContainsString('test', $bytes);
        } finally {
            unlink($file);
        }
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLegacyFileAndEchoNeverContainPasskeyOrStructuredSecrets(): void
    {
        define('IN_NEXUS', true);
        require_once dirname(__DIR__, 2) . '/include/constants.php';
        require_once dirname(__DIR__, 2) . '/include/globalfunctions.php';
        $directory = sys_get_temp_dir() . '/nexus-log-test-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        putenv('NEXUS_LOG_DIR=' . $directory);
        $_SERVER['HTTP_X_REQUEST_ID'] = 'request-id-secret-canary';
        \Nexus\Nexus::boot();
        $GLOBALS['CURUSER'] = ['id' => 101, 'passkey' => 'prefix-canary'];
        ob_start();
        do_log('user operation auth_key=message-canary; result=ok', 'info', true);
        do_log('Cache lookup nexus_user_passkey_prefix-canary', 'info', true);
        $GLOBALS['CURUSER'] = [];
        $_REQUEST['authkey'] = 'request-canary';
        do_log('safe operation', 'info', true);
        require_once dirname(__DIR__, 2) . '/include/functions.php';
        $GLOBALS['smtptype'] = 'none';
        self::assertFalse(sent_mail('user@example.test', 'Tracker', 'site@example.test', 'Recovery', '<br />密码：mail-canary<br />'));
        $echo = ob_get_clean();
        $output = $echo . file_get_contents(getLogFile());
        $stream = fopen('php://memory', 'w+');
        $logger = new Logger('request-id-test', [new StreamHandler($stream)]);
        (new NexusFormatter())($logger);
        $logger->info('safe request-id operation');
        rewind($stream);
        $output .= stream_get_contents($stream);
        fclose($stream);
        try {
            foreach (['prefix-canary', 'message-canary', 'request-canary', 'mail-canary', 'request-id-secret-canary'] as $secret) {
                self::assertStringNotContainsString($secret, $output);
            }
            self::assertStringContainsString('safe operation', $output);
            self::assertStringContainsString('[101]', $output);
        } finally {
            foreach (glob($directory . '/*') as $file) unlink($file);
            rmdir($directory);
            putenv('NEXUS_LOG_DIR');
        }
    }

    public function testRealMonologOutputRedactsNestedCredentialsAndRequestTargets(): void
    {
        require_once dirname(__DIR__, 2) . '/include/globalfunctions.php';
        $stream = fopen('php://memory', 'w+');
        $logger = new Logger('security-test', [new StreamHandler($stream)]);
        (new NexusFormatter())($logger);
        $logger->warning('OAuth callback https://tracker.test/path-canary/?access_token=query-canary', [
            'headers' => ['Authorization' => 'Bearer header-canary', 'Cookie' => 'session=cookie-canary'],
            'payload' => ['auth_key' => 'context-canary', 'username' => 'visible-user'],
            'exception' => new \RuntimeException('password=exception-canary'),
        ]);
        rewind($stream);
        $output = stream_get_contents($stream);
        foreach (['path-canary', 'query-canary', 'header-canary', 'cookie-canary', 'context-canary', 'exception-canary'] as $secret) {
            self::assertStringNotContainsString($secret, $output);
        }
        self::assertStringContainsString('visible-user', $output);
        self::assertStringContainsString('WARNING', $output);
        fclose($stream);
    }
}
