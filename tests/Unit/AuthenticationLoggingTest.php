<?php

namespace Tests\Unit;

use App\Models\User;
use App\Repositories\AuthenticateRepository;
use Carbon\Carbon;
use Illuminate\Cache\CacheServiceProvider;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Tests\Support\IsolatedActivityTestCase;

class AuthenticationLoggingTest extends IsolatedActivityTestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testInvalidSignatureIsLoggedWithoutKeyAndValidSignatureStillWorks(): void
    {
        $directory = sys_get_temp_dir() . '/ammds-log-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        putenv('NEXUS_LOG_DIR=' . $directory);
        $this->app['config']->set('cache', ['default' => 'array', 'stores' => ['array' => ['driver' => 'array']]]);
        $this->app->register(CacheServiceProvider::class);
        $this->app['config']->set('nexus.ammds_secret', 'hmac-key-canary');
        $passkey = str_repeat('a', 32);
        $this->app['db']->table('users')->insert(['id' => 1, 'username' => 'test', 'passkey' => $passkey, 'status' => 'confirmed', 'enabled' => 'yes']);
        $fields = User::$commonFields;
        User::$commonFields = ['id', 'username', 'passkey', 'status', 'enabled'];
        try {
            $repository = new AuthenticateRepository();
            $timestamp = Carbon::now()->getTimestampMs();
            try {
                $repository->ammdsApprove(Request::create('/', 'POST', ['uid' => 1, 'timestamp' => $timestamp, 'nonce' => 'invalid-attempt', 'signature' => 'invalid-signature']));
                self::fail('Invalid signature was accepted');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Invalid signature.', $exception->getMessage());
            }
            $signature = hash_hmac('sha256', '1' . hash('sha256', $passkey) . $timestamp . 'valid-attempt', 'hmac-key-canary');
            $user = $repository->ammdsApprove(Request::create('/', 'POST', ['uid' => 1, 'timestamp' => $timestamp, 'nonce' => 'valid-attempt', 'signature' => $signature]));
            self::assertSame(1, $user->id);
            $output = file_get_contents(getLogFile());
            self::assertStringNotContainsString('hmac-key-canary', $output);
            self::assertStringNotContainsString(hash('sha256', $passkey), $output);
            self::assertStringContainsString('uid', $output);
        } finally {
            User::$commonFields = $fields;
            foreach (glob($directory . '/*') as $file) unlink($file);
            rmdir($directory);
            putenv('NEXUS_LOG_DIR');
        }
    }
}
