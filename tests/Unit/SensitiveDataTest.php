<?php

namespace Tests\Unit;

use App\Support\SensitiveData;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class SensitiveDataTest extends TestCase
{
    #[DataProvider('logMessages')]
    public function testEncodedAndMalformedCredentialMessagesDoNotLeak(string $message): void
    {
        self::assertStringNotContainsString('credential-canary', SensitiveData::redactText($message));
    }

    public static function logMessages(): array
    {
        return [
            ['auth%5fkey=credential-canary&event=update'],
            ['request: {"auth_key":"credential-canary"}'],
            ['request: {\\"auth_key\\":\\"credential-canary\\"}'],
            ['request: {"\\u0061uth_key":"credential-canary"}'],
            ['request: {"password":["credential-canary"]}'],
            ['request: {"secret":{"nested":"credential-canary"}}'],
            ['auth_key[0]=credential-canary'],
            ['request: {"password":"quote\\"credential-canary"}'],
            ['request: {"auth_key":"credential-canary'],
            ['setting: {"name":"smtp.accountpassword","value":"credential-canary"}'],
            ['INSERT INTO settings (name,value) VALUES (\'smtp.accountpassword\',\'credential-canary\')'],
            ['Authorization: Bearer credential-canary'],
            ['Cookie: session=credential-canary; other=credential-canary'],
            ['request https://tracker.test/credential-canary/announce?key=credential-canary'],
            ['useChallengeResponse, client response: credential-canary, !hash_equals'],
            ['expectedResponse: credential-canary, login successful'],
            ['two_step_code=credential-canary'],
        ];
    }

    public function testNonSecretAuditAndLogMetadataRemainsUseful(): void
    {
        $data = ['username' => 'alice', 'class' => 3, 'enabled' => true, 'password_client' => false, 'download_support_passkey' => 'yes'];
        self::assertSame($data, SensitiveData::redact($data));
        self::assertSame('user 101 updated enabled=yes', SensitiveData::redactText('user 101 updated enabled=yes'));
    }

    public function testCredentialPathSegmentsAndNestedCookieMapsAreRedacted(): void
    {
        $secret = str_repeat('a', 32);
        self::assertStringNotContainsString($secret, SensitiveData::redactText('GET /login/' . $secret));
        $encoded = str_repeat('%61', 32);
        self::assertStringNotContainsString($encoded, SensitiveData::redactText('GET /login/' . $encoded));
        self::assertSame(['cookies' => SensitiveData::REDACTED], SensitiveData::redact(['cookies' => ['PHPSESSID' => 'cookie-value']]));
    }

    public function testShortSecretsDoNotCorruptEventNamesAndRedactionIsIdempotent(): void
    {
        $result = SensitiveData::redact(['password' => 'a', 'event' => 'updated', 'note' => 'key a']);
        self::assertSame('updated', $result['event']);
        self::assertSame('key [REDACTED]', $result['note']);
        self::assertSame($result, SensitiveData::redact($result));
    }

    public function testEncodedCopiesAndAssociativeKeysDoNotRetainCredentials(): void
    {
        $result = SensitiveData::redact([
            'auth_key' => 'canary/key',
            'copy' => '%63anary%2fkey',
            'nested_copy' => '%2563anary%252fkey',
            'canary/key' => 'operation',
            'master_key' => 'master-canary',
        ]);
        $bytes = json_encode($result, JSON_UNESCAPED_SLASHES);
        foreach (['%63anary', '%2563anary', 'canary/key', 'master-canary'] as $secret) {
            self::assertStringNotContainsString($secret, $bytes);
        }
    }
}
