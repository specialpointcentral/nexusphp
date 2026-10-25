<?php

namespace Tests\Unit;

use App\Models\Setting;
use App\Models\User;
use App\Models\UserMeta;
use App\Models\OauthClient;
use Tests\Support\IsolatedActivityTestCase;

class SensitiveAuditTest extends IsolatedActivityTestCase
{
    public function testCredentialOnlyRotationStillProducesAnAuditEventWithoutTheKey(): void
    {
        $user = new User();
        $user->forceFill(['username' => 'rotation-user', 'auth_key' => 'before-rotation-canary'])->save();
        $user->forceFill(['auth_key' => 'after-rotation-canary'])->save();
        self::assertSame(['created', 'updated'], $this->app['db']->table('activity_log')->pluck('event')->all());
        self::assertStringNotContainsString('before-rotation-canary', $this->auditBytes());
        self::assertStringNotContainsString('after-rotation-canary', $this->auditBytes());
    }

    public function testEventMetadataIsPreservedEvenWhenASecretCoincidesWithIt(): void
    {
        Setting::create(['name' => 'smtp.accountpassword', 'value' => 'created']);
        self::assertSame('created', $this->app['db']->table('activity_log')->value('event'));
        self::assertSame('default', $this->app['db']->table('activity_log')->value('log_name'));
    }

    public function testGeneratedAuthenticationAndOAuthSecretsRemainOnlyInBusinessTables(): void
    {
        $user = new User();
        $user->forceFill(['username' => 'generated-user'])->save();
        $client = new OauthClient();
        $client->forceFill(['name' => 'test-client'])->save();
        self::assertNotEmpty($user->auth_key);
        self::assertNotEmpty($client->secret);
        self::assertSame($user->auth_key, $this->app['db']->table('users')->value('auth_key'));
        self::assertSame($client->secret, $this->app['db']->table('oauth_clients')->value('secret'));
        self::assertStringNotContainsString($user->auth_key, $this->auditBytes());
        self::assertStringNotContainsString($client->secret, $this->auditBytes());
    }

    public function testUserMetaValueOnlyChangesDoNotLeakSecrets(): void
    {
        $meta = UserMeta::create(['uid' => 1, 'meta_key' => 'two_step_secret', 'meta_value' => 'meta-original-canary']);
        $meta->update(['meta_value' => 'meta-rotated-canary']);
        $meta->delete();
        self::assertStringNotContainsString('meta-original-canary', $this->auditBytes());
        self::assertStringNotContainsString('meta-rotated-canary', $this->auditBytes());
        self::assertSame(3, $this->app['db']->table('activity_log')->count());
    }

    public function testUserLifecycleNeverPersistsCredentialValuesInAudit(): void
    {
        $secrets = [];
        foreach (['auth_key', 'passhash', 'password', 'secret', 'editsecret', 'passkey', 'two_step_secret', 'remember_token'] as $key) {
            $secrets[$key] = 'canary-' . $key . '-do-not-log';
        }
        $user = new User();
        $user->forceFill(['username' => 'audit-user'] + $secrets)->save();
        $user->forceFill(['username' => 'renamed-user', 'auth_key' => 'rotated-auth-canary'])->save();
        self::assertSame('rotated-auth-canary', $this->app['db']->table('users')->value('auth_key'));
        $user->delete();
        $bytes = $this->auditBytes();
        foreach ([...array_values($secrets), 'rotated-auth-canary'] as $secret) {
            self::assertStringNotContainsString($secret, $bytes);
        }
        self::assertStringContainsString('renamed-user', $bytes);
        self::assertSame(['created', 'updated', 'deleted'], $this->app['db']->table('activity_log')->pluck('event')->all());
    }

    public function testSettingValueOnlyUpdatesAndNameTransitionsAreRedacted(): void
    {
        $setting = Setting::create(['name' => 'smtp.accountpassword', 'value' => 'initial-setting-canary']);
        $setting->update(['value' => 'updated-setting-canary']);
        $setting->update(['name' => 'main.site_name', 'value' => 'Public tracker']);
        $setting->update(['name' => 'backup.google_drive_refresh_token', 'value' => 'refresh-setting-canary']);
        $setting->delete();
        $bytes = $this->auditBytes();
        foreach (['initial-setting-canary', 'updated-setting-canary', 'refresh-setting-canary'] as $secret) {
            self::assertStringNotContainsString($secret, $bytes);
        }
        self::assertStringContainsString('main.site_name', $bytes);
        self::assertSame(5, $this->app['db']->table('activity_log')->count());
    }

    public function testManualActivityNestedPropertiesAndExpandedDescriptionsAreRedacted(): void
    {
        $user = new User();
        $user->forceFill(['username' => 'safe-user', 'auth_key' => 'subject-canary', 'passkey' => 'actor-canary'])->save();
        activity()->performedOn($user)->causedBy($user)->withProperties([
            'auth_key' => 'property-canary',
            'nested' => ['client_secret' => 'nested-canary', 'count' => 7],
            'json' => json_encode(['two_step_secret' => 'json-canary']),
            'record' => ['name' => 'smtp.accountpassword', 'value' => 'indirect-canary'],
            'note' => 'copied key: subject-canary',
        ])->log('user :subject.username keys :subject.auth_key :causer.passkey :properties.auth_key');
        $bytes = $this->auditBytes();
        foreach (['subject-canary', 'actor-canary', 'property-canary', 'nested-canary', 'json-canary', 'indirect-canary'] as $secret) {
            self::assertStringNotContainsString($secret, $bytes);
        }
        self::assertStringContainsString('safe-user', $bytes);
        self::assertStringContainsString('count', $bytes);
    }

    public function testHistoricalSettingWithoutItsSubjectIsConservativelyRedacted(): void
    {
        $activity = new \App\Models\ActivityLog();
        $activity->subject_type = Setting::class;
        $activity->subject_id = 999;
        $activity->properties = collect(['old' => ['value' => 'deleted-setting-canary']]);
        $activity->description = 'changed deleted-setting-canary';
        $activity->redactSensitiveData(true);
        self::assertStringNotContainsString('deleted-setting-canary', json_encode($activity->getAttributes()));
    }
}
