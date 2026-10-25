<?php

namespace Tests\Support;

use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Database\DatabaseServiceProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use Spatie\Activitylog\ActivitylogServiceProvider;
use Spatie\Activitylog\CauserResolver;

abstract class IsolatedActivityTestCase extends TestCase
{
    protected Application $app;

    protected function setUp(): void
    {
        parent::setUp();
        defined('IN_NEXUS') || define('IN_NEXUS', false);
        require_once dirname(__DIR__, 2) . '/include/constants.php';
        require_once dirname(__DIR__, 2) . '/include/globalfunctions.php';
        $this->app = new Application(dirname(__DIR__, 2));
        Application::setInstance($this->app);
        Facade::setFacadeApplication($this->app);
        $this->app->instance('config', new Repository([
            'activitylog' => require dirname(__DIR__, 2) . '/config/activitylog.php',
            'database' => ['default' => 'sqlite', 'connections' => ['sqlite' => ['driver' => 'sqlite', 'database' => ':memory:']]],
            'nexus' => ['database' => ['default' => 'sqlite']],
        ]));
        $this->app->instance('events', new Dispatcher($this->app));
        $provider = $this->app->register(DatabaseServiceProvider::class);
        $provider->boot();
        $this->app->instance(AuthManager::class, new AuthManager($this->app));
        $this->app->register(ActivitylogServiceProvider::class);
        $this->app->make(CauserResolver::class)->resolveUsing(fn ($subject) => $subject instanceof Model ? $subject : null);
        $schema = $this->app['db']->connection()->getSchemaBuilder();
        $schema->create('activity_log', function (Blueprint $table) {
            $table->increments('id');
            $table->string('log_name')->nullable();
            $table->text('description')->collation('NOCASE');
            $table->nullableMorphs('subject');
            $table->nullableMorphs('causer');
            $table->string('event')->nullable();
            $table->string('batch_uuid')->nullable();
            $table->text('properties')->nullable();
            $table->timestamps();
        });
        $schema->create('users', function (Blueprint $table) {
            $table->increments('id');
            foreach (['username', 'auth_key', 'passhash', 'password', 'secret', 'editsecret', 'passkey', 'two_step_secret', 'remember_token', 'status', 'enabled'] as $name) {
                $table->string($name)->nullable();
            }
        });
        $schema->create('settings', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->text('value')->nullable();
            $table->string('autoload')->default('yes');
            $table->timestamps();
        });
        $schema->create('oauth_clients', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('secret')->nullable();
            $table->timestamps();
        });
        $schema->create('user_metas', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('uid');
            $table->string('meta_key');
            $table->text('meta_value');
            $table->timestamps();
        });
    }

    protected function auditBytes(): string
    {
        return json_encode($this->app['db']->table('activity_log')->orderBy('id')->get()->all(), JSON_THROW_ON_ERROR);
    }

    protected function tearDown(): void
    {
        $this->app['db']->disconnect();
        Model::clearBootedModels();
        Model::unsetEventDispatcher();
        Model::unsetConnectionResolver();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Application::setInstance(null);
        parent::tearDown();
    }
}
