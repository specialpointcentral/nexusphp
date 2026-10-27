<?php

namespace Tests\Unit;

use Illuminate\Bus\Dispatcher;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Bus\Dispatcher as DispatcherContract;
use Illuminate\Queue\Capsule\Manager;
use Illuminate\Queue\Connectors\ConnectorInterface;
use Illuminate\Queue\NullQueue;
use Illuminate\Support\Facades\Facade;
use Nexus\Imdb\Imdb;
use Nexus\Nexus;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Support/ImdbQueueEnvironment.php';
require_once __DIR__ . '/../../include/globalfunctions.php';
require_once __DIR__ . '/../../include/functions.php';

#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
class ImdbQueueTest extends TestCase
{
    private Repository $cache;
    private NullQueue $queue;
    private Imdb $imdb;
    private string $directory;

    private function boot(bool $legacy): void
    {
        define('IN_NEXUS', $legacy);
        $container = new Container();
        Container::setInstance($container);
        Facade::setFacadeApplication($container);
        $this->cache = new Repository(new ArrayStore());
        $container->instance('cache', $this->cache);
        $GLOBALS['Cache'] = new class($this->cache) {
            public function __construct(private Repository $cache) {}
            public function get_value($key) { return $this->cache->get($key); }
            public function cache_value($key, $value, $ttl) { return $this->cache->put($key, $value, $ttl); }
            public function delete_value($key, $all = false) { return $this->cache->forget($key); }
        };
        $GLOBALS['imdbTestLogs'] = [];
        // Replace only the external queue transport. Both dispatch paths remain real.
        $this->queue = new class extends NullQueue {
            public array $jobs = [];
            public bool $fail = false;
            public function push($job, $data = '', $queue = null)
            {
                if ($this->fail) throw new \RuntimeException('transport-credential-canary');
                $this->jobs[] = unserialize(serialize($job));
                return count($this->jobs);
            }
        };
        if ($legacy) {
            $manager = new Manager($container);
            $manager->getQueueManager()->addConnector('test', fn () => new class($this->queue) implements ConnectorInterface {
                public function __construct(private NullQueue $queue) {}
                public function connect(array $config) { return $this->queue; }
            });
            $manager->addConnection(['driver' => 'test'], Nexus::QUEUE_CONNECTION_NAME);
            $manager->setAsGlobal();
            (new \ReflectionProperty(Nexus::class, 'queueManager'))->setValue(null, $manager);
            self::assertFalse($container->bound(DispatcherContract::class));
        } else {
            $container->instance(DispatcherContract::class, new Dispatcher($container, fn () => $this->queue));
        }
        $this->directory = sys_get_temp_dir() . '/imdb-queue-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        // Bypass unrelated directory/settings setup; use the real cache-miss renderer.
        $this->imdb = (new \ReflectionClass(Imdb::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(Imdb::class, 'config'))->setValue($this->imdb, (object) ['cacheDir' => $this->directory . '/']);
    }

    public static function runtimes(): array
    {
        return ['legacy page' => [true], 'Laravel' => [false]];
    }

    #[DataProvider('runtimes')]
    public function testMissingCacheRendersFallbackAndQueuesOnlyOneJob(bool $legacy): void
    {
        $this->boot($legacy);
        self::assertSame('N/A', $this->imdb->getRating('tt1234567'));
        self::assertSame('N/A', $this->imdb->getRating('tt1234567'));
        self::assertCount(1, $this->queue->jobs);
        self::assertSame(['imdb_Job', 'imdb:1234567'], $this->queue->jobs[0]->tags());
        self::assertSame(1, $this->cache->get('imdb:fetch_queue:1234567'));
    }

    #[DataProvider('runtimes')]
    public function testQueueFailurePreservesRenderingAndAllowsRetry(bool $legacy): void
    {
        $this->boot($legacy);
        $this->queue->fail = true;
        $html = '<main>' . $this->imdb->getRating('tt1234567') . '</main><footer>complete</footer>';
        self::assertSame('<main>N/A</main><footer>complete</footer>', $html);
        self::assertNull($this->cache->get('imdb:fetch_queue:1234567'));
        self::assertStringNotContainsString('transport-credential-canary', json_encode($GLOBALS['imdbTestLogs']));
        self::assertStringContainsString('RuntimeException', json_encode($GLOBALS['imdbTestLogs']));
        $this->queue->fail = false;
        self::assertSame('N/A', $this->imdb->getRating('tt1234567'));
        self::assertCount(1, $this->queue->jobs);
    }

    public function testExistingCacheDoesNotScheduleFetch(): void
    {
        $this->boot(true);
        touch($this->directory . '/title.tt1234567');
        self::assertSame(1, $this->imdb->getCacheStatus(1234567));
        self::assertCount(0, $this->queue->jobs);
    }

    protected function tearDown(): void
    {
        if (isset($this->directory)) {
            foreach (glob($this->directory . '/*') as $file) unlink($file);
            rmdir($this->directory);
        }
        parent::tearDown();
    }
}
