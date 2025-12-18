<?php

namespace Tests\Unit;

use App\Exceptions\Handler;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Routing\ResponseFactory as ResponseFactoryContract;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Redirector;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Facade;
use Laravel\Passport\Exceptions\AuthenticationException as PassportAuthenticationException;
use Nexus\Nexus;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthenticationResponseTest extends TestCase
{
    #[DataProvider('unauthenticatedRequests')]
    public function testAuthenticationResponse(string $path, string $accept, string $exceptionClass, int $status): void
    {
        // Exercise the real handler without booting database-backed site providers.
        defined('IN_NEXUS') || define('IN_NEXUS', false);
        require_once dirname(__DIR__, 2) . '/include/constants.php';
        require_once dirname(__DIR__, 2) . '/include/globalfunctions.php';
        $app = new class extends Application {
            public function runningInConsole() { return false; }
        };
        Application::setInstance($app);
        Facade::setFacadeApplication($app);
        $request = Request::create('https://tracker.test/' . $path, 'GET', ['secret' => 'must-not-be-returned']);
        $request->headers->set('Accept', $accept);
        $app->instance('request', $request);
        $app->instance('config', new Repository(['app' => ['debug' => false]]));
        $redirector = new Redirector(new UrlGenerator(new RouteCollection(), $request));
        $redirector->setSession(new Store('testing', new ArraySessionHandler(120)));
        $app->instance('redirect', $redirector);
        $app->instance(ResponseFactoryContract::class, new ResponseFactory($this->createStub(ViewFactory::class), $redirector));
        Nexus::boot();

        try {
            $handler = new Handler($app);
            $response = $handler->render($request, new $exceptionClass('Unauthenticated.', ['api'], 'https://tracker.test/login.php'));
            self::assertSame($status, $response->getStatusCode());
            if ($status === 401) {
                self::assertStringContainsString('application/json', $response->headers->get('Content-Type'));
                self::assertSame(-1, json_decode($response->getContent(), true)['ret']);
                self::assertFalse($response->headers->has('Location'));
            } else {
                self::assertStringContainsString('/login.php', $response->headers->get('Location'));
            }
        } finally {
            Facade::clearResolvedInstances();
            Facade::setFacadeApplication(null);
            Application::setInstance(null);
            Nexus::flush();
        }
    }

    public static function unauthenticatedRequests(): array
    {
        return [
            'user-info without JSON accept' => ['oauth/user-info', '*/*', AuthenticationException::class, 401],
            'user-info with HTML accept' => ['oauth/user-info', 'text/html', AuthenticationException::class, 401],
            'user-info Passport exception' => ['oauth/user-info', '*/*', PassportAuthenticationException::class, 401],
            'other JSON endpoint' => ['api/torrents', 'application/json', AuthenticationException::class, 401],
            'browser login redirect' => ['account', 'text/html', AuthenticationException::class, 302],
            'Passport browser redirect' => ['account', 'text/html', PassportAuthenticationException::class, 302],
        ];
    }
}
