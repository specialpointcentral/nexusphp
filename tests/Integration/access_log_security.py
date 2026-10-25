"""Exercise the real OpenResty access log with synthetic credentials only.

Run: python3 tests/Integration/access_log_security.py [nginx.conf]
Requires Docker images openresty/openresty:alpine and php:8.2-cli-alpine.
NEXUS_SECURITY_TMP may point to an isolated temporary artifact directory.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def main():
    root = Path(__file__).resolve().parents[2]
    config = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / '.docker/openresty/nginx.conf'
    name = 'nexus-log-test-' + uuid.uuid4().hex[:12]
    markers = ['path-canary', 'query-canary', 'cookie-canary', 'referer-canary', 'header-canary', 'body-canary']
    with tempfile.TemporaryDirectory(prefix='nexus-access-', dir=os.getenv('NEXUS_SECURITY_TMP')) as temporary:
        directory = Path(temporary)
        (directory / 'test.conf').write_text('''server {
    listen 8080;
    location / {
        content_by_lua_block {
            ngx.req.read_body()
            ngx.status = 204
            ngx.exit(204)
        }
    }
}
''')
        try:
            run('docker', 'run', '-d', '--rm', '--name', name, '--network', 'none',
                '-v', str(config) + ':/usr/local/openresty/nginx/conf/nginx.conf:ro',
                '-v', str(directory) + ':/etc/nginx/conf.d:ro',
                'openresty/openresty:alpine', 'sh', '-c',
                'mkdir -p /var/run/openresty/nginx-client-body /var/run/openresty/nginx-proxy '
                '/var/run/openresty/nginx-fastcgi /var/run/openresty/nginx-uwsgi /var/run/openresty/nginx-scgi '
                '&& openresty -g "daemon off;"')
            for _ in range(20):
                ready = run('docker', 'exec', name, 'wget', '-q', '-O', '/dev/null', 'http://127.0.0.1:8080/health', check=False)
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError('Isolated OpenResty failed to start')
            php = '''$context = stream_context_create(['http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-www-form-urlencoded\\r\\nCookie: c_secure_pass=cookie-canary\\r\\nReferer: https://example.test/referer-canary\\r\\nAuthorization: Bearer header-canary",
                'content' => 'password=body-canary',
                'ignore_errors' => true,
            ]]);
            file_get_contents('http://127.0.0.1:8080/path-canary?auth_key=query-canary', false, $context);
            if (!str_contains($http_response_header[0], '204')) exit(1);
            '''
            run('docker', 'run', '--rm', '--network', 'container:' + name,
                'php:8.2-cli-alpine', 'php', '-r', php)
            logs = run('docker', 'logs', name)
            output = logs.stdout + logs.stderr
            leaked = [marker for marker in markers if marker in output]
            assert not leaked, 'Synthetic credential leaked from request locations: ' + ', '.join(leaked)
            assert 'POST' in output and '204' in output, 'Normal request metadata was not logged'
            print(json.dumps({'access_log_test': 'passed', 'credential_locations': len(markers), 'status_and_method_preserved': True}))
        finally:
            run('docker', 'rm', '-f', name, check=False)


if __name__ == '__main__':
    main()
