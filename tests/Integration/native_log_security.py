"""Real, isolated Nginx -> rsyslog test; requires nginx and rsyslogd on Linux.

No production config, network listener or database is used. The HTTP listener is
loopback-only and temporary; the logging socket never enters the system journal.
Run: python3 tests/Integration/native_log_security.py
"""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    root = Path(__file__).resolve().parents[2]
    markers = [f'nexus-{part}-canary' for part in ('path', 'query', 'cookie', 'referer', 'authorization', 'agent', 'body', 'requestid', 'exception', 'fake-source')]
    # These paths work with Ubuntu's shipped rsyslog AppArmor profile.
    with tempfile.TemporaryDirectory(prefix='.nexus-test-', dir='/etc/rsyslog.d') as confdir, \
         tempfile.TemporaryDirectory(prefix='nexus-test-', dir='/var/spool/rsyslog') as spooldir, \
         tempfile.TemporaryDirectory(prefix='nexus-test-', dir='/var/log') as tmp:
        directory = Path(tmp)
        sockpath = directory / 'error.sock'
        errorfile = directory / 'safe-error.log'
        rsyslog = (root / 'deploy/rsyslog/15-nexus-nginx-errors.conf').read_text().replace('/var/log/nginx/nexus-error.sock', str(sockpath)).replace('/var/log/nexusphp/nginx-error.log', str(errorfile))
        (Path(confdir) / 'rsyslog.conf').write_text('module(load="imuxsock" SysSock.Use="off")\n' + rsyslog)
        port, upstream = free_port(), free_port()
        nginx = f'''user root;
pid {directory}/nginx.pid;
error_log syslog:server=unix:{sockpath},tag=nexus_error,nohostname warn;
events {{}}
http {{
    {(root / 'deploy/nginx/nexus-safe-log-format.conf').read_text()}
    access_log {directory}/access.log nexus_safe;
    server {{ listen 127.0.0.1:{port};
        location / {{ proxy_pass http://127.0.0.1:{upstream}; }}
    }}
}}
'''
        (directory / 'nginx.conf').write_text(nginx)
        processes = []
        try:
            subprocess.run(['rsyslogd', '-N1', '-f', str(Path(confdir) / 'rsyslog.conf')], check=True)
            processes.append(subprocess.Popen(['rsyslogd', '-n', '-i', str(Path(spooldir) / 'rsyslog.pid'), '-f', str(Path(confdir) / 'rsyslog.conf')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
            for _ in range(50):
                if sockpath.exists(): break
                time.sleep(.1)
            else: raise RuntimeError('Isolated rsyslog did not start')
            processes.append(subprocess.Popen(['nginx', '-p', tmp, '-c', str(directory / 'nginx.conf'), '-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1): pass
                    break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('Isolated nginx did not start')
            client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            client.request('POST', '/' + markers[0] + '?auth_key=' + markers[1], body='password=' + markers[6], headers={'Cookie': 'session=' + markers[2], 'Referer': markers[3] + ' in /var/www/hitpt.com/' + markers[9] + '.php:17', 'Authorization': 'Bearer ' + markers[4], 'User-Agent': markers[5], 'X-Request-ID': markers[7]})
            response = client.getresponse()
            assert response.status == 502, 'The upstream-error path was not exercised'
            response.read(); client.close()
            # Native PHP error text may contain unlabelled secrets: allowlist metadata.
            payload = '<131>Oct 27 12:00:00 nexus_error: [error] 123#123: *123 PHP Fatal error: Uncaught RuntimeException: ' + markers[8] + ' in /var/www/hitpt.com/public/takelogin.php:17, request: GET /' + markers[0]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
                sender.sendto(payload.encode(), str(sockpath))
            for _ in range(50):
                output = errorfile.read_text() if errorfile.exists() else ''
                if 'php_fatal' in output and 'upstream_connect_failed' in output: break
                time.sleep(.1)
            else:
                # This instance receives synthetic inputs only, never host logs.
                diagnostics = []
                for process in reversed(processes):
                    process.terminate()
                    _, stderr = process.communicate(timeout=5)
                    diagnostics.append(stderr.decode(errors='replace'))
                raise AssertionError('Safe error metadata was not delivered: ' + output + repr(diagnostics))
            output += (directory / 'access.log').read_text()
            leaked = [marker for marker in markers if marker in output]
            assert not leaked, 'Credential locations leaked: ' + ', '.join(leaked)
            assert 'POST HTTP/1.1' in output and '502' in output
            assert 'exception=RuntimeException connection=123' in output
            print(json.dumps({'native_log_security': 'passed', 'canaries': len(markers), 'upstream_error_preserved': True, 'php_error_type_preserved': True}))
        finally:
            for process in reversed(processes):
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == '__main__':
    main()
