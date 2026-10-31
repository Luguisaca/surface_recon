"""Real loopback HTTP tests: no external targets, no mock of HTTP transport."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse

from surface_recon.core import recon_url
from surface_recon.model import ScopeState, Target


@contextmanager
def fixture_server(mode):
    calls = {}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            calls[path] = calls.get(path, 0) + 1
            if path == "/":
                status, body, retry = 200, b'<a href="/proyectos">Projects</a>', None
            elif path.startswith("/.surface-recon-missing-route"):
                status, body, retry = 404, b"missing", None
            elif path == "/proyectos":
                if mode == "429-recover" and calls[path] == 1:
                    status, body, retry = 429, b"slow down", "0"
                elif mode == "503-date" and calls[path] == 1:
                    status, body, retry = 503, b"unavailable", format_datetime(datetime.now(timezone.utc) + timedelta(seconds=2), usegmt=True)
                elif mode == "503-persistent":
                    status, body, retry = 503, b"unavailable", "90"
                else:
                    status, body, retry = 200, b"projects", None
            else:
                status, body, retry = 404, b"missing", None
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if status == 200 else "text/plain")
            if retry is not None:
                self.send_header("Retry-After", retry)
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", calls
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def _scan(url):
    return recon_url(Target("loopback", url, ScopeState.AUTHORIZED, target_type="url"), max_requests=15, max_seconds=15)


def _decision(result):
    return [x["evidence"] for x in result.observations if x["evidence"].get("kind") == "decision"][-1]


def test_loopback_429_zero_delay_recovers():
    with fixture_server("429-recover") as (url, calls):
        result = _scan(url)
        assert result.succeeded
        assert url + "proyectos" in result.discovered
        assert calls["/proyectos"] == 2
        assert _decision(result)["stop_reason"] == "frontier-exhausted"


def test_loopback_503_http_date_recovers():
    with fixture_server("503-date") as (url, calls):
        result = _scan(url)
        assert result.succeeded
        assert url + "proyectos" in result.discovered
        assert calls["/proyectos"] == 2
        assert any(x["evidence"].get("kind") == "throttle" and x["evidence"].get("status") == 503 for x in result.observations)


def test_loopback_503_long_retry_after_stops_safely():
    with fixture_server("503-persistent") as (url, calls):
        result = _scan(url)
        assert result.succeeded
        assert url + "proyectos" not in result.discovered
        assert calls["/proyectos"] == 1
        assert _decision(result)["stop_reason"] == "server-rate-limit"
        assert "content-discovery-partial" in result.covered_subcapabilities
