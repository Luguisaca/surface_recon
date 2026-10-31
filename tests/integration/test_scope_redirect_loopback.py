"""HTTP-scope and early throttling integration tests against actual loopback servers."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from surface_recon.core import recon_url
from surface_recon.model import ScopeState, Target


@contextmanager
def _server(responder):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            seen.append(self.path)
            code, headers, body = responder(self.path)
            self.send_response(code)
            for key, val in headers.items():
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(body)
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{service.server_port}", seen
    finally:
        service.shutdown()
        thread.join(timeout=3)
        service.server_close()


def _run(url):
    return recon_url(Target("scope-fixture", url, ScopeState.AUTHORIZED, target_type="url"),
                     max_requests=20, max_seconds=15)


def _stop(result):
    return [x["evidence"]["stop_reason"] for x in result.observations
            if x["evidence"].get("kind") == "decision"][-1]


def test_entrypoint_rate_limit_stops_without_extra_requests():
    with _server(lambda path: (429, {"Retry-After": "30"}, b"slow")) as (base, seen):
        result = _run(base + "/")
        assert result.succeeded
        assert _stop(result) == "server-rate-limit"
        assert seen == ["/"]
        assert "content-discovery-partial" in result.covered_subcapabilities


def test_external_redirect_at_entrypoint_never_contacts_other_origin():
    with _server(lambda path: (200, {}, b"OUTSIDE")) as (outside, seen_outside):
        with _server(lambda path: (302, {"Location": outside + "/secret"}, b"redirect")) as (base, seen):
            result = _run(base + "/")
            assert result.succeeded
            assert _stop(result) == "redirect-unfollowed"
            assert seen == ["/"]
            assert not seen_outside


def test_external_redirect_on_child_never_contacts_other_origin():
    with _server(lambda path: (200, {}, b"OUTSIDE")) as (outside, seen_outside):
        def handler(path):
            if path == "/":
                return 200, {"Content-Type": "text/html"}, b'<a href="/redirect">link</a>'
            if path == "/redirect":
                return 302, {"Location": outside + "/secret"}, b"move"
            return 404, {}, b"missing"
        with _server(handler) as (base, seen):
            result = _run(base + "/")
            assert result.succeeded
            assert "/redirect" in seen
            assert not seen_outside
            assert base + "/redirect" not in result.discovered
            assert any(x["evidence"].get("kind") == "redirect-unfollowed" for x in result.observations)


def test_same_origin_redirect_is_allowed():
    def handler(path):
        if path == "/":
            return 200, {"Content-Type": "text/html"}, b'<a href="/redirect">link</a>'
        if path == "/redirect":
            return 302, {"Location": "/moved"}, b"move"
        if path == "/moved":
            return 200, {"Content-Type": "text/plain"}, b"ok"
        return 404, {}, b"missing"
    with _server(handler) as (base, seen):
        result = _run(base + "/")
        assert result.succeeded
        assert "/moved" in seen
        assert base + "/moved" in result.discovered


def test_canary_throttle_stops_before_following_links():
    def handler(path):
        if path == "/":
            return 200, {"Content-Type": "text/html"}, b'<a href="/go">link</a>'
        if path.startswith("/.surface-recon-missing-route"):
            return 503, {"Retry-After": "60"}, b"maintenance"
        return 200, {}, b"ok"
    with _server(handler) as (base, seen):
        result = _run(base + "/")
        assert result.succeeded
        assert _stop(result) == "server-rate-limit"
        assert len(seen) == 2
        assert "/go" not in seen
