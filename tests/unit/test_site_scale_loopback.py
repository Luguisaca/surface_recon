"""Measured same-origin HTTP frontier coverage across site sizes."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from time import monotonic
from urllib.parse import urlparse

import pytest

from surface_recon.controls import ReconControls, current_controls
from surface_recon.core import recon_target
from surface_recon.model import ScopeState, Target


@contextmanager
def site(size):
    counts = {}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            counts[path] = counts.get(path, 0) + 1
            if path == "/":
                body = ("<html>" + "".join(f'<a href="/p/{i}">Page</a>' for i in range(size)) + "</html>").encode()
                status = 200
            elif path.startswith("/p/") and path[3:].isdigit() and int(path[3:]) < size:
                body, status = b"<html>ok</html>", 200
            else:
                body, status = b"not found", 404
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", counts
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


@pytest.mark.parametrize("size,profile,expected_complete", [
    (8, "auto", True),
    (120, "auto", True),
    (320, "auto", True),
    (320, "unlimited", True),
])
def test_site_scale_http_loopback(size, profile, expected_complete):
    with site(size) as (url, counts):
        token = current_controls.set(ReconControls(profile=profile, pace_ms=0))
        try:
            started = monotonic()
            result = recon_target(Target("scale", url, ScopeState.AUTHORIZED, target_type="url"))
            elapsed = monotonic() - started
        finally:
            current_controls.reset(token)
        decisions = [x["evidence"] for x in result.observations if x["evidence"].get("kind") == "decision"]
        assert result.succeeded and decisions
        decision = decisions[-1]
        discovered_pages = {u for u in result.discovered if "/p/" in u}
        expected = size if expected_complete else 300 - 2 - 3
        assert len(discovered_pages) == expected, (size, profile, len(discovered_pages), decision)
        assert (decision["stop_reason"] == "frontier-exhausted") == expected_complete
        assert decision["requests"] == sum(counts.values())
        if size == 320 and profile == "auto":
            assert decision["budget"] > 300
            assert decision["budget_extensions"] >= 1
        print(f"SIZE={size} PROFILE={profile} PAGES={len(discovered_pages)}/{size} REQUESTS={decision['requests']} ELAPSED={elapsed:.3f}s STOP={decision['stop_reason']}")
