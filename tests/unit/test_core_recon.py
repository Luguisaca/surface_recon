from surface_recon.core import recon_url
from surface_recon.model import ScopeState, Target


def test_owned_core_discovers_same_origin_surface_from_html_and_robots(monkeypatch):
    pages = {
        "http://example.test/": (200, {"Content-Type": "text/html", "Server": "demo"}, b'<a href="/app">App</a>', "http://example.test/"),
        "http://example.test/app": (200, {"Content-Type": "text/html"}, b"app", "http://example.test/app"),
        "http://example.test/robots.txt": (200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /private\n", "http://example.test/robots.txt"),
        "http://example.test/.well-known/security.txt": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/.well-known/security.txt"),
        "http://example.test/sitemap.xml": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/sitemap.xml"),
        "http://example.test/private": (200, {"Content-Type": "text/html"}, b"private", "http://example.test/private"),
    }

    monkeypatch.setattr("surface_recon.core._fetch", lambda url, **_: pages.get(url, (404, {"Content-Type": "text/plain"}, b"", url)))
    monkeypatch.setattr(
        "surface_recon.core.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("192.0.2.10", 0))],
    )
    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")

    result = recon_url(target)

    assert result.succeeded
    assert "http://example.test/app" in result.discovered
    assert "http://example.test/private" in result.discovered
    assert "content-discovery" in result.covered_subcapabilities
    assert all("outside.test" not in item for item in result.discovered)


def test_owned_core_does_not_follow_cross_origin_links(monkeypatch):
    pages = {
        "http://example.test/": (200, {"Content-Type": "text/html"}, b'<a href="https://outside.test/admin">x</a>', "http://example.test/"),
        "http://example.test/robots.txt": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/robots.txt"),
        "http://example.test/.well-known/security.txt": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/.well-known/security.txt"),
        "http://example.test/sitemap.xml": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/sitemap.xml"),
    }
    monkeypatch.setattr("surface_recon.core._fetch", lambda url, **_: pages.get(url, (404, {"Content-Type": "text/plain"}, b"", url)))
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])

    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")
    result = recon_url(target)

    assert result.succeeded
    assert not any("outside.test" in item for item in result.discovered)


def test_core_forms_bounded_hypotheses_from_observed_application_evidence(monkeypatch):
    pages = {
        "http://example.test/": (200, {"Content-Type": "text/html", "Server": "demo"}, b'<script>window.api="/api/items"</script>', "http://example.test/"),
        "http://example.test/robots.txt": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/robots.txt"),
        "http://example.test/.well-known/security.txt": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/.well-known/security.txt"),
        "http://example.test/sitemap.xml": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/sitemap.xml"),
        "http://example.test/api": (200, {"Content-Type": "application/json"}, b"{}", "http://example.test/api"),
        "http://example.test/graphql": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/graphql"),
        "http://example.test/metrics": (200, {"Content-Type": "text/plain"}, b"demo 1", "http://example.test/metrics"),
        "http://example.test/health": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/health"),
        "http://example.test/status": (404, {"Content-Type": "text/plain"}, b"", "http://example.test/status"),
    }
    monkeypatch.setattr("surface_recon.core._fetch", lambda url, **_: pages.get(url, (404, {"Content-Type": "text/plain"}, b"", url)))
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])
    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")

    result = recon_url(target)

    assert "http://example.test/metrics" in result.discovered
    assert any(item["evidence"].get("kind") == "hypothesis" for item in result.observations)


def test_client_template_literals_reveal_service_endpoints(monkeypatch):
    pages = {
        "http://example.test/": (200, {"Content-Type": "text/html"}, b'<script src="/app.js"></script>', "http://example.test/"),
        "http://example.test/app.js": (200, {"Content-Type": "application/javascript"}, b'client.get(host+`/api/widgets`)', "http://example.test/app.js"),
        "http://example.test/api/widgets": (200, {"Content-Type": "application/json"}, b"[]", "http://example.test/api/widgets"),
    }
    monkeypatch.setattr("surface_recon.core._fetch", lambda url, **_: pages.get(url, (404, {"Content-Type": "text/plain"}, b"missing", url)))
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])
    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")
    result = recon_url(target, max_requests=12)
    assert "http://example.test/api/widgets" in result.discovered


def test_soft_not_found_fallback_is_not_reported_as_surface(monkeypatch):
    root = b"<html>SPA shell</html>"
    pages = {
        "http://example.test/": (200, {"Content-Type": "text/html"}, root, "http://example.test/"),
        "http://example.test/.surface-recon-missing-route-7f31": (200, {"Content-Type": "text/html"}, root, "http://example.test/.surface-recon-missing-route-7f31"),
    }
    monkeypatch.setattr("surface_recon.core._fetch", lambda url, **_: pages.get(url, (200, {"Content-Type": "text/html"}, root, url)))
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])
    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")
    result = recon_url(target, max_requests=10)
    assert not result.discovered
    assert any(item["evidence"].get("kind") == "not_found" for item in result.observations)


def test_hypotheses_respect_authorized_application_prefix(monkeypatch):
    pages = {
        "http://example.test/app": (200, {"Content-Type": "text/html"}, b"<html>login account</html>", "http://example.test/app"),
        "http://example.test/app/login": (200, {"Content-Type": "text/html"}, b"login", "http://example.test/app/login"),
    }
    requested = []
    def fake_fetch(url, **_):
        requested.append(url)
        return pages.get(url, (404, {"Content-Type": "text/plain"}, b"missing", url))
    monkeypatch.setattr("surface_recon.core._fetch", fake_fetch)
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])
    target = Target("t1", "http://example.test/app", ScopeState.AUTHORIZED, target_type="url")
    result = recon_url(target, max_requests=12)
    assert result.succeeded
    assert "http://example.test/app/login" in requested
    assert "http://example.test/login" not in requested


def test_normal_mode_has_no_arbitrary_global_request_cap(monkeypatch):
    links = "".join(f'<a href="/r/{i}">r{i}</a>' for i in range(40)).encode()
    def fake_fetch(url, **_):
        if url == "http://example.test/":
            return 200, {"Content-Type": "text/html"}, links, url
        if ".surface-recon-missing-route-" in url:
            return 404, {"Content-Type": "text/plain"}, b"missing-control", url
        return 200, {"Content-Type": "text/plain"}, b"ok", url
    monkeypatch.setattr("surface_recon.core._fetch", fake_fetch)
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])
    target = Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")
    result = recon_url(target)
    assert all(f"http://example.test/r/{i}" in result.discovered for i in range(40))
    decision = [x["evidence"] for x in result.observations if x["evidence"].get("stop_reason")]
    assert decision[-1]["stop_reason"] == "frontier-exhausted"
    assert decision[-1]["budget"] is None


def test_directory_index_style_relative_link_does_not_duplicate_current_path():
    from surface_recon.core import _safe_same_origin

    assert _safe_same_origin(
        "http://example.test/ftp/", "ftp/report.txt"
    ) == "http://example.test/ftp/report.txt"


def test_normal_relative_link_still_resolves_from_current_directory():
    from surface_recon.core import _safe_same_origin

    assert _safe_same_origin(
        "http://example.test/app/", "profile"
    ) == "http://example.test/app/profile"


def test_same_origin_normalizes_default_http_ports():
    from surface_recon.core import _safe_same_origin

    assert _safe_same_origin(
        "https://example.test/app", "https://example.test:443/api"
    ) == "https://example.test:443/api"
    assert _safe_same_origin(
        "http://example.test/app", "http://example.test:80/api"
    ) == "http://example.test:80/api"


def test_same_origin_rejects_non_default_port_change():
    from surface_recon.core import _safe_same_origin

    assert _safe_same_origin(
        "https://example.test/app", "https://example.test:8443/api"
    ) is None


def test_hypothesis_trigger_does_not_match_api_inside_server_product(monkeypatch):
    pages = {
        "http://example.test/": (
            404,
            {"Content-Type": "text/plain", "Server": "Microsoft-HTTPAPI/2.0"},
            b"not found",
            "http://example.test/",
        ),
    }
    monkeypatch.setattr(
        "surface_recon.core._fetch",
        lambda url, **_: pages.get(url, (404, {"Content-Type": "text/plain"}, b"", url)),
    )
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *args, **kwargs: [])

    result = recon_url(Target("t1", "http://example.test/", ScopeState.AUTHORIZED, target_type="url"))

    hypotheses = [
        item for item in result.observations
        if item["evidence"].get("kind") == "hypothesis"
    ]
    assert hypotheses == []
    assert not any(path.endswith(("/api", "/graphql", "/metrics")) for path in result.discovered)
    assert "content-discovery" in result.covered_subcapabilities
    assert "content-discovery-partial" not in result.covered_subcapabilities


def test_host_ground_truth_exposes_bounded_port_depth_without_overclaim(monkeypatch):
    from surface_recon.model import Target, ScopeState
    from surface_recon.universal_core import recon_host

    monkeypatch.setattr("surface_recon.universal_core.socket.getaddrinfo", lambda *a, **k: [
        (2, 1, 6, "", ("127.0.0.1", 0))
    ])

    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *args): return False

    open_ports = {8080, 18080}
    def fake_connect(address, timeout=0.2):
        if address[1] not in open_ports:
            raise OSError("closed control")
        return FakeSocket()

    monkeypatch.setattr("surface_recon.universal_core.socket.create_connection", fake_connect)
    target = Target("t-host-depth", "127.0.0.1", ScopeState.AUTHORIZED, target_type="host")
    observations, covered = recon_host(target)
    ports = next(row["evidence"] for row in observations if row["evidence"].get("kind") == "ports")

    assert [row["port"] for row in ports["reachable"]] == [8080]
    assert 18080 not in ports["tested_ports"]
    assert ports["full_tcp_range_tested"] is False
    assert covered == ("host-discovery", "port-discovery-partial")
