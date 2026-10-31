from surface_recon.core import recon_url
from surface_recon.model import Target, ScopeState


def _target():
    return Target("fixture", "http://example.test/", ScopeState.AUTHORIZED, target_type="url")


def test_small_and_large_frontiers_and_unlimited(monkeypatch):
    from surface_recon.controls import ReconControls
    from surface_recon.core import recon_target
    from surface_recon.controls import current_controls
    counts = []
    def fake(url, **_):
        counts.append(url)
        if url.endswith("/"):
            return 200, {"Content-Type": "text/html"}, "".join(
                f'<a href="/p/{i}">p</a>' for i in range(350)
            ).encode(), url
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"missing", url
        return 200, {"Content-Type": "text/plain"}, b"ok", url
    monkeypatch.setattr("surface_recon.core._fetch", fake)
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *a, **k: [])
    token = current_controls.set(ReconControls(profile="auto"))
    try:
        normal = recon_target(_target())
        normal_decision = [x["evidence"] for x in normal.observations if x["evidence"].get("kind") == "decision"][-1]
        assert normal_decision["requests"] > 300
        assert normal_decision["stop_reason"] == "frontier-exhausted"
        assert normal_decision["budget_extensions"] >= 1
        assert normal_decision["initial_budget"] == 300
        assert normal_decision["budget"] <= 1200
        assert normal_decision["remaining_candidates"] == 0
        counts.clear()
        current_controls.set(ReconControls(profile="unlimited"))
        unlimited = recon_target(_target())
        decision = [x["evidence"] for x in unlimited.observations if x["evidence"].get("kind") == "decision"][-1]
        assert decision["stop_reason"] == "frontier-exhausted"
        assert decision["requests"] > 300
        assert decision["remaining_candidates"] == 0
    finally:
        current_controls.reset(token)


def test_429_retries_and_respects_retry_after(monkeypatch):
    import surface_recon.core as core
    seen = {}
    slept = []
    def fake(url, **_):
        if url.endswith("/"):
            return 200, {"Content-Type": "text/html"}, b'<a href="/proyectos">projects</a>', url
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"missing", url
        if url.endswith("/proyectos"):
            seen[url] = seen.get(url, 0) + 1
            if seen[url] == 1:
                return 429, {"Retry-After": "0.01"}, b"slow down", url
            return 200, {"Content-Type": "text/html"}, b"projects", url
        return 404, {"Content-Type": "text/plain"}, b"", url
    monkeypatch.setattr(core, "_fetch", fake)
    monkeypatch.setattr(core.time, "sleep", lambda seconds: slept.append(seconds))
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *a, **k: [])
    result = recon_url(_target(), max_requests=20)
    assert "http://example.test/proyectos" in result.discovered
    assert seen["http://example.test/proyectos"] == 2
    assert slept == [0.01]
    assert any(x["evidence"].get("kind") == "throttle" for x in result.observations)


def test_persistent_429_stops_with_partial_coverage(monkeypatch):
    import surface_recon.core as core
    seen = []
    def fake(url, **_):
        seen.append(url)
        if url.endswith("/"):
            return 200, {"Content-Type": "text/html"}, b'<a href="/proyectos">p</a>', url
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"", url
        if url.endswith("/proyectos"):
            return 429, {"Retry-After": "0"}, b"slow down", url
        return 404, {"Content-Type": "text/plain"}, b"", url
    monkeypatch.setattr(core, "_fetch", fake)
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *a, **k: [])
    result = recon_url(_target(), max_requests=20)
    assert seen.count("http://example.test/proyectos") <= 3
    assert "http://example.test/proyectos" not in result.discovered


def test_auto_does_not_expand_when_link_candidates_are_404(monkeypatch):
    from surface_recon.controls import ReconControls, current_controls
    from surface_recon.core import recon_target
    import surface_recon.core as core
    def fake(url, **_):
        if url.endswith("/"):
            return (200, {"Content-Type": "text/html"},
                "".join(f'<a href="/dead/{i}">dead</a>' for i in range(1400)).encode(), url)
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"not found", url
        return 404, {"Content-Type": "text/plain"}, b"not found", url
    monkeypatch.setattr(core, "_fetch", fake)
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *a, **k: [])
    token = current_controls.set(ReconControls(profile="auto"))
    try:
        result = recon_target(_target())
    finally:
        current_controls.reset(token)
    assert result.succeeded, (result.error, result.observations[-3:])
    decision = next(x["evidence"] for x in reversed(result.observations)
                    if x["evidence"].get("kind") == "decision")
    assert decision["budget"] == 300
    assert decision["budget_extensions"] == 0
    assert decision["requests"] == 300
    assert decision["stop_reason"] == "request-budget-exhausted"


def test_auto_cannot_exceed_bounded_ceiling(monkeypatch):
    from surface_recon.controls import ReconControls, current_controls
    from surface_recon.core import recon_target
    import surface_recon.core as core
    def fake(url, **_):
        if url.endswith("/"):
            return (200, {"Content-Type": "text/html"},
                "".join(f'<a href="/p/{i}">ok</a>' for i in range(1400)).encode(), url)
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"not found", url
        return 200, {"Content-Type": "text/html"}, b"ok", url
    monkeypatch.setattr(core, "_fetch", fake)
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *a, **k: [])
    token = current_controls.set(ReconControls(profile="auto", pace_ms=0))
    try:
        result = recon_target(_target())
    finally:
        current_controls.reset(token)
    assert result.succeeded, (result.error, result.observations[-3:])
    decision = next(x["evidence"] for x in reversed(result.observations)
                    if x["evidence"].get("kind") == "decision")
    assert decision["requests"] == 1200
    assert decision["budget"] == decision["adaptive_ceiling"] == 1200
    assert decision["budget_extensions"] == 9
    assert decision["stop_reason"] == "request-budget-exhausted"
    assert decision["remaining_candidates"] > 0


def test_strict_request_budget_and_low_noise_never_expand(monkeypatch):
    from surface_recon.controls import ReconControls, current_controls
    from surface_recon.core import recon_url, recon_target
    import surface_recon.core as core
    def fake(url, **_):
        if url.endswith("/"):
            return (200, {"Content-Type": "text/html"},
                "".join(f'<a href="/p/{i}">ok</a>' for i in range(350)).encode(), url)
        if "missing-route" in url:
            return 404, {"Content-Type": "text/plain"}, b"not found", url
        return 200, {"Content-Type": "text/html"}, b"ok", url
    monkeypatch.setattr(core, "_fetch", fake)
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *a, **k: [])
    direct = recon_url(_target(), max_requests=20)
    assert direct.succeeded, (direct.error, direct.observations[-3:])
    direct_decision = next(x["evidence"] for x in reversed(direct.observations)
                           if x["evidence"].get("kind") == "decision")
    assert direct_decision["requests"] == 20
    assert direct_decision["budget_extensions"] == 0
    token = current_controls.set(ReconControls(profile="auto", noise="low", pace_ms=0))
    try:
        low = recon_target(_target())
    finally:
        current_controls.reset(token)
    low_decision = next(x["evidence"] for x in reversed(low.observations)
                        if x["evidence"].get("kind") == "decision")
    assert low_decision["requests"] == 60
    assert low_decision["budget_extensions"] == 0
