from surface_recon.findings import findings_from_capability_result
from surface_recon.model import FindingStatus


def test_supported_result_produces_traceable_finding():
    findings, observations, evidence = findings_from_capability_result(
        target_id="t1",
        capability_id="controlled",
        observations=[{
            "description": "Known observable condition",
            "evidence": {"detail": "controlled evidence"},
        }],
    )

    assert len(findings) == 1
    assert findings[0].status is FindingStatus.SUPPORTED
    assert findings[0].observation_ids
    assert findings[0].evidence_ids


def test_insufficient_result_remains_potential():
    findings, observations, evidence = findings_from_capability_result(
        target_id="t1",
        capability_id="controlled",
        observations=[{
            "description": "Weak signal",
            "evidence": None,
        }],
    )

    assert len(findings) == 1
    assert findings[0].status is FindingStatus.POTENTIAL


def test_zero_observations_produce_zero_findings():
    findings, observations, evidence = findings_from_capability_result(
        target_id="t1",
        capability_id="controlled",
        observations=[],
    )

    assert findings == []
    assert observations == []
    assert evidence == []


def test_owned_web_recon_preserves_ground_truth_findings_end_to_end(monkeypatch):
    from surface_recon.core import recon_url
    from surface_recon.model import Target, ScopeState

    root = b'<html><a href="/files/">files</a><a href="/error">error</a><a href="/docs">docs</a></html>'
    listing = b'''<html><head><title>Index of /files/</title></head>
    <body><h1>Index of /files/</h1><ul class="directory-listing">
    <li><a href="backup.sql.bak">backup.sql.bak</a></li>
    <li><a href="public.txt">public.txt</a></li></ul></body></html>'''
    error = b'''Internal Server Error
    at handler (/srv/depth/routes/error.js:18:7)
    at dispatch (/srv/depth/node_modules/router.js:42:3)'''
    docs = b'Documentation example: /srv/example/routes/server.js:10:2'
    missing = b'not found'

    def fake_fetch(url, timeout=4.0, max_bytes=2_000_000):
        from urllib.parse import urlparse
        path = urlparse(url).path
        if path == "/":
            return 200, {"Content-Type": "text/html"}, root, url
        if path == "/files/":
            return 200, {"Content-Type": "text/html"}, listing, url
        if path == "/error":
            return 500, {"Content-Type": "text/plain"}, error, url
        if path == "/docs":
            return 200, {"Content-Type": "text/plain"}, docs, url
        return 404, {"Content-Type": "text/plain"}, missing, url

    monkeypatch.setattr("surface_recon.core._fetch", fake_fetch)
    monkeypatch.setattr("surface_recon.core.socket.getaddrinfo", lambda *a, **k: [
        (2, 1, 6, "", ("127.0.0.1", 80))
    ])
    target = Target("t-depth", "http://depth.test/", ScopeState.AUTHORIZED, target_type="url")
    execution = recon_url(target)

    findings = [row for row in execution.observations if row.get("finding")]
    classes = [row["evidence"]["classification"] for row in findings]
    assert classes.count("directory-listing") == 1
    assert classes.count("information-disclosure") == 1
    assert not any(row.get("finding") and row["evidence"].get("url", "").endswith("/docs")
                   for row in execution.observations)
    assert "content-discovery" in execution.covered_subcapabilities
    assert "error-handling-analysis" in execution.covered_subcapabilities
