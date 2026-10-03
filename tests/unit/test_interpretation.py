from surface_recon.interpretation import interpret_http_response


def test_verbose_stack_trace_becomes_evidence_backed_finding():
    body = b"""403 Error
at verify (/juice-shop/build/routes/fileServer.js:68:18)
at /juice-shop/build/routes/fileServer.js:52:13
at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)
"""
    rows = interpret_http_response(
        url="http://127.0.0.1:3000/ftp/suspicious_errors.yml",
        status=403,
        headers={"Content-Type": "text/html"},
        body=body,
        discovered_from="http://127.0.0.1:3000/ftp/",
    )
    finding = next(row for row in rows if row.get("finding"))
    evidence = finding["evidence"]
    assert finding["description"] == "Verbose error response exposes internal implementation details"
    assert evidence["kind"] == "security-finding"
    assert evidence["classification"] == "information-disclosure"
    assert evidence["cwe"] == "CWE-209"
    assert evidence["confidence"] == "high"
    assert evidence["stack_frames_observed"] >= 2
    assert evidence["validation"]["safe_reproduction"][-1].endswith("/ftp/suspicious_errors.yml")


def test_single_path_like_text_does_not_become_vulnerability():
    rows = interpret_http_response(
        url="https://example.test/docs",
        status=200,
        headers={"Content-Type": "text/plain"},
        body=b"Documentation example: /srv/app/src/server.js:10:2",
    )
    assert not any(row.get("finding") for row in rows)


def test_query_parameters_create_hypothesis_not_vulnerability():
    rows = interpret_http_response(
        url="https://example.test/search?q=hello",
        status=200,
        headers={"Content-Type": "text/html"},
        body=b"<html>ok</html>",
    )
    hypothesis = next(row for row in rows if row["evidence"]["kind"] == "security-hypothesis")
    assert hypothesis["finding"] is False
    assert "SQL injection" in hypothesis["evidence"]["candidate_classes"]
    assert "no injection vulnerability has been demonstrated" in hypothesis["evidence"]["reason"]


def test_directory_listing_is_finding_but_sensitive_names_are_not_claimed_exposed_contents():
    body = b"""<html><head><title>listing directory /files/</title></head>
    <body><h1><a href=".">~</a> / <a href="">files</a> / </h1>
    <ul id="files"><li><a href="backup.sql.bak">backup.sql.bak</a></li>
    <li><a href="public.md">public.md</a></li></ul></body></html>"""
    rows = interpret_http_response(
        url="https://example.test/files/",
        status=200,
        headers={"Content-Type": "text/html"},
        body=body,
    )
    finding = next(row for row in rows if row.get("finding"))
    evidence = finding["evidence"]
    assert evidence["classification"] == "directory-listing"
    assert evidence["cwe"] == "CWE-548"
    assert "backup.sql.bak" in evidence["potentially_sensitive_entries"]
    assert "file contents were not automatically retrieved" in evidence["impact_demonstrated"]


def test_query_hypothesis_contains_executable_validation_recipe():
    rows = interpret_http_response(
        url="https://example.test/search?q=hello&category=1",
        status=200,
        headers={"Content-Type": "text/html"},
        body=b"<html>ok</html>",
    )
    evidence = next(x["evidence"] for x in rows if x["evidence"].get("hypothesis") == "input-validation")
    assert evidence["parameters"] == ["q", "category"]
    assert {x["class"] for x in evidence["validation_recipe"]["checks"]} >= {"SQL injection", "cross-site scripting"}
    assert "Promote only" in evidence["validation_recipe"]["success_rule"]


def test_html_form_creates_input_validation_recipe_without_claiming_vulnerability():
    body = b"""<form action="/login" method="post">
    <input name="email"><input type="password" name="password">
    </form>"""
    rows = interpret_http_response(
        url="https://example.test/",
        status=200,
        headers={"Content-Type": "text/html"},
        body=body,
    )
    row = next(x for x in rows if x["evidence"].get("hypothesis") == "form-input-validation")
    assert row["finding"] is False
    assert row["evidence"]["form"] == {"action": "/login", "method": "POST", "inputs": ["email", "password"]}


def test_sensitive_route_creates_authorization_hypothesis_not_finding():
    rows = interpret_http_response(
        url="https://example.test/api/orders/42",
        status=200,
        headers={"Content-Type": "application/json"},
        body=b'{"id":42}',
    )
    row = next(x for x in rows if x["evidence"].get("hypothesis") == "authorization-boundary")
    assert row["finding"] is False
    assert "IDOR/BOLA" in row["evidence"]["candidate_classes"]
    assert "Promote only" in row["evidence"]["validation_recipe"]["success_rule"]


def test_large_javascript_bundle_is_not_document_scanned_for_stack_trace_findings():
    body = (b"var p='/app/src/routes/server.js:10:2';" * 60000)
    rows = interpret_http_response(
        url="https://example.test/main.js",
        status=200,
        headers={"Content-Type": "application/javascript"},
        body=body,
    )
    assert not any(row.get("finding") for row in rows)
