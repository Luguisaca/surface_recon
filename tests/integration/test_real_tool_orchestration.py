import pytest

from surface_recon.assessment import assess_targets
from surface_recon.model import FindingStatus
from surface_recon.tooling import ToolCandidate, ToolExecution


def test_url_composes_discovered_tools_and_normalizes_evidence(monkeypatch):
    tools = [
        ToolCandidate(
            "httpx", "http-recon", ("httpx",), "probe", ("Linux",), "MIT",
            ("http-probing", "technology-fingerprinting"), "/bin/httpx",
        ),
        ToolCandidate(
            "nuclei", "http-recon", ("nuclei",), "templates", ("Linux",), "MIT",
            ("template-detection",), "/bin/nuclei",
        ),
    ]
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: tools)

    def fake_execute(tool, target):
        if tool.id == "httpx":
            return ToolExecution(
                "httpx", True,
                [{"description": "HTTP 200: https://example.test", "evidence": {"status_code": 200}, "finding": False, "source": "httpx"}],
                covered_subcapabilities=tool.subcapabilities,
            )
        return ToolExecution(
            "nuclei", True,
            [{"description": "Nuclei: Missing Header", "evidence": {"template_id": "missing-header", "severity": "info"}, "finding": False, "source": "nuclei"}],
            covered_subcapabilities=tool.subcapabilities,
        )

    monkeypatch.setattr("surface_recon.tooling.execute_tool", fake_execute)
    assessment = assess_targets(["https://example.test"])

    assert set(assessment.coverage[0].evaluated) == {
        "http-probing", "technology-fingerprinting", "template-detection"
    }
    # Deeper validation classes are not global requirements. They are
    # introduced only when owned reconnaissance observes a relevant hypothesis.
    assert assessment.coverage[0].unevaluated == [
        "content-discovery", "error-handling-analysis", "input-surface-analysis",
    ]
    assert len(assessment.observations) == 2
    assert len(assessment.findings) == 0

    from surface_recon.results import render_assessment
    rendered = render_assessment(assessment)
    assert "Coverage state: partial" in rendered
    assert "content-discovery" in rendered
    assert "none reported by executed tooling within evaluated coverage" in rendered
    assert "does not establish that the target is secure" in rendered
    assert set(assessment.capabilities[0].tools_used) == {"httpx", "nuclei"}


def test_renderer_leads_with_plain_language_interpretation(monkeypatch):
    tools = [
        ToolCandidate(
            "httpx", "http-recon", ("httpx",), "probe", ("Linux",), "MIT",
            ("http-probing", "technology-fingerprinting"), "/bin/httpx",
        ),
        ToolCandidate(
            "nuclei", "http-recon", ("nuclei",), "templates", ("Linux",), "MIT",
            ("template-detection",), "/bin/nuclei",
        ),
    ]
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: tools)

    def fake_execute(tool, target):
        if tool.id == "httpx":
            return ToolExecution(
                "httpx", True,
                [{"description": "HTTP 200: https://example.test", "evidence": {"status_code": 200, "page_title": "Example"}, "finding": False, "source": "httpx"}],
                covered_subcapabilities=tool.subcapabilities,
            )
        return ToolExecution(
            "nuclei", True,
            [{"description": "Nuclei: controlled check", "evidence": {"template_id": "lab-check", "severity": "info"}, "finding": False, "source": "nuclei"}],
            covered_subcapabilities=tool.subcapabilities,
        )

    monkeypatch.setattr("surface_recon.tooling.execute_tool", fake_execute)
    assessment = assess_targets(["https://example.test"])

    from surface_recon.results import render_assessment
    rendered = render_assessment(assessment)
    summary = rendered.split("Technical detail:", 1)[0]

    assert "What was actually checked:" in summary
    assert "HTTP reachability and response metadata" in summary
    assert "technology fingerprint signals" in summary
    assert "template-based checks configured for this run" in summary
    assert "No risk finding was reported" in summary
    assert "does not mean the target is secure" in summary
    assert "Assessment: assessment-local" not in summary


def test_network_provider_service_evidence_pivots_into_web_recon(monkeypatch):
    from surface_recon.core import CoreExecution

    nmap = ToolCandidate(
        "nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
        ("host-discovery", "port-discovery", "service-fingerprinting"), "/bin/nmap",
    )
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [nmap])

    def fake_execute(tool, target):
        return ToolExecution("nmap", True, [{
            "description": "provider surface",
            "evidence": {"kind": "nmap-surface", "hosts": [{
                "addresses": ["192.0.2.10"],
                "services": [
                    {"port": 8080, "protocol": "tcp", "service": "http-alt"},
                    {"port": 8888, "protocol": "tcp", "service": "http-proxy"},
                    {"port": 9443, "protocol": "tcp", "service": "ssl/http"},
                ],
            }], "full_tcp_range_tested": True},
            "finding": False, "source": "nmap",
        }], covered_subcapabilities=nmap.subcapabilities)

    monkeypatch.setattr("surface_recon.tooling.execute_tool", fake_execute)
    monkeypatch.setattr("surface_recon.universal_core.recon_network", lambda target: ([], ()))
    seen = []
    def fake_web(target):
        seen.append(target.value)
        return CoreExecution(True, [{
            "description": "web pivot checked",
            "evidence": {"kind": "resource", "url": target.value, "status": 200},
            "finding": False, "source": "surface-recon-core",
        }], ("http-probing",), [])
    monkeypatch.setattr("surface_recon.core.recon_target", fake_web)

    assessment = assess_targets(["192.0.2.0/30"])

    assert seen == [
        "http://192.0.2.10:8080",
        "http://192.0.2.10:8888",
        "https://192.0.2.10:9443",
    ]
    assert "http-probing" in assessment.coverage[0].evaluated
    from surface_recon.results import _surface_data
    provider_surfaces = [
        item for item in _surface_data(assessment)[0]["surface"]
        if item["value"].startswith("192.0.2.10:")
    ]
    assert provider_surfaces
    assert all(item["type"] == "open-port" for item in provider_surfaces)
    decisions = [e.content for e in assessment.evidence if isinstance(e.content, dict)]
    assert any(x.get("reason") == "provider-service-to-web-pivot" for x in decisions)


def test_owned_host_web_pivot_preserves_web_coverage(monkeypatch):
    from surface_recon.core import CoreExecution
    monkeypatch.setattr("surface_recon.universal_core.recon_host", lambda target: ([{
        "description": "ports", "finding": False, "source": "surface-recon-core",
        "evidence": {"kind": "ports", "reachable": [{"port": 8080, "service_hint": "http-alt"}]},
    }], ("host-discovery", "port-discovery-partial")))
    monkeypatch.setattr("surface_recon.universal_core.fingerprint_host_services",
                        lambda target, row: ([], ("service-fingerprinting",)))
    monkeypatch.setattr("surface_recon.core.recon_target", lambda target:
        CoreExecution(True, [], ("http-probing", "input-surface-analysis"), []))

    assessment = assess_targets(["127.0.0.1"], use_extensions=False)

    assert "http-probing" in assessment.coverage[0].evaluated
    assert "input-surface-analysis" in assessment.coverage[0].evaluated


def test_provider_does_not_repeat_owned_web_pivot(monkeypatch):
    from surface_recon.core import CoreExecution
    nmap = ToolCandidate(
        "nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
        ("host-discovery", "port-discovery", "service-fingerprinting"), "/bin/nmap",
    )
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [nmap])
    monkeypatch.setattr("surface_recon.universal_core.recon_host", lambda target: ([{
        "description": "ports", "finding": False, "source": "surface-recon-core",
        "evidence": {"kind": "ports", "reachable": [{"port": 8080, "service_hint": "http-alt"}]},
    }], ("host-discovery", "port-discovery-partial")))
    monkeypatch.setattr("surface_recon.universal_core.fingerprint_host_services",
                        lambda target, row: ([], ("service-fingerprinting",)))
    monkeypatch.setattr("surface_recon.tooling.execute_tool", lambda tool, target:
        ToolExecution("nmap", True, [{
            "description": "surface", "finding": False, "source": "nmap",
            "evidence": {"kind": "nmap-surface", "hosts": [{
                "addresses": ["127.0.0.1"], "services": [
                    {"port": 8080, "service": "http-proxy"},
                    {"port": 9000, "service": "http"},
                ],
            }]},
        }], covered_subcapabilities=nmap.subcapabilities))
    seen = []
    def fake_web(target):
        seen.append(target.value)
        return CoreExecution(True, [], ("http-probing",), [])
    monkeypatch.setattr("surface_recon.core.recon_target", fake_web)

    assess_targets(["127.0.0.1"])

    assert seen.count("http://127.0.0.1:8080") == 1
    assert seen.count("http://127.0.0.1:9000") == 1
