from surface_recon.controls import ReconControls
from surface_recon.findings import findings_from_capability_result
from surface_recon.model import FindingStatus
from surface_recon.reporting import csv_export


def test_provider_timeout_and_pacing_are_bounded():
    ReconControls(provider_timeout=30, pace_ms=0).validate(use_extensions=False)
    ReconControls(provider_timeout=3600, pace_ms=5000).validate(use_extensions=False)
    for controls in (ReconControls(provider_timeout=29), ReconControls(provider_timeout=3601), ReconControls(pace_ms=5001)):
        try:
            controls.validate(use_extensions=False)
        except ValueError:
            pass
        else:
            raise AssertionError("control fuera de rango debe fallar cerrado")


def test_cleartext_http_condition_can_remain_potential_with_evidence():
    findings, _, evidence = findings_from_capability_result(
        target_id="target-1", capability_id="host-recon", observations=[{
            "description": "Superficie HTTP sin TLS observada en http://example.test:8080",
            "evidence": {"kind": "security-condition", "url": "http://example.test:8080", "impact_demonstrated": False},
            "finding": True, "sufficient_evidence": False, "source": "surface-recon-core",
        }])
    assert evidence
    assert findings[0].status is FindingStatus.POTENTIAL


def test_csv_export_has_one_physical_line_per_row():
    payload = {"run_id": "run", "rows": [{"target": "t", "surface": [], "resources": [], "findings": [], "hypotheses": [], "discarded": [], "evaluated": ["host-discovery"], "unevaluated": [], "lifecycle": []}]}
    text = csv_export(payload)
    assert "\r\r\n" not in text
    assert len(text.splitlines()) == 2


def test_failed_launched_provider_can_preserve_execution_provenance(monkeypatch):
    from surface_recon import tooling
    from surface_recon.tooling import ToolCandidate, execute_tool
    from surface_recon.model import Target, ScopeState
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "network", ("Windows",), "test", ("port-discovery",), executable="nmap")
    class Result:
        succeeded = False
        stderr = "timed out"
        returncode = 124
        stdout = ""
    monkeypatch.setattr(tooling, "run_process", lambda *a, **k: Result())
    result = execute_tool(tool, Target("t", "127.0.0.1", ScopeState.AUTHORIZED, target_type="host"))
    assert not result.succeeded
    assert result.observations[0]["evidence"]["kind"] == "execution-attempt"
    assert result.observations[0]["evidence"]["command"]
