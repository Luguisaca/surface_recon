from surface_recon.model import Evidence, Finding, FindingStatus, Observation
from surface_recon.results import render_findings


def test_sensitive_evidence_is_redacted_in_human_output():
    evidence = Evidence("e1", "controlled", {"token": "secret123", "banner": "ok"})
    observation = Observation("o1", "t1", "recon", "signal", "controlled", ["e1"])
    finding = Finding(
        "f1", "t1", "possible exposure", FindingStatus.SUPPORTED,
        ["o1"], ["e1"], "controlled evidence",
    )
    output = render_findings([finding], [observation], [evidence])
    assert "secret123" not in output
    assert "[REDACTED]" in output
