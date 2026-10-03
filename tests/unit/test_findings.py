import pytest

from surface_recon.findings import build_finding
from surface_recon.model import FindingStatus, Observation, Evidence


def test_supported_finding_preserves_traceability():
    observation = Observation(
        id="o1",
        target_id="t1",
        capability_id="controlled",
        description="Observable condition",
        context="controlled test",
        evidence_ids=["e1"],
    )
    evidence = Evidence(
        id="e1",
        source="controlled",
        content={"detail": "observable"},
    )

    finding = build_finding(
        target_id="t1",
        description="Supported condition",
        observations=[observation],
        evidence=[evidence],
        sufficient_evidence=True,
    )

    assert finding.status is FindingStatus.SUPPORTED
    assert finding.target_id == "t1"
    assert finding.observation_ids == ["o1"]
    assert finding.evidence_ids == ["e1"]
    finding.validate_traceability()


def test_insufficient_evidence_is_not_confirmed():
    observation = Observation(
        id="o1",
        target_id="t1",
        capability_id="controlled",
        description="Weak signal",
        context="controlled test",
    )

    finding = build_finding(
        target_id="t1",
        description="Possible condition",
        observations=[observation],
        evidence=[],
        sufficient_evidence=False,
    )

    assert finding.status is FindingStatus.POTENTIAL


def test_duplicate_tool_findings_are_correlated_into_one_result():
    from surface_recon.findings import findings_from_capability_result

    findings, observations, evidence = findings_from_capability_result(
        target_id="t1",
        capability_id="http-recon",
        observations=[
            {
                "description": "Exposed condition",
                "evidence": {"source_detail": "a"},
                "source": "tool-a",
                "finding": True,
                "correlation_key": "condition:x",
            },
            {
                "description": "Exposed condition",
                "evidence": {"source_detail": "b"},
                "source": "tool-b",
                "finding": True,
                "correlation_key": "condition:x",
            },
        ],
    )

    assert len(observations) == 2
    assert len(evidence) == 2
    assert len(findings) == 1
    assert len(findings[0].observation_ids) == 2
    assert len(findings[0].evidence_ids) == 2
    assert {item.source for item in evidence} == {"tool-a", "tool-b"}


def test_normalization_minimizes_session_identifiers_before_persistence():
    from surface_recon.findings import findings_from_capability_result
    findings, observations, evidence = findings_from_capability_result(
        target_id="t1",
        capability_id="http-recon",
        observations=[{
            "description": "Observed /login;WEBWOLFSESSION=SECRET",
            "evidence": {"url": "http://example.test/login;WEBWOLFSESSION=SECRET"},
            "finding": False,
        }],
    )
    assert not findings
    assert "SECRET" not in observations[0].description
    assert "SECRET" not in str(evidence[0].content)
