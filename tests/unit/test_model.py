import pytest

from surface_recon.model import (
    Assessment,
    Evidence,
    Finding,
    FindingStatus,
    ScopeState,
    Target,
)


def test_assessment_rejects_out_of_scope_target():
    assessment = Assessment(
        id="a1",
        targets=[Target(id="t1", value="example", scope_state=ScopeState.OUT_OF_SCOPE)],
    )
    with pytest.raises(ValueError, match="authorized"):
        assessment.validate_scope()


def test_finding_requires_traceable_observation_and_evidence():
    finding = Finding(
        id="f1",
        target_id="t1",
        description="Potential issue",
        status=FindingStatus.POTENTIAL,
        observation_ids=[],
        evidence_ids=[],
        context="controlled test",
    )
    with pytest.raises(ValueError, match="supporting"):
        finding.validate_traceability()


def test_evidence_can_hold_minimal_reference():
    evidence = Evidence(id="e1", source="controlled", content={"reference": "artifact-1"})
    assert evidence.content["reference"] == "artifact-1"
