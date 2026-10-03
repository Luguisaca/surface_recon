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
