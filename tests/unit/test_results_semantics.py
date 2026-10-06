from surface_recon.model import (
    Assessment, AssessmentStatus, Capability, Coverage, ScopeState, Target,
)
from surface_recon.results import render_assessment


def test_followed_resources_are_not_mislabeled_out_of_scope():
    target = Target(
        "t1", "https://example.test/", ScopeState.AUTHORIZED, target_type="url",
        discovered_resources=["https://example.test/api"],
    )
    capability = Capability(
        "http-recon", availability="available", target_id="t1",
        status="completed", tools_used=["surface-recon-core"],
        required_subcapabilities=["http-probing"],
        evaluated_subcapabilities=["http-probing"],
    )
    assessment = Assessment(
        "a1", [target], AssessmentStatus.COMPLETED,
        capabilities=[capability],
        coverage=[Coverage("t1", ["http-probing"], ["http-probing"], [])],
    )

    rendered = render_assessment(assessment)

    assert "Discovered/followed resources within submitted target context: 1" in rendered
    assert "out-of-scope context" not in rendered
    assert "Purpose not recorded" not in rendered


def test_supported_findings_are_not_labeled_merely_potential():
    from surface_recon.model import Finding, FindingStatus

    target = Target("t1", "x", ScopeState.AUTHORIZED, target_type="opaque")
    finding = Finding(
        "f1", "t1", "demonstrated condition", FindingStatus.SUPPORTED,
        ["o1"], ["e1"], "evidence-backed",
    )
    assessment = Assessment(
        "a1", [target], AssessmentStatus.COMPLETED,
        findings=[finding], coverage=[Coverage("t1")],
    )

    rendered = render_assessment(assessment)

    assert "1 evidence-supported risk finding(s) reported" in rendered
    assert "potential risk finding(s)" not in rendered


def test_surface_data_retires_soft_not_found_hypothesis():
    from surface_recon.model import Evidence, Observation
    from surface_recon.results import _surface_data
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED, target_type="url")
    assessment = Assessment("a1", [target], AssessmentStatus.PARTIAL, coverage=[Coverage("t1")])
    assessment.evidence = [
        Evidence("e1", "t1", "surface-recon-core", {"kind":"hypothesis","hypothesis":"api-surface","url":"https://example.test/api"}),
        Evidence("e2", "t1", "surface-recon-core", {"kind":"not_found","reason":"matches missing-route baseline","url":"https://example.test/api"}),
    ]
    assessment.observations = [
        Observation("o1", "t1", "hypothesis", ["e1"], {}),
        Observation("o2", "t1", "rejected", ["e2"], {}),
    ]
    row = _surface_data(assessment)[0]
    assert row["hypotheses"] == []


def test_surface_data_retires_hypothesis_after_explicit_404():
    from surface_recon.model import Evidence, Observation
    from surface_recon.results import _surface_data
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED, target_type="url")
    assessment = Assessment("a1", [target], AssessmentStatus.PARTIAL, coverage=[Coverage("t1")])
    assessment.evidence = [
        Evidence("e1", "t1", "surface-recon-core", {"kind":"hypothesis","hypothesis":"api-surface","url":"https://example.test/api"}),
        Evidence("e2", "t1", "surface-recon-core", {"kind":"interesting","url":"https://example.test/api","status":404,"fetched":True}),
    ]
    assessment.observations = [
        Observation("o1", "t1", "hypothesis", ["e1"], {}),
        Observation("o2", "t1", "observed", ["e2"], {}),
    ]
    row = _surface_data(assessment)[0]
    assert row["hypotheses"] == []
