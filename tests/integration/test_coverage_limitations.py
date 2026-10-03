from surface_recon.assessment import assess_targets
from surface_recon.model import AvailabilityState, Capability


def test_unavailable_applicable_capability_is_visible(monkeypatch):
    monkeypatch.setattr(
        "surface_recon.capabilities.applicable_capabilities",
        lambda target: [Capability("http-recon", AvailabilityState.UNAVAILABLE, True)],
    )
    assessment = assess_targets(["https://example.test"])
    coverage = assessment.coverage[0]
    assert coverage.evaluated == []
    assert coverage.unevaluated == ["http-recon"]
    assert coverage.limitations
    assert assessment.status.value == "partial"


def test_failed_capability_does_not_stop_independent_target(monkeypatch):
    calls = iter([
        [Capability("http-recon", AvailabilityState.AVAILABLE, True, status="failed")],
        [Capability("host-recon", AvailabilityState.AVAILABLE, True, status="completed")],
    ])
    monkeypatch.setattr(
        "surface_recon.capabilities.applicable_capabilities", lambda target: next(calls)
    )
    assessment = assess_targets(["https://example.test", "192.0.2.10"])
    assert assessment.coverage[0].unevaluated == ["http-recon"]
    assert assessment.coverage[1].evaluated == ["host-recon"]
    assert assessment.status.value == "partial"
