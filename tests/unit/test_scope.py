from surface_recon.assessment import assess_targets
from surface_recon.model import ScopeState, Target


def test_submitted_targets_define_authorized_scope():
    assessment = assess_targets(["https://example.test"])
    assert assessment.targets[0].scope_state is ScopeState.AUTHORIZED


def test_discovered_resource_is_context_only():
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED)
    target.discovered_resources.append("https://related.example.test")
    assert target.discovered_resources == ["https://related.example.test"]
