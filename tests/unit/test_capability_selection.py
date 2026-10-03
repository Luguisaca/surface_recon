from surface_recon.capabilities import applicable_capabilities
from surface_recon.model import ScopeState, Target

def test_selects_capabilities_from_classified_target():
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED,
                    target_type="url")
    selected = applicable_capabilities(target)
    assert selected
    assert all(cap.applicable for cap in selected)
