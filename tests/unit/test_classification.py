from surface_recon.classification import classify_target
from surface_recon.model import ClassificationState, ScopeState, Target

def test_classifies_url():
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED)
    result = classify_target(target)
    assert result.target_type == "url"
    assert result.classification_state is ClassificationState.RESOLVED

def test_unknown_target_is_preserved_as_opaque():
    target = Target("t1", "???", ScopeState.AUTHORIZED)
    result = classify_target(target)
    assert result.target_type == "opaque"
    assert result.classification_state is ClassificationState.RESOLVED


def test_domain_name_classifies_as_host():
    from surface_recon.classification import classify_target
    from surface_recon.model import ScopeState, Target
    target = classify_target(Target("d", "example.com", ScopeState.AUTHORIZED))
    assert target.target_type == "host"
