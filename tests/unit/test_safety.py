import pytest

from surface_recon.capabilities import CapabilityDefinition
from surface_recon.model import AvailabilityState, ScopeState, Target


def test_exploitative_capability_is_rejected():
    capability = CapabilityDefinition(
        "exploit-check", AvailabilityState.AVAILABLE, lambda target: True,
        action_kind="exploit",
    )
    with pytest.raises(ValueError, match="unsafe"):
        capability.consider(Target("t1", "https://example.test", ScopeState.AUTHORIZED))
