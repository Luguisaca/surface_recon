import pytest

from surface_recon.model import ScopeState, Target
from surface_recon.process import run_process


def test_out_of_scope_target_cannot_be_used_for_external_invocation():
    target = Target("t1", "https://related.example.test", ScopeState.OUT_OF_SCOPE)
    with pytest.raises(ValueError, match="authorized scope"):
        run_process(["python", "--version"], target=target)


def test_destructive_external_action_is_blocked():
    target = Target("t1", "https://example.test", ScopeState.AUTHORIZED)
    with pytest.raises(ValueError, match="unsafe"):
        run_process(["python", "--version"], target=target, action_kind="destructive")
