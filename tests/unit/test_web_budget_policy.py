from surface_recon.controls import ReconControls


def test_web_budget_is_bounded_but_scales_with_profile():
    low = ReconControls(noise="low").web_budget
    auto = ReconControls(profile="auto").web_budget
    deep = ReconControls(profile="deep").web_budget
    assert 30 < low[0] < auto[0] < deep[0] <= 1000
    assert 0 < low[1] < auto[1] < deep[1]
    assert all(isinstance(limit, int) and limit > 0 for limit in (low[0], auto[0], deep[0]))


def test_low_noise_disables_external_providers():
    assert not ReconControls(noise="low").extensions
