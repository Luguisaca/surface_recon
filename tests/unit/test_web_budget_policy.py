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


def test_unlimited_has_no_request_count_but_retains_deadline():
    requests, seconds = ReconControls(profile="unlimited").web_budget
    assert requests is None and seconds == 3600.0


def test_http_retry_after_policy():
    from surface_recon.core import _retry_delay
    assert _retry_delay(429, {"Retry-After": "3"}) == 3.0
    assert _retry_delay(503, {"retry-after": "90"}) == 90.0
    assert _retry_delay(429, {}) == 5.0
    assert _retry_delay(200, {"Retry-After": "10"}) == 0.0
