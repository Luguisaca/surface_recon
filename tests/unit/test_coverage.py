from surface_recon.assessment import aggregate_coverage
from surface_recon.model import AvailabilityState, Capability, Limitation


def test_coverage_separates_evaluated_from_unavailable_and_failed():
    caps = [
        Capability("ok", AvailabilityState.AVAILABLE, True, status="completed"),
        Capability("missing", AvailabilityState.UNAVAILABLE, True),
        Capability("broken", AvailabilityState.AVAILABLE, True, status="failed"),
    ]
    coverage = aggregate_coverage("t1", caps, [])

    assert coverage.considered == ["ok", "missing", "broken"]
    assert coverage.evaluated == ["ok"]
    assert coverage.unevaluated == ["missing", "broken"]


def test_coverage_keeps_limitations_attached():
    limitation = Limitation("t1", "Capability failed.", "Coverage is partial.", "broken")
    coverage = aggregate_coverage("t1", [], [limitation])
    assert coverage.limitations == [limitation]


def test_full_coverage_supersedes_partial_marker():
    cap = Capability(
        "host-recon", AvailabilityState.AVAILABLE, True, status="completed",
        required_subcapabilities=["port-discovery"],
        evaluated_subcapabilities=["port-discovery-partial", "port-discovery"],
    )

    coverage = aggregate_coverage("t1", [cap], [])

    assert "port-discovery" in coverage.evaluated
    assert "port-discovery-partial" not in coverage.evaluated
    assert coverage.unevaluated == []


def test_ipv6_host_is_url_authority_safe():
    from surface_recon.assessment import _url_host

    assert _url_host("2001:db8::10") == "[2001:db8::10]"
    assert _url_host("127.0.0.1") == "127.0.0.1"
    assert _url_host("example.test") == "example.test"
