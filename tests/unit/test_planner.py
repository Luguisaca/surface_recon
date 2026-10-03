from surface_recon.tooling import ToolCandidate, select_tools_for_gaps


def _tool(name, subs):
    return ToolCandidate(name, "http-recon", (name,), name, ("Linux",), "test", tuple(subs), f"/bin/{name}")


def test_planner_uses_only_tools_that_close_current_gaps(monkeypatch):
    tools = [_tool("probe", ("http-probing",)), _tool("detect", ("template-detection",))]
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: tools)

    selected = select_tools_for_gaps("http-recon", {"template-detection"})

    assert [tool.id for tool in selected] == ["detect"]


def test_planner_prefers_smallest_set_with_most_missing_coverage(monkeypatch):
    tools = [
        _tool("one", ("port-discovery",)),
        _tool("combined", ("port-discovery", "service-fingerprinting")),
        _tool("irrelevant", ("http-probing",)),
    ]
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: tools)

    selected = select_tools_for_gaps(
        "host-recon", {"port-discovery", "service-fingerprinting"}
    )

    assert [tool.id for tool in selected] == ["combined"]


def test_recommendations_do_not_offer_tools_that_cannot_close_requested_gap(monkeypatch):
    from surface_recon.tooling import recommendations_for

    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [])

    assert recommendations_for("http-recon", {"injection-testing"}) == []
    names = {item.tool_id for item in recommendations_for(
        "http-recon", {"template-detection"}
    )}
    assert "nuclei" in names
    assert "httpx" not in names
