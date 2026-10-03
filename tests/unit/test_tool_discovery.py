from pathlib import Path

from surface_recon.tooling import discover_tools, recommendations_for


def test_discovers_available_candidate_from_path(monkeypatch):
    monkeypatch.setattr("surface_recon.tooling.shutil.which", lambda name: f"/tools/{name}" if name == "nuclei" else None)
    monkeypatch.setattr("surface_recon.tooling._discovery_roots", lambda: [])

    discovered = discover_tools("http-recon")

    assert [tool.id for tool in discovered] == ["nuclei"]
    assert discovered[0].executable == "/tools/nuclei"


def test_recommends_candidates_when_capability_has_no_available_tool(monkeypatch):
    monkeypatch.setattr("surface_recon.tooling.shutil.which", lambda name: None)
    monkeypatch.setattr("surface_recon.tooling._discovery_roots", lambda: [])

    recommendations = recommendations_for("http-recon")

    assert recommendations
    assert all(item.capability_id == "http-recon" for item in recommendations)
    assert any(item.tool_id == "nuclei" for item in recommendations)
    assert any(item.tool_id == "httpx" for item in recommendations)
    assert all(item.install_automatically is False for item in recommendations)


def test_unknown_capability_has_no_invented_recommendation():
    assert recommendations_for("unknown-capability") == []


def test_discovers_candidate_outside_path_from_bounded_tool_root(monkeypatch, tmp_path):
    tool = tmp_path / "ProjectDiscovery" / "httpx" / "httpx.exe"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"")
    monkeypatch.setattr("surface_recon.tooling.shutil.which", lambda name: None)
    monkeypatch.setattr("surface_recon.tooling._discovery_roots", lambda: [Path(tmp_path)])
    monkeypatch.setattr("surface_recon.tooling._provider_identity_matches", lambda candidate, executable: True)

    discovered = discover_tools("http-recon")

    assert discovered[0].id == "httpx"
    assert discovered[0].executable == str(tool)

def test_httpx_adapter_rejects_incompatible_cli_identity(monkeypatch):
    class Probe:
        succeeded = False
        stdout = "Usage: httpx [OPTIONS] URL"
        stderr = "Error: No such option: -e"
    monkeypatch.setattr("surface_recon.tooling._find_executable", lambda names: "/usr/bin/httpx" if names == ("httpx",) else None)
    monkeypatch.setattr("surface_recon.tooling.run_process", lambda *args, **kwargs: Probe())
    assert all(tool.id != "httpx" for tool in discover_tools("http-recon"))
