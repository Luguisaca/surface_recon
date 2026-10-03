from pathlib import Path

from surface_recon.assessment import assess_targets
from surface_recon.classification import classify_target
from surface_recon.model import ScopeState, Target


def _classify(value: str):
    return classify_target(Target("t", value, ScopeState.AUTHORIZED))


def test_classifies_network_and_local_target_families(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    folder = tmp_path / "folder"
    folder.mkdir()
    exe = tmp_path / "sample.exe"
    exe.write_bytes(b"MZ")
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00\x01")

    assert _classify("10.10.0.0/24").target_type == "network"
    assert _classify(str(repo)).target_type == "repository"
    assert _classify(str(folder)).target_type == "directory"
    assert _classify(str(exe)).target_type == "binary"
    assert _classify(str(binary)).target_type == "binary"


def test_httpx_alone_cannot_complete_full_web_recon(monkeypatch):
    from surface_recon.tooling import ToolCandidate, ToolExecution

    httpx = ToolCandidate(
        "httpx", "http-recon", ("httpx",), "probe", ("Linux",), "MIT",
        subcapabilities=("http-probing", "technology-fingerprinting"),
        executable="/bin/httpx",
    )
    monkeypatch.setattr(
        "surface_recon.tooling.discover_tools",
        lambda capability_id: [httpx] if capability_id == "http-recon" else [],
    )
    monkeypatch.setattr(
        "surface_recon.tooling.execute_tool",
        lambda tool, target: ToolExecution(tool.id, True, [], covered_subcapabilities=tool.subcapabilities),
    )

    assessment = assess_targets(["https://example.test"])
    web = assessment.coverage[0]

    assert "http-probing" in web.evaluated
    assert "technology-fingerprinting" in web.evaluated
    assert "template-detection" in web.unevaluated
    assert assessment.status.value == "partial"
