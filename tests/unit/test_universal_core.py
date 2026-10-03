from surface_recon.model import ScopeState, Target
from surface_recon.universal_core import recon_artifact, recon_path

def test_artifact_core_identifies_pe_and_hashes(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"X" * 20 + b"https://example.test/api")
    obs, covered = recon_artifact(Target("x", str(path), ScopeState.AUTHORIZED, target_type="binary"))
    assert "binary-identification" in covered
    assert obs[0]["evidence"]["artifact_type"] == "PE/Windows executable"
    assert len(obs[0]["evidence"]["sha256"]) == 64
    assert obs[1]["evidence"]["urls"] == ["https://example.test/api"]

def test_directory_core_inventories_manifests(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]", encoding="utf-8")
    obs, covered = recon_path(Target("x", str(tmp_path), ScopeState.AUTHORIZED, target_type="directory"))
    assert covered == ("inventory",)
    assert "pyproject.toml" in obs[0]["evidence"]["manifests"]

def test_owned_static_review_marks_candidates_not_findings(tmp_path):
    (tmp_path / "app.py").write_text("value = eval(user_input)", encoding="utf-8")
    from surface_recon.universal_core import static_source_review
    obs, covered = static_source_review(Target("x", str(tmp_path), ScopeState.AUTHORIZED, target_type="repository"))
    assert covered == ("static-analysis",)
    assert obs[0]["finding"] is False
    assert obs[0]["evidence"]["claim"] == "review-candidates-not-confirmed-vulnerabilities"
    assert obs[0]["evidence"]["candidates"][0]["rule"] == "dynamic-eval"

def test_zip_artifact_is_analyzed_without_extraction(tmp_path):
    import zipfile
    path = tmp_path / "sample.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("app/config.json", "{}")
    obs, covered = recon_artifact(Target("z", str(path), ScopeState.AUTHORIZED, target_type="path"))
    assert "static-analysis" in covered
    archive_obs = next(x for x in obs if x["evidence"].get("kind") == "archive-analysis")
    assert archive_obs["evidence"]["entry_count"] == 1
    assert archive_obs["evidence"]["entries"] == ["app/config.json"]


def test_host_core_declares_exact_partial_port_coverage(monkeypatch):
    import surface_recon.universal_core as core
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda *args, **kwargs: [(None,None,None,None,("127.0.0.1",0))])
    class Closed:
        def __enter__(self): return self
        def __exit__(self, *args): return False
    def fake_connection(address, timeout):
        if address[1] == 443:
            return Closed()
        raise OSError("closed")
    monkeypatch.setattr(core.socket, "create_connection", fake_connection)
    obs, covered = core.recon_host(Target("h", "127.0.0.1", ScopeState.AUTHORIZED, target_type="host"))
    ports = next(x["evidence"] for x in obs if x["evidence"].get("kind") == "ports")
    assert ports["full_tcp_range_tested"] is False
    assert ports["tested_port_count"] == len(ports["tested_ports"])
    assert "port-discovery-partial" in covered
    assert "port-discovery" not in covered
