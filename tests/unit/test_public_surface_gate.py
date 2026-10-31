"""Regression tests for the public disclosure gate."""
from pathlib import Path
import importlib.util
import json
import subprocess

MODULE_FILE = Path(__file__).resolve().parents[2] / "tools" / "public_surface_gate.py"
SPEC = importlib.util.spec_from_file_location("surface_public_gate", MODULE_FILE)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def test_public_example_text_does_not_trigger():
    assert gate.scan("Visit https://example.test and use Python in a virtual environment.", "README") == []


def test_private_repository_reference_is_rejected_without_disclosing_value():
    private = "surface_recon" + "-internal"
    found = gate.scan(f"See {private} for details", "PR.body")
    assert found and any("private-repository-reference" in row for row in found)
    assert all(private not in row for row in found)


def test_operational_device_and_local_path_rejected():
    device = "PC" + "2"
    path = "E:" + "\\" + "Luguisaca" + "\\" + "private"
    found = gate.scan(f"Execution on {device} at {path}", "qa.md")
    assert any("operational-device" in row for row in found)
    assert any("personal-local-path" in row for row in found)
    assert all(device not in row and path not in row for row in found)


def test_credentials_not_printed():
    secret = "ghp_" + ("A" * 30)
    found = gate.scan("token = " + secret, "config.md")
    assert any("credential-like-value" in row for row in found)
    assert all(secret not in row for row in found)


def test_pr_metadata_and_discussion_are_checked(tmp_path, monkeypatch):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({
        "number": 12,
        "pull_request": {"title": "Valid candidate", "body": "See " + "surface_recon" + "-internal"}
    }), encoding="utf-8")
    urls = []
    def fake_fetch(url, token):
        urls.append(url)
        return [{"id": 41, "body": "reviewed from Dell" + "-Server"}]
    monkeypatch.setattr(gate, "fetch_comments", fake_fetch)
    env = {
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_REPOSITORY": "owner/public",
        "GITHUB_TOKEN": "test-token",
    }
    found = gate.scan_event(env)
    assert len(urls) == 3
    assert any("PR.body" in row for row in found)
    assert any("PR.discussion" in row for row in found)
    assert all(("Dell" + "-Server") not in row for row in found)


def test_tracked_repository_surface_detects_bad_file(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "README.md").write_text("Public documentation", encoding="utf-8")
    (tmp_path / "qa.md").write_text("Machine: " + "PC" + "1", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "--", "README.md", "qa.md"], check=True)
    found, count = gate.scan_files(tmp_path)
    assert count == 2
    assert len(found) == 1 and "operational-device" in found[0]
