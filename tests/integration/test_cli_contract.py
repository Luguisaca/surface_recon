import sys

from surface_recon import cli


def test_cli_accepts_one_and_multiple_targets(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "https://example.test"])
    assert cli.main() == 2
    assert capsys.readouterr().out.splitlines().count("Target: https://example.test") == 1

    monkeypatch.setattr(
        sys, "argv", ["surface-recon", "assess", "https://example.test", "192.0.2.10"]
    )
    assert cli.main() == 2
    lines = capsys.readouterr().out.splitlines()
    assert lines.count("Target: https://example.test") == 1
    assert lines.count("Target: 192.0.2.10") == 1


def test_cli_returns_machine_observable_partial(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "unclassifiable-target"])
    assert cli.main() == 2
