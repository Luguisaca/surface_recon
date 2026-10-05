import sys

from surface_recon import cli


def test_cli_accepts_one_and_multiple_targets(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "https://example.test"])
    assert cli.main() == 2
    assert "Target: https://example.test" in capsys.readouterr().out

    monkeypatch.setattr(
        sys, "argv", ["surface-recon", "assess", "https://example.test", "192.0.2.10"]
    )
    assert cli.main() == 2
    output = capsys.readouterr().out
    lines = output.splitlines()\n    assert "Target: https://example.test" in lines\n    assert "Target: 192.0.2.10" in lines


def test_cli_returns_machine_observable_partial(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "unclassifiable-target"])
    assert cli.main() == 2
