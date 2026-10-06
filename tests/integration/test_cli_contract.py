import sys

from surface_recon import cli


def test_cli_accepts_one_and_multiple_targets(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "--authorized", "https://example.test"])
    assert cli.main() == 2
    assert "Target: https://example.test" in capsys.readouterr().out

    monkeypatch.setattr(
        sys, "argv", ["surface-recon", "assess", "--authorized", "https://example.test", "192.0.2.10"]
    )
    assert cli.main() == 2
    output = capsys.readouterr().out
    assert "https://example.test" in output and "192.0.2.10" in output


def test_cli_returns_machine_observable_partial(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "--authorized", "unclassifiable-target"])
    assert cli.main() == 2


def test_cli_fails_closed_without_authorization(monkeypatch, capsys):
    called = False
    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("assessment must not execute")
    monkeypatch.setattr(cli, "assess_targets", forbidden)
    monkeypatch.setattr(sys, "argv", ["surface-recon", "recon", "https://example.test"])
    assert cli.main() == 3
    assert called is False
    assert "autorización requerida" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", ["surface-recon", "assess", "https://example.test"])
    assert cli.main() == 3
    assert called is False


def test_recon_reports_progress_and_cancels_cleanly(monkeypatch, capsys):
    def interrupted(targets, use_extensions=True, progress=None):
        assert progress is not None
        progress("fixture progress")
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "assess_targets", interrupted)
    monkeypatch.setattr(sys, "argv", ["surface-recon", "recon", "--authorized", "https://example.test"])
    assert cli.main() == 130
    captured = capsys.readouterr()
    assert "fixture progress" in captured.out
    assert "reconocimiento cancelado" in captured.err
