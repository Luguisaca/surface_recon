import sys

import pytest

from surface_recon.process import run_process


def test_process_uses_structured_arguments():
    result = run_process([sys.executable, "-c", "print('controlled')"])
    assert result.succeeded
    assert result.stdout.strip() == "controlled"


def test_process_rejects_shell_string():
    with pytest.raises(ValueError, match="structured"):
        run_process("echo unsafe")


def test_process_failure_is_visible():
    result = run_process([sys.executable, "-c", "raise SystemExit(7)"])
    assert result.returncode == 7
    assert not result.succeeded
