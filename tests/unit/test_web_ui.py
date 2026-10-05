import subprocess
import sys

import pytest

from surface_recon.web import inspect_authorized, _handler


def test_web_ui_requires_explicit_authorization_before_assessment():
    with pytest.raises(ValueError, match="explicit authorization"):
        inspect_authorized("opaque://preserved", authorized=False, use_extensions=False)


def test_web_ui_uses_current_assessment_engine_for_authorized_target():
    payload = inspect_authorized("opaque://preserved", authorized=True, use_extensions=False)
    assert payload["status"] in {"completed", "partial"}
    assert payload["rows"][0]["target"] == "opaque://preserved"
    assert "evaluated" in payload["rows"][0]
    assert "unevaluated" in payload["rows"][0]


def test_web_handler_is_loopback_surface_contract():
    handler = _handler(False)
    assert handler is not None


def test_cli_keeps_serve_product_surface():
    completed = subprocess.run(
        [sys.executable, "-m", "surface_recon", "serve", "--help"],
        capture_output=True, text=True, timeout=15,
    )
    assert completed.returncode == 0
    assert "--port" in completed.stdout
    assert "--core-only" in completed.stdout
