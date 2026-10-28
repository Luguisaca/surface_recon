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


def test_web_ui_exposes_recon_controls_and_human_wording():
    from surface_recon.web import _HTML
    assert 'Perfil' in _HTML
    assert 'Pasivo' in _HTML
    assert 'Solo proveedores' in _HTML
    assert 'Qué falta comprobar' in _HTML
    assert 'Gaps / siguientes fases' not in _HTML


def test_human_qa_validation_errors_are_distinct_and_accessible():
    from surface_recon.web import _HTML
    assert 'Falta el objetivo:' in _HTML
    assert 'Falta la autorización:' in _HTML
    assert 'role="status" aria-live="polite"' in _HTML
    assert 'id="profile-help"' in _HTML
    assert 'Cómo continuar' in _HTML
    assert 'no lo demuestra' in _HTML


def test_web_ui_exposes_downloadable_traceable_exports():
    from surface_recon.web import _HTML
    assert 'Descargar informe HTML' in _HTML
    assert 'Exportar JSON' in _HTML
    assert 'Exportar CSV' in _HTML
    payload = inspect_authorized('opaque://preserved', authorized=True, use_extensions=False)
    assert payload['export']['run_id'] == payload['run_id']
    assert payload['csv'].startswith('run_id,target,')
    assert payload['html']


def test_web_ui_rejects_unknown_provider_before_running():
    with pytest.raises(ValueError, match='adapter verificado'):
        inspect_authorized('opaque://preserved', authorized=True, include=('not-a-provider',))
