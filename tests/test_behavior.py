"""Behavioral smoke tests using synthetic, non-network inputs."""

import subprocess
import sys

import pytest

from surface_recon.classification import classify_target
from surface_recon.model import Assessment, ClassificationState, Finding, FindingStatus, ScopeState, Target
from surface_recon.redaction import minimize, redact_text
from surface_recon.web import _HTML, inspect_authorized


def test_url_classification():
    item = classify_target(Target("example", "https://example.test", ScopeState.AUTHORIZED))
    assert item.target_type == "url"
    assert item.classification_state is ClassificationState.RESOLVED


def test_unknown_input_preserved():
    item = classify_target(Target("example", "???", ScopeState.AUTHORIZED))
    assert item.target_type == "opaque"


def test_out_of_scope_fails():
    item = Assessment(id="example", targets=[Target("target", "example", ScopeState.OUT_OF_SCOPE)])
    with pytest.raises(ValueError, match="authorized"):
        item.validate_scope()


def test_findings_require_support():
    finding = Finding(
        id="example", target_id="target", description="Potential issue",
        status=FindingStatus.POTENTIAL, observation_ids=[], evidence_ids=[],
        context="synthetic case",
    )
    with pytest.raises(ValueError, match="supporting"):
        finding.validate_traceability()


def test_bearer_values_are_redacted():
    result = redact_text("Authorization: Bearer sample-value")
    assert "sample-value" not in result
    assert "[REDACTED]" in result


def test_nested_sensitive_fields_are_minimized():
    result = minimize({"token": "sample-value", "safe": "visible"})
    assert result == {"token": "[REDACTED]", "safe": "visible"}


def test_local_interface_requires_authorization():
    with pytest.raises(ValueError, match="explicit authorization"):
        inspect_authorized("opaque://example", authorized=False, use_extensions=False)


def test_opaque_input_does_not_need_network():
    result = inspect_authorized("opaque://example", authorized=True, use_extensions=False)
    assert result["status"] in {"completed", "partial"}
    assert result["rows"][0]["target"] == "opaque://example"


def test_interface_brand_and_controls():
    assert "Surface_Recon" in _HTML
    assert "LUGUISACA" in _HTML
    assert "Perfil" in _HTML


def test_cli_help_contract():
    result = subprocess.run(
        [sys.executable, "-m", "surface_recon", "serve", "--help"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0
    assert "--port" in result.stdout
