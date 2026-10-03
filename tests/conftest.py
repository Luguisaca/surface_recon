"""Shared fixtures for controlled Surface_Recon tests."""

from pathlib import Path

import pytest


@pytest.fixture
def controlled_workspace(tmp_path: Path) -> Path:
    """Return an isolated workspace owned by the test run."""
    workspace = tmp_path / "controlled-target"
    workspace.mkdir()
    return workspace