"""Tests for workspace path layout."""

from __future__ import annotations

from pathlib import Path

import pytest

from pivotir.workspace import layout


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point PIVOTIR_WORKSPACE_ROOT at tmp_path so tests don't touch ~/.pivotir."""
    monkeypatch.setenv("PIVOTIR_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


def test_workspace_root_uses_env_override(isolated_workspace: Path) -> None:
    assert layout.workspace_root() == isolated_workspace.resolve()


def test_workspace_root_default_is_home_dot_pivotir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PIVOTIR_WORKSPACE_ROOT", raising=False)
    assert layout.workspace_root() == (Path.home() / ".pivotir").resolve()


def test_init_investigation_dirs_creates_required_subdirs(isolated_workspace: Path) -> None:
    inv_id = "INV-test"
    layout.init_investigation_dirs(inv_id)
    assert layout.investigation_dir(inv_id).is_dir()
    assert layout.subcases_dir(inv_id).is_dir()
    assert layout.reports_dir(inv_id).is_dir()


def test_init_investigation_dirs_is_idempotent(isolated_workspace: Path) -> None:
    inv_id = "INV-test"
    layout.init_investigation_dirs(inv_id)
    layout.init_investigation_dirs(inv_id)  # second call must not raise


def test_init_subcase_dirs_creates_evidence_outputs(isolated_workspace: Path) -> None:
    layout.init_investigation_dirs("INV-x")
    layout.init_subcase_dirs("INV-x", "SUB-dc-a")
    assert layout.subcase_dir("INV-x", "SUB-dc-a").is_dir()
    assert layout.subcase_evidence_dir("INV-x", "SUB-dc-a").is_dir()
    assert layout.subcase_outputs_dir("INV-x", "SUB-dc-a").is_dir()


def test_find_investigation_for_subcase_returns_owner(isolated_workspace: Path) -> None:
    layout.init_investigation_dirs("INV-x")
    layout.init_subcase_dirs("INV-x", "SUB-host-1")
    assert layout.find_investigation_for_subcase("SUB-host-1") == "INV-x"


def test_find_investigation_for_subcase_returns_none_when_missing(
    isolated_workspace: Path,
) -> None:
    assert layout.find_investigation_for_subcase("SUB-nope") is None


def test_investigation_db_and_ledger_paths_are_under_investigation_dir(
    isolated_workspace: Path,
) -> None:
    inv_dir = layout.investigation_dir("INV-x")
    assert layout.investigation_db_path("INV-x").parent == inv_dir
    assert layout.investigation_ledger_path("INV-x").parent == inv_dir
