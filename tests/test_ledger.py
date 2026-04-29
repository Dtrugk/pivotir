"""Tests for the receipt ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from pivotir.ledger.writer import Receipt, get_receipt, read_receipts, write_receipt
from pivotir.workspace.layout import investigation_ledger_path


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PIVOTIR_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


def _sample_receipt(inv_id: str = "INV-x", sub_id: str | None = "SUB-dc-a") -> Receipt:
    return Receipt(
        investigation_id=inv_id,
        subcase_id=sub_id,
        audit_id="pivotir-test-20260429-aaaaaa",
        tool="run_evtxecmd",
        args={"input": "/cases/x/Security.evtx"},
        input_paths=["/cases/x/Security.evtx"],
        input_hashes={"/cases/x/Security.evtx": "deadbeef"},
        output_path="/wrk/SUB-dc-a/outputs/evtx_security.csv",
        output_sha256="cafebabe",
        parser_version="EvtxECmd 1.5.0",
    )


def test_write_creates_ledger_file(isolated_workspace: Path) -> None:
    r = _sample_receipt()
    path = write_receipt(r)
    assert path == investigation_ledger_path("INV-x")
    assert path.exists()


def test_write_appends_line_per_receipt(isolated_workspace: Path) -> None:
    write_receipt(_sample_receipt())
    write_receipt(_sample_receipt())
    write_receipt(_sample_receipt())
    receipts = read_receipts("INV-x")
    assert len(receipts) == 3


def test_read_returns_empty_when_no_ledger(isolated_workspace: Path) -> None:
    assert read_receipts("INV-nope") == []


def test_get_receipt_returns_one_by_id(isolated_workspace: Path) -> None:
    r = _sample_receipt()
    write_receipt(r)
    fetched = get_receipt("INV-x", r.id)
    assert fetched is not None
    assert fetched.id == r.id
    assert fetched.tool == "run_evtxecmd"


def test_get_receipt_returns_none_when_missing(isolated_workspace: Path) -> None:
    assert get_receipt("INV-x", "R-nope") is None


def test_lfa_level_receipt_has_no_subcase(isolated_workspace: Path) -> None:
    r = _sample_receipt(sub_id=None)
    write_receipt(r)
    receipts = read_receipts("INV-x")
    assert receipts[0].subcase_id is None


def test_receipt_id_is_auto_assigned_when_omitted(isolated_workspace: Path) -> None:
    r = _sample_receipt()
    assert r.id.startswith("R-")
    assert len(r.id) > len("R-")
