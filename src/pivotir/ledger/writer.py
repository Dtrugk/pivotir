"""Append-only JSONL receipt ledger for PivotIR.

Every L2 tool call (run_*, read_output_*) appends a Receipt to the ledger.
The receipt is the forensic provenance for that call:
- which tool was run with which args
- input paths + sha256
- output path + sha256
- when it ran, by which subcase, with what audit_id

Findings reference receipts by their `id`. The LFA's verify_subcase_findings
checks every finding's evidence_refs resolve to a receipt here.

The ledger never updates or deletes — append-only. Append is process-locked
(threading.Lock) for safety within a single MCP server process; cross-process
safety relies on POSIX append semantics.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from pivotir.state.ids import new_receipt_id
from pivotir.workspace.layout import investigation_ledger_path

_lock = threading.Lock()


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class Receipt(BaseModel):
    """Forensic provenance entry for one tool call."""

    id: str = Field(default_factory=new_receipt_id)
    investigation_id: str
    subcase_id: str | None = None  # None = LFA-level call
    audit_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    input_paths: list[str] = Field(default_factory=list)
    input_hashes: dict[str, str] = Field(default_factory=dict)  # path -> sha256
    output_path: str | None = None
    output_sha256: str | None = None
    parser_version: str | None = None
    started_at: datetime = Field(default_factory=_utc_now)
    finished_at: datetime | None = None
    success: bool = True
    error: str | None = None


def write_receipt(receipt: Receipt) -> Path:
    """Append a receipt to the investigation's ledger. Returns the ledger path."""
    path = investigation_ledger_path(receipt.investigation_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = receipt.model_dump_json() + "\n"
    with _lock, path.open("a", encoding="utf-8") as f:
        f.write(line)
    return path


def read_receipts(investigation_id: str) -> list[Receipt]:
    """Read every receipt from the ledger. For verification + queries."""
    path = investigation_ledger_path(investigation_id)
    if not path.exists():
        return []
    receipts: list[Receipt] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            receipts.append(Receipt.model_validate_json(line))
    return receipts


def get_receipt(investigation_id: str, receipt_id: str) -> Receipt | None:
    """Fetch a single receipt by id. Linear scan; cache later if hot."""
    for r in read_receipts(investigation_id):
        if r.id == receipt_id:
            return r
    return None
