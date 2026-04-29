"""SQLite-backed CRUD for PivotIR state.

Each investigation has its own SQLite database at
    <workspace>/workspaces/<investigation_id>/investigation.db

Schema versioning: implicit. Migrations would land here when the schema evolves;
for v0.0.x we recreate from scratch via init_investigation_db.

Tables:
    investigations  exactly one row — this investigation
    hosts           one row per host added to the investigation
    subcases        one row per FA's per-host slice
    evidence        registered artifacts per subcase

Hypothesis / Finding / Task tables are added in later commits when the
playbook engine and orchestrator land.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pivotir.state.models import (
    Evidence,
    Host,
    HostRole,
    Investigation,
    InvestigationStatus,
    Subcase,
    SubcaseStatus,
)
from pivotir.workspace.layout import investigation_db_path, workspaces_dir

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id            TEXT PRIMARY KEY,
    brief         TEXT NOT NULL,
    anchor_json   TEXT,
    status        TEXT NOT NULL,
    opened_at     TEXT NOT NULL,
    closed_at     TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    investigation_id  TEXT NOT NULL REFERENCES investigations(id),
    name              TEXT NOT NULL,
    evidence_path     TEXT NOT NULL,
    role              TEXT NOT NULL,
    PRIMARY KEY (investigation_id, name)
);

CREATE TABLE IF NOT EXISTS subcases (
    id                TEXT PRIMARY KEY,
    investigation_id  TEXT NOT NULL REFERENCES investigations(id),
    host_name         TEXT NOT NULL,
    evidence_path     TEXT NOT NULL,
    status            TEXT NOT NULL,
    opened_at         TEXT NOT NULL,
    concluded_at      TEXT,
    UNIQUE (investigation_id, host_name)
);

CREATE TABLE IF NOT EXISTS evidence (
    id                TEXT PRIMARY KEY,
    subcase_id        TEXT NOT NULL REFERENCES subcases(id),
    path              TEXT NOT NULL,
    type              TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL,
    sha256            TEXT,
    registered_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_subcase ON evidence (subcase_id);
"""


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_investigation_db(investigation_id: str) -> Path:
    """Create the investigation DB + schema if missing. Returns the DB path."""
    path = investigation_db_path(investigation_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as conn:
        conn.executescript(_SCHEMA)
    return path


# ── Investigation ────────────────────────────────────────────────────────────


def insert_investigation(inv: Investigation) -> None:
    init_investigation_db(inv.id)
    with _connect(investigation_db_path(inv.id)) as conn:
        conn.execute(
            "INSERT INTO investigations (id, brief, anchor_json, status, opened_at, closed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                inv.id,
                inv.brief,
                json.dumps(inv.anchor) if inv.anchor is not None else None,
                inv.status.value,
                inv.opened_at.isoformat(),
                inv.closed_at.isoformat() if inv.closed_at else None,
            ),
        )


def get_investigation(investigation_id: str) -> Investigation | None:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return None
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id, brief, anchor_json, status, opened_at, closed_at "
            "FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_investigation(row)


def list_investigations() -> list[Investigation]:
    """Discover all investigations on disk by scanning workspaces/."""
    out: list[Investigation] = []
    root = workspaces_dir()
    if not root.exists():
        return out
    for inv_dir in sorted(root.iterdir()):
        if not inv_dir.is_dir():
            continue
        inv = get_investigation(inv_dir.name)
        if inv is not None:
            out.append(inv)
    return out


def _row_to_investigation(row: sqlite3.Row) -> Investigation:
    return Investigation(
        id=row["id"],
        brief=row["brief"],
        anchor=json.loads(row["anchor_json"]) if row["anchor_json"] else None,
        status=InvestigationStatus(row["status"]),
        opened_at=datetime.fromisoformat(row["opened_at"]),
        closed_at=datetime.fromisoformat(row["closed_at"]) if row["closed_at"] else None,
    )


# ── Host ─────────────────────────────────────────────────────────────────────


def insert_host(host: Host) -> None:
    with _connect(investigation_db_path(host.investigation_id)) as conn:
        conn.execute(
            "INSERT INTO hosts (investigation_id, name, evidence_path, role) VALUES (?, ?, ?, ?)",
            (host.investigation_id, host.name, host.evidence_path, host.role.value),
        )


def list_hosts(investigation_id: str) -> list[Host]:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return []
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT investigation_id, name, evidence_path, role FROM hosts "
            "WHERE investigation_id = ? ORDER BY name",
            (investigation_id,),
        ).fetchall()
    return [
        Host(
            investigation_id=r["investigation_id"],
            name=r["name"],
            evidence_path=r["evidence_path"],
            role=HostRole(r["role"]),
        )
        for r in rows
    ]


# ── Subcase ──────────────────────────────────────────────────────────────────


def insert_subcase(subcase: Subcase) -> None:
    with _connect(investigation_db_path(subcase.investigation_id)) as conn:
        conn.execute(
            "INSERT INTO subcases (id, investigation_id, host_name, evidence_path, status, opened_at, concluded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                subcase.id,
                subcase.investigation_id,
                subcase.host_name,
                subcase.evidence_path,
                subcase.status.value,
                subcase.opened_at.isoformat(),
                subcase.concluded_at.isoformat() if subcase.concluded_at else None,
            ),
        )


def get_subcase(investigation_id: str, subcase_id: str) -> Subcase | None:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return None
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id, investigation_id, host_name, evidence_path, status, opened_at, concluded_at "
            "FROM subcases WHERE id = ?",
            (subcase_id,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_subcase(row)


def list_subcases(investigation_id: str) -> list[Subcase]:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return []
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT id, investigation_id, host_name, evidence_path, status, opened_at, concluded_at "
            "FROM subcases WHERE investigation_id = ? ORDER BY opened_at",
            (investigation_id,),
        ).fetchall()
    return [_row_to_subcase(r) for r in rows]


def _row_to_subcase(row: sqlite3.Row) -> Subcase:
    return Subcase(
        id=row["id"],
        investigation_id=row["investigation_id"],
        host_name=row["host_name"],
        evidence_path=row["evidence_path"],
        status=SubcaseStatus(row["status"]),
        opened_at=datetime.fromisoformat(row["opened_at"]),
        concluded_at=datetime.fromisoformat(row["concluded_at"]) if row["concluded_at"] else None,
    )


# ── Evidence ─────────────────────────────────────────────────────────────────


def insert_evidence(investigation_id: str, ev: Evidence) -> None:
    with _connect(investigation_db_path(investigation_id)) as conn:
        conn.execute(
            "INSERT INTO evidence (id, subcase_id, path, type, size_bytes, sha256, registered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                ev.id,
                ev.subcase_id,
                ev.path,
                ev.type,
                ev.size_bytes,
                ev.sha256,
                ev.registered_at.isoformat(),
            ),
        )


def get_evidence(investigation_id: str, evidence_id: str) -> Evidence | None:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return None
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id, subcase_id, path, type, size_bytes, sha256, registered_at "
            "FROM evidence WHERE id = ?",
            (evidence_id,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_evidence(row)


def list_evidence(investigation_id: str, subcase_id: str) -> list[Evidence]:
    db = investigation_db_path(investigation_id)
    if not db.exists():
        return []
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT id, subcase_id, path, type, size_bytes, sha256, registered_at "
            "FROM evidence WHERE subcase_id = ? ORDER BY registered_at",
            (subcase_id,),
        ).fetchall()
    return [_row_to_evidence(r) for r in rows]


def _row_to_evidence(row: sqlite3.Row) -> Evidence:
    return Evidence(
        id=row["id"],
        subcase_id=row["subcase_id"],
        path=row["path"],
        type=row["type"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        registered_at=datetime.fromisoformat(row["registered_at"]),
    )
