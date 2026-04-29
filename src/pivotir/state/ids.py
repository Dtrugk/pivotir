"""ID generation for PivotIR entities.

Every entity has a human-readable, time-sortable ID. Format:
    <PREFIX>-<12-hex-ms-timestamp><4-hex-random>

Time-sortable so that scanning a directory lists newest-first, helps ledger
inspection, and gives the agent a sense of chronology without needing the
SQLite mtime.

The 16-bit random suffix gives ~65k unique IDs per millisecond — enough for
any real DFIR workload (we generate at most ~10s/s of IDs, not 10^5).
"""

from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime


def _short_ts_id() -> str:
    """Time-sortable 16-char hex: 12 chars (48-bit ms ts) + 4 chars random."""
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand = secrets.token_hex(2)  # 4 hex chars
    return f"{ts_ms:012x}{rand}"


def new_investigation_id() -> str:
    """E.g. INV-018d4a7c92ea1f3b."""
    return f"INV-{_short_ts_id()}"


def new_evidence_id() -> str:
    """E.g. E-018d4a7c92ea1f3b."""
    return f"E-{_short_ts_id()}"


def new_receipt_id() -> str:
    """E.g. R-018d4a7c92ea1f3b."""
    return f"R-{_short_ts_id()}"


def new_audit_id(component: str) -> str:
    """Audit id for tool responses. Format: pivotir-<component>-YYYYMMDD-<6-hex>.

    Mirrors Valhuntir's audit_id shape; the 6-hex random suffix avoids collisions
    when many tool calls happen in the same day.
    """
    date_part = datetime.now(tz=UTC).strftime("%Y%m%d")
    rand = secrets.token_hex(3)
    return f"pivotir-{component}-{date_part}-{rand}"


def subcase_id_for_host(host_name: str) -> str:
    """Subcase ID is deterministic from host name (slugified).

    This means the agent can refer to a host by name and get a stable subcase id.
    Two hosts with the same name in the same investigation are not allowed
    (enforced at the SQLite layer via UNIQUE(investigation_id, host_name)).
    """
    slug_parts: list[str] = []
    for ch in host_name.lower().strip():
        if ch.isalnum() or ch == "-":
            slug_parts.append(ch)
        elif ch in (" ", "_", ".", "/", "\\"):
            slug_parts.append("-")
        # else drop
    slug = "".join(slug_parts).strip("-")
    # collapse repeated hyphens
    while "--" in slug:
        slug = slug.replace("--", "-")
    if not slug:
        raise ValueError(f"host_name produced empty slug: {host_name!r}")
    return f"SUB-{slug}"
