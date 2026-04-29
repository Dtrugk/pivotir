"""Pydantic models for PivotIR state.

These are the *typed* schemas the agent reasons over via MCP tools. They map
1:1 to SQLite tables in state/store.py and are what tool responses serialize.

Hypothesis / Finding / Task models are introduced in later commits when the
playbook engine and orchestrator land.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class InvestigationStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class HostRole(StrEnum):
    KNOWN_AFFECTED = "known_affected"
    KNOWN_CLEAN = "known_clean"
    TRIAGE = "triage"


class SubcaseStatus(StrEnum):
    OPEN = "open"
    CONCLUDED = "concluded"


class Investigation(BaseModel):
    """Top-level case spanning one or more hosts."""

    model_config = ConfigDict(use_enum_values=False)

    id: str
    brief: str
    anchor: dict[str, Any] | None = None
    status: InvestigationStatus = InvestigationStatus.OPEN
    opened_at: datetime = Field(default_factory=_utc_now)
    closed_at: datetime | None = None


class Host(BaseModel):
    """A logical host within an investigation. Identified by name."""

    investigation_id: str
    name: str
    evidence_path: str  # absolute path on disk where the host's artifacts live
    role: HostRole = HostRole.TRIAGE


class Subcase(BaseModel):
    """A per-host investigation slice. Each FA owns one subcase."""

    id: str
    investigation_id: str
    host_name: str
    evidence_path: str
    status: SubcaseStatus = SubcaseStatus.OPEN
    opened_at: datetime = Field(default_factory=_utc_now)
    concluded_at: datetime | None = None


class Evidence(BaseModel):
    """A registered artifact within a subcase.

    The path is an absolute reference. PivotIR never copies or modifies
    evidence — chain-of-custody is preserved. We record metadata only:
    type guess, size, and (for files under the eager-hash limit) sha256.
    """

    id: str
    subcase_id: str
    path: str
    type: str  # "evtx", "memory_dump", "csv", "directory", "registry_hive", "unknown", ...
    size_bytes: int
    sha256: str | None = None
    registered_at: datetime = Field(default_factory=_utc_now)
