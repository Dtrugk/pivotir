"""L1b — subcase-level MCP tool implementations.

A subcase is one FA's per-host investigation slice. It carries its own
hypotheses, findings, evidence registry, and (in later commits) its own
playbook progress.

Implementations live here; the @mcp.tool() registration happens in server.py.

Tools provided:
- add_subcase(investigation_id, host_name, evidence_path, role)  → Subcase as dict | error
- list_subcases(investigation_id)                                 → list[Subcase as dict] | error
- get_subcase(investigation_id, subcase_id)                       → Subcase as dict | error
"""

from __future__ import annotations

from typing import Any

from pivotir.state import store
from pivotir.state.ids import subcase_id_for_host
from pivotir.state.models import Host, HostRole, Subcase
from pivotir.workspace.layout import init_subcase_dirs


def add_subcase(
    investigation_id: str,
    host_name: str,
    evidence_path: str,
    role: str = "triage",
) -> dict[str, Any]:
    """Add a host to the investigation and create its subcase.

    Args:
        investigation_id: From open_investigation.
        host_name: Logical name (e.g. "DC-A", "WS-1"). Slugified into the subcase id.
        evidence_path: Absolute path on disk where this host's artifacts live.
        role: 'known_affected', 'known_clean', or 'triage' (default).

    Returns the new Subcase record. Returns `error` dict if:
    - investigation not found
    - role is invalid
    - host already exists in this investigation
    """
    inv = store.get_investigation(investigation_id)
    if inv is None:
        return {"error": "investigation_not_found", "investigation_id": investigation_id}

    try:
        host_role = HostRole(role)
    except ValueError:
        return {
            "error": "invalid_role",
            "role": role,
            "valid_roles": [r.value for r in HostRole],
        }

    # check for duplicate host
    existing = store.list_hosts(investigation_id)
    if any(h.name == host_name for h in existing):
        return {
            "error": "host_already_exists",
            "investigation_id": investigation_id,
            "host_name": host_name,
        }

    sub_id = subcase_id_for_host(host_name)

    host = Host(
        investigation_id=investigation_id,
        name=host_name,
        evidence_path=evidence_path,
        role=host_role,
    )
    subcase = Subcase(
        id=sub_id,
        investigation_id=investigation_id,
        host_name=host_name,
        evidence_path=evidence_path,
    )

    init_subcase_dirs(investigation_id, sub_id)
    store.insert_host(host)
    store.insert_subcase(subcase)

    return subcase.model_dump(mode="json")


def list_subcases(investigation_id: str) -> list[dict[str, Any]] | dict[str, Any]:
    """List all subcases in this investigation."""
    inv = store.get_investigation(investigation_id)
    if inv is None:
        return {"error": "investigation_not_found", "investigation_id": investigation_id}
    return [s.model_dump(mode="json") for s in store.list_subcases(investigation_id)]


def get_subcase(investigation_id: str, subcase_id: str) -> dict[str, Any]:
    """Fetch a single subcase."""
    sub = store.get_subcase(investigation_id, subcase_id)
    if sub is None:
        return {"error": "subcase_not_found", "subcase_id": subcase_id}
    return sub.model_dump(mode="json")
