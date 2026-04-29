"""L1a — investigation-level MCP tool implementations.

These functions form the LFA's surface. They are used by the main Claude Code
session (acting as the LFA) to open and inspect investigations.

Implementations live here; the @mcp.tool() registration happens in server.py.

Tools provided:
- open_investigation(brief)       → Investigation as dict
- list_investigations()           → list[Investigation as dict]
- get_investigation(id)           → Investigation as dict | error dict
"""

from __future__ import annotations

from typing import Any

from pivotir.state import store
from pivotir.state.ids import new_investigation_id
from pivotir.state.models import Investigation
from pivotir.workspace.layout import init_investigation_dirs


def open_investigation(brief: str) -> dict[str, Any]:
    """Create a new investigation.

    Args:
        brief: Free-text incident description.

    Side effects:
    - Creates <workspace>/workspaces/<investigation_id>/ with subcases/ and reports/.
    - Initialises the investigation SQLite DB.
    - The ledger.jsonl is created lazily on first receipt write.

    Returns the new Investigation record (as a dict).
    """
    inv = Investigation(id=new_investigation_id(), brief=brief)
    init_investigation_dirs(inv.id)
    store.insert_investigation(inv)
    return inv.model_dump(mode="json")


def list_investigations() -> list[dict[str, Any]]:
    """List every investigation discoverable on disk, oldest-first."""
    return [inv.model_dump(mode="json") for inv in store.list_investigations()]


def get_investigation(investigation_id: str) -> dict[str, Any]:
    """Fetch one investigation by id. Returns a dict with `error` if not found."""
    inv = store.get_investigation(investigation_id)
    if inv is None:
        return {"error": "investigation_not_found", "investigation_id": investigation_id}
    return inv.model_dump(mode="json")
