"""PivotIR MCP server entry point.

Starts a FastMCP server that exposes the PivotIR tool surface (L1a / L1b / L2 / L3).

Currently registered:
- ping
- L1a — open_investigation, list_investigations, get_investigation
- L1b — add_subcase, list_subcases, get_subcase
- L2  — add_evidence, list_evidence, inspect_artifact

Subsequent commits will add:
- L2  — run_evtxecmd / run_python_evtx, run_pecmd, run_amcacheparser, ...
- L2  — describe_output, read_output_filter, read_output_count, cross_query, ...
- L3  — playbook + anomaly tools, pivot helpers, evasion detection
- L1a — task lifecycle, dispatch, verify_subcase_findings, lead_finalize
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from pivotir import __version__
from pivotir.tools import catalog, investigation, subcase

mcp = FastMCP("pivotir")


@mcp.tool()
def ping() -> str:
    """Verify the PivotIR MCP server is reachable. Returns server name + version."""
    return f"pong from pivotir {__version__}"


# ── L1a — Investigation ──────────────────────────────────────────────────────


@mcp.tool()
def open_investigation(brief: str) -> dict:
    """Create a new investigation from an incident brief.

    The brief is free-text — anything from a one-line alarm description to a
    multi-paragraph IR ticket. Returns the Investigation record including its
    new id, which all downstream tools require.

    Example brief: "User on WS-1 reported credential prompt phishing on
    2026-04-29 14:23 UTC. SMB activity from WS-1 to DC-A noticed by helpdesk.
    NTDS.dit appeared on attacker-controlled share. Evidence: /cases/case42/."

    Side effects:
    - Creates <workspace>/workspaces/<investigation_id>/ with subcases/ and reports/.
    - Initialises the investigation SQLite DB.
    """
    return investigation.open_investigation(brief)


@mcp.tool()
def list_investigations() -> list[dict]:
    """List every investigation in the workspace, oldest-first."""
    return investigation.list_investigations()


@mcp.tool()
def get_investigation(investigation_id: str) -> dict:
    """Fetch one investigation's record by id."""
    return investigation.get_investigation(investigation_id)


# ── L1b — Subcase ────────────────────────────────────────────────────────────


@mcp.tool()
def add_subcase(
    investigation_id: str,
    host_name: str,
    evidence_path: str,
    role: str = "triage",
) -> dict:
    """Add a host to the investigation and create its subcase.

    Each host gets exactly one subcase. The subcase is the FA's working scope:
    its own findings, hypotheses, evidence registry, and outputs directory.

    Args:
        investigation_id: From open_investigation.
        host_name: Logical name (e.g. "DC-A", "WS-1"). Slugified into the subcase id.
        evidence_path: Absolute path on disk where this host's artifacts live.
        role: 'known_affected', 'known_clean', or 'triage' (default).
    """
    return subcase.add_subcase(investigation_id, host_name, evidence_path, role)


@mcp.tool()
def list_subcases(investigation_id: str) -> list[dict] | dict:
    """List every subcase in an investigation."""
    return subcase.list_subcases(investigation_id)


@mcp.tool()
def get_subcase(investigation_id: str, subcase_id: str) -> dict:
    """Fetch one subcase's record by id."""
    return subcase.get_subcase(investigation_id, subcase_id)


# ── L2 — Evidence catalog ────────────────────────────────────────────────────


@mcp.tool()
def add_evidence(
    investigation_id: str,
    subcase_id: str,
    path: str,
    type_hint: str | None = None,
) -> dict:
    """Register an artifact (file or directory) in a subcase.

    The artifact stays at its original path — PivotIR never copies or mutates
    evidence. Only metadata is recorded (type, size, sha256-if-small).

    Args:
        investigation_id: scope.
        subcase_id: scope.
        path: absolute path to the artifact.
        type_hint: optional override (e.g. "evtx", "registry_hive"); defaults
            to extension + magic-byte sniff.
    """
    return catalog.add_evidence(investigation_id, subcase_id, path, type_hint)


@mcp.tool()
def list_evidence(investigation_id: str, subcase_id: str) -> list[dict] | dict:
    """List every artifact registered to a subcase."""
    return catalog.list_evidence(investigation_id, subcase_id)


@mcp.tool()
def inspect_artifact(investigation_id: str, evidence_id: str) -> dict:
    """Return registered metadata for an artifact + cheap on-disk checks
    (exists_on_disk, readable)."""
    return catalog.inspect_artifact(investigation_id, evidence_id)


def main() -> None:
    """Entry point for the `pivotir` console script. Runs over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
