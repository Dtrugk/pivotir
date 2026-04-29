"""PivotIR MCP server entry point.

Starts a FastMCP server that exposes the PivotIR tool surface (L1a / L1b / L2 / L3).
Today: just `ping()`. Subsequent commits register the lifecycle, runner, reader,
playbook, and pivot tools.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from pivotir import __version__

mcp = FastMCP("pivotir")


@mcp.tool()
def ping() -> str:
    """Verify the PivotIR MCP server is reachable.

    Returns a small string identifying the server and version, so a calling
    agent can confirm wire-up before issuing real investigation tools.
    """
    return f"pong from pivotir {__version__}"


def main() -> None:
    """Entry point for the `pivotir` console script.

    Runs the MCP server over stdio, which is what Claude Code and most MCP
    clients expect for locally-installed servers.
    """
    mcp.run()


if __name__ == "__main__":
    main()
