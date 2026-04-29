# PivotIR

Autonomous DFIR investigation: a Custom MCP Server + multi-agent orchestrator for the SANS [FIND EVIL!](https://findevil.devpost.com/) hackathon.

PivotIR turns any MCP-capable agent runtime (Claude Code first) into an autonomous, multi-host DFIR investigator. A **Lead Forensic Agent** decomposes incidents across hosts, dispatches per-host **Forensic Agents** in parallel, and stitches their findings into a cross-host attack chain — every claim grounded in tool-output receipts.

## Status

Week 1 of 7 (deadline: 2026-06-15). The full plan and architecture are in [`docs/`](docs/).

## Quick start

Requires Python 3.11+. With [uv](https://docs.astral.sh/uv/):

```bash
uv sync
uv run pivotir
```

Or with stdlib venv + pip:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -e ".[dev]"
pivotir
```

The server currently exposes one tool: `ping()`. More to come — see milestones in the plan.

## How it works (one-paragraph version)

The user provides an incident brief and a directory of evidence. The Lead Forensic Agent identifies the starting point, builds a severity-prioritized TODO list of per-host tasks, and dispatches Forensic Agents in parallel. Each FA, given a host and a candidate anomaly, looks up the anomaly in `kb/anomalies/`, walks every candidate hypothesis through its YAML playbook, and runs DFIR analyzers (EZTools / python-evtx / Volatility / YARA) against the evidence — each producing a CSV/JSON output file the agent then queries via DuckDB. A step is only marked dead-end after every listed source has been tried, with the receipt ledger as proof. The LFA aggregates round results, runs cross-host correlation, and replans until no new leads remain. The final report cites a receipt for every claim.

## License

MIT
