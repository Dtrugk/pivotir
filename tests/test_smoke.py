"""Smoke tests: package imports cleanly and the ping tool returns the expected payload."""

from __future__ import annotations

import pivotir
from pivotir import server


def test_version_exposed() -> None:
    assert pivotir.__version__ == "0.0.1"


def test_ping_returns_pong_with_version() -> None:
    assert server.ping() == f"pong from pivotir {pivotir.__version__}"
