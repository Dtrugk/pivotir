"""Integration tests for the L1+L2 lifecycle tools.

End-to-end: open_investigation → add_subcase → add_evidence → list_evidence,
exercising the SQLite store + workspace + path resolution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pivotir.tools import catalog, investigation, subcase


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PIVOTIR_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


@pytest.fixture
def synthetic_evtx(tmp_path: Path) -> Path:
    """A tiny file with the EVTX magic prefix so type detection works."""
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
    return p


# ── End-to-end flow ──────────────────────────────────────────────────────────


def test_full_lifecycle_single_host(isolated_workspace: Path, synthetic_evtx: Path) -> None:
    # 1. Open investigation
    inv = investigation.open_investigation("Found NTDS.dit dump on DC-A")
    assert "id" in inv
    assert inv["status"] == "open"
    inv_id = inv["id"]

    # 2. Add a subcase for DC-A
    sub = subcase.add_subcase(inv_id, "DC-A", str(synthetic_evtx.parent), role="known_affected")
    assert sub["id"] == "SUB-dc-a"
    assert sub["status"] == "open"
    sub_id = sub["id"]

    # 3. Register evidence
    ev = catalog.add_evidence(inv_id, sub_id, str(synthetic_evtx))
    assert ev["type"] == "evtx"
    assert ev["size_bytes"] > 0
    assert ev["sha256"] is not None  # small file → eager hash

    # 4. List back
    evs = catalog.list_evidence(inv_id, sub_id)
    assert isinstance(evs, list)
    assert len(evs) == 1
    assert evs[0]["path"] == str(synthetic_evtx)


def test_open_investigation_creates_workspace_dirs(isolated_workspace: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    assert (isolated_workspace / "workspaces" / inv_id).is_dir()
    assert (isolated_workspace / "workspaces" / inv_id / "subcases").is_dir()
    assert (isolated_workspace / "workspaces" / inv_id / "reports").is_dir()


def test_list_investigations_finds_multiple(isolated_workspace: Path) -> None:
    investigation.open_investigation("a")
    investigation.open_investigation("b")
    listed = investigation.list_investigations()
    assert len(listed) == 2


def test_get_investigation_not_found_returns_error(isolated_workspace: Path) -> None:
    out = investigation.get_investigation("INV-nope")
    assert out.get("error") == "investigation_not_found"


# ── Subcase guards ───────────────────────────────────────────────────────────


def test_add_subcase_rejects_unknown_investigation(isolated_workspace: Path) -> None:
    out = subcase.add_subcase("INV-nope", "DC-A", "/x")
    assert out.get("error") == "investigation_not_found"


def test_add_subcase_rejects_duplicate_host(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    out = subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    assert out.get("error") == "host_already_exists"


def test_add_subcase_rejects_invalid_role(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    out = subcase.add_subcase(inv_id, "DC-A", str(tmp_path), role="bogus")
    assert out.get("error") == "invalid_role"


def test_list_subcases_returns_added(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    subcase.add_subcase(inv_id, "WS-1", str(tmp_path))
    listed = subcase.list_subcases(inv_id)
    assert isinstance(listed, list)
    assert {s["host_name"] for s in listed} == {"DC-A", "WS-1"}


# ── Evidence guards ──────────────────────────────────────────────────────────


def test_add_evidence_rejects_missing_subcase(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    p = tmp_path / "x.evtx"
    p.write_bytes(b"ElfFile\x00")
    out = catalog.add_evidence(inv_id, "SUB-nope", str(p))
    assert out.get("error") == "subcase_not_found"


def test_add_evidence_rejects_missing_path(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    out = catalog.add_evidence(inv_id, "SUB-dc-a", str(tmp_path / "missing.evtx"))
    assert out.get("error") == "path_not_found"


def test_add_evidence_uses_extension_to_detect_registry_hive(
    isolated_workspace: Path, tmp_path: Path
) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    p = tmp_path / "amcache.hve"
    p.write_bytes(b"regf" + b"\x00" * 256)
    ev = catalog.add_evidence(inv_id, "SUB-dc-a", str(p))
    assert ev["type"] == "registry_hive"


def test_add_evidence_directory_no_sha256(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    evidence_dir = tmp_path / "Prefetch"
    evidence_dir.mkdir()
    (evidence_dir / "FOO.pf").write_bytes(b"pftest")
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    ev = catalog.add_evidence(inv_id, "SUB-dc-a", str(evidence_dir))
    assert ev["type"] == "directory"
    assert ev["sha256"] is None
    assert ev["size_bytes"] > 0


def test_add_evidence_respects_type_hint(isolated_workspace: Path, tmp_path: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(tmp_path))
    p = tmp_path / "weird.dat"
    p.write_bytes(b"\x00" * 64)
    ev = catalog.add_evidence(inv_id, "SUB-dc-a", str(p), type_hint="custom_format")
    assert ev["type"] == "custom_format"


def test_inspect_artifact_reports_existence(isolated_workspace: Path, synthetic_evtx: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    subcase.add_subcase(inv_id, "DC-A", str(synthetic_evtx.parent))
    ev = catalog.add_evidence(inv_id, "SUB-dc-a", str(synthetic_evtx))
    inspected = catalog.inspect_artifact(inv_id, ev["id"])
    assert inspected.get("exists_on_disk") is True
    assert inspected.get("readable") is True


def test_inspect_artifact_handles_unknown_evidence(isolated_workspace: Path) -> None:
    inv = investigation.open_investigation("test")
    inv_id = inv["id"]
    out = catalog.inspect_artifact(inv_id, "E-nope")
    assert out.get("error") == "evidence_not_found"
