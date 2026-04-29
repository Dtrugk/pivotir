"""Tests for state models, IDs, and SQLite store."""

from __future__ import annotations

from pathlib import Path

import pytest

from pivotir.state import store
from pivotir.state.ids import new_evidence_id, new_investigation_id, subcase_id_for_host
from pivotir.state.models import Evidence, Host, HostRole, Investigation, Subcase
from pivotir.workspace.layout import init_investigation_dirs, init_subcase_dirs


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PIVOTIR_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


# ── IDs ──────────────────────────────────────────────────────────────────────


def test_subcase_id_slugifies_host_name() -> None:
    assert subcase_id_for_host("DC-A") == "SUB-dc-a"
    assert subcase_id_for_host("WS_1") == "SUB-ws-1"
    assert subcase_id_for_host("server.example.com") == "SUB-server-example-com"


def test_subcase_id_collapses_repeated_hyphens() -> None:
    assert subcase_id_for_host("dc - a") == "SUB-dc-a"


def test_subcase_id_rejects_empty_slug() -> None:
    with pytest.raises(ValueError):
        subcase_id_for_host("!!!")


def test_investigation_ids_are_unique() -> None:
    a = new_investigation_id()
    b = new_investigation_id()
    assert a != b
    assert a.startswith("INV-")
    assert b.startswith("INV-")


# ── Investigation ────────────────────────────────────────────────────────────


def test_insert_and_get_investigation(isolated_workspace: Path) -> None:
    inv_id = new_investigation_id()
    init_investigation_dirs(inv_id)
    inv = Investigation(id=inv_id, brief="test brief")
    store.insert_investigation(inv)

    fetched = store.get_investigation(inv_id)
    assert fetched is not None
    assert fetched.id == inv_id
    assert fetched.brief == "test brief"
    assert fetched.status.value == "open"


def test_get_investigation_returns_none_when_missing(isolated_workspace: Path) -> None:
    assert store.get_investigation("INV-nope") is None


def test_list_investigations_returns_all_on_disk(isolated_workspace: Path) -> None:
    ids = []
    for i in range(3):
        # use deterministic ids so sort order is predictable
        inv_id = f"INV-aaa{i:013d}"
        ids.append(inv_id)
        init_investigation_dirs(inv_id)
        store.insert_investigation(Investigation(id=inv_id, brief=f"brief {i}"))

    fetched = store.list_investigations()
    assert len(fetched) == 3
    fetched_ids = [i.id for i in fetched]
    assert sorted(fetched_ids) == fetched_ids  # listed in sorted dir order


# ── Host + Subcase ───────────────────────────────────────────────────────────


def test_insert_host_and_subcase(isolated_workspace: Path) -> None:
    inv_id = new_investigation_id()
    init_investigation_dirs(inv_id)
    store.insert_investigation(Investigation(id=inv_id, brief="b"))

    host = Host(
        investigation_id=inv_id,
        name="DC-A",
        evidence_path="/cases/dc-a",
        role=HostRole.KNOWN_AFFECTED,
    )
    store.insert_host(host)

    sub_id = subcase_id_for_host("DC-A")
    init_subcase_dirs(inv_id, sub_id)
    sub = Subcase(id=sub_id, investigation_id=inv_id, host_name="DC-A", evidence_path="/cases/dc-a")
    store.insert_subcase(sub)

    assert [h.name for h in store.list_hosts(inv_id)] == ["DC-A"]
    assert [s.id for s in store.list_subcases(inv_id)] == [sub_id]
    fetched = store.get_subcase(inv_id, sub_id)
    assert fetched is not None
    assert fetched.host_name == "DC-A"


# ── Evidence ─────────────────────────────────────────────────────────────────


def test_insert_and_list_evidence(isolated_workspace: Path) -> None:
    inv_id = new_investigation_id()
    init_investigation_dirs(inv_id)
    store.insert_investigation(Investigation(id=inv_id, brief="b"))
    store.insert_host(Host(investigation_id=inv_id, name="DC-A", evidence_path="/x"))
    sub_id = subcase_id_for_host("DC-A")
    init_subcase_dirs(inv_id, sub_id)
    store.insert_subcase(
        Subcase(id=sub_id, investigation_id=inv_id, host_name="DC-A", evidence_path="/x")
    )

    ev = Evidence(
        id=new_evidence_id(),
        subcase_id=sub_id,
        path="/x/security.evtx",
        type="evtx",
        size_bytes=1024,
    )
    store.insert_evidence(inv_id, ev)

    listed = store.list_evidence(inv_id, sub_id)
    assert len(listed) == 1
    assert listed[0].path == "/x/security.evtx"
    assert listed[0].type == "evtx"

    fetched = store.get_evidence(inv_id, ev.id)
    assert fetched is not None
    assert fetched.id == ev.id


def test_get_evidence_returns_none_when_missing(isolated_workspace: Path) -> None:
    inv_id = new_investigation_id()
    init_investigation_dirs(inv_id)
    store.insert_investigation(Investigation(id=inv_id, brief="b"))
    assert store.get_evidence(inv_id, "E-nope") is None
