"""L2 — evidence catalog tool implementations.

Register and inspect evidence artifacts. Evidence is referenced by absolute
path; PivotIR never copies or modifies the source files (chain of custody).
We record metadata: type guess (extension + magic bytes), size, optional sha256.

Implementations live here; the @mcp.tool() registration happens in server.py.

Tools provided:
- add_evidence(investigation_id, subcase_id, path, type_hint?)  → Evidence as dict | error
- list_evidence(investigation_id, subcase_id)                    → list[Evidence as dict] | error
- inspect_artifact(investigation_id, evidence_id)                → Evidence as dict + extras | error
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pivotir.state import store
from pivotir.state.ids import new_evidence_id
from pivotir.state.models import Evidence

# threshold above which we don't compute sha256 eagerly (defer to runners)
_SHA256_EAGER_LIMIT_BYTES = 256 * 1024 * 1024  # 256 MiB


# Magic bytes for common DFIR artifact types
_MAGIC_TABLE: list[tuple[bytes, str]] = [
    (b"ElfFile\x00", "evtx"),  # Windows EVTX
    (b"regf", "registry_hive"),
    (b"FILE", "mft"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),  # libpcap LE
    (b"\xa1\xb2\xc3\xd4", "pcap"),  # libpcap BE
    (b"\n\r\r\n", "pcapng"),
    (b"EVF\x09", "ewf_image"),  # Expert Witness Format (.E01)
]


_EXTENSION_TYPE_MAP: dict[str, str] = {
    "evtx": "evtx",
    "csv": "csv",
    "json": "json",
    "jsonl": "jsonl",
    "log": "log",
    "txt": "text",
    "raw": "memory_dump",
    "mem": "memory_dump",
    "dmp": "memory_dump",
    "vmem": "memory_dump",
    "dat": "registry_hive",  # NTUSER.DAT, UsrClass.dat
    "hve": "registry_hive",  # Amcache.hve
    "pcap": "pcap",
    "pcapng": "pcapng",
    "e01": "ewf_image",
}


def _guess_type_from_path(path: Path) -> str:
    """Best-effort artifact type from extension + first 16 bytes."""
    if path.is_dir():
        return "directory"

    suffix = path.suffix.lower().lstrip(".")
    if suffix in _EXTENSION_TYPE_MAP:
        return _EXTENSION_TYPE_MAP[suffix]

    # magic bytes
    try:
        with path.open("rb") as f:
            head = f.read(16)
        for magic, ftype in _MAGIC_TABLE:
            if head.startswith(magic):
                return ftype
    except OSError:
        pass

    # specials by name
    name = path.name
    if name == "$MFT":
        return "mft"
    if name == "$J":
        return "usnjrnl"
    return "unknown"


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _directory_size_bytes(path: Path) -> int:
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                continue
    return total


def add_evidence(
    investigation_id: str,
    subcase_id: str,
    path: str,
    type_hint: str | None = None,
) -> dict[str, Any]:
    """Register an artifact in this subcase.

    The artifact stays at its original path — we never copy or mutate evidence.
    We record metadata: type, size, and (for files under ~256 MiB) sha256.
    Larger files have sha256 computed lazily by the first runner that needs it.

    Args:
        investigation_id: scope.
        subcase_id: scope.
        path: absolute path to the artifact (file or directory).
        type_hint: optional override for type detection (e.g. "evtx").

    Returns the new Evidence record. Returns `error` dict if:
    - subcase not found
    - path does not exist
    """
    sub = store.get_subcase(investigation_id, subcase_id)
    if sub is None:
        return {"error": "subcase_not_found", "subcase_id": subcase_id}

    p = Path(path).expanduser()
    if not p.is_absolute():
        p = p.resolve()
    if not p.exists():
        return {"error": "path_not_found", "path": str(p)}

    type_ = type_hint if type_hint else _guess_type_from_path(p)

    if p.is_dir():
        size_bytes = _directory_size_bytes(p)
        sha256: str | None = None  # don't hash directories
    else:
        size_bytes = p.stat().st_size
        sha256 = _sha256_of_file(p) if size_bytes <= _SHA256_EAGER_LIMIT_BYTES else None

    ev = Evidence(
        id=new_evidence_id(),
        subcase_id=subcase_id,
        path=str(p),
        type=type_,
        size_bytes=size_bytes,
        sha256=sha256,
    )
    store.insert_evidence(investigation_id, ev)
    return ev.model_dump(mode="json")


def list_evidence(investigation_id: str, subcase_id: str) -> list[dict[str, Any]] | dict[str, Any]:
    """List all evidence registered to a subcase, oldest-first."""
    sub = store.get_subcase(investigation_id, subcase_id)
    if sub is None:
        return {"error": "subcase_not_found", "subcase_id": subcase_id}
    return [e.model_dump(mode="json") for e in store.list_evidence(investigation_id, subcase_id)]


def inspect_artifact(investigation_id: str, evidence_id: str) -> dict[str, Any]:
    """Return registered metadata + a few cheap on-disk inspections.

    Adds: exists_on_disk (bool), readable (bool).
    """
    ev = store.get_evidence(investigation_id, evidence_id)
    if ev is None:
        return {"error": "evidence_not_found", "evidence_id": evidence_id}

    p = Path(ev.path)
    exists = p.exists()
    if not exists:
        readable = False
    elif p.is_dir():
        readable = True
    else:
        try:
            readable = p.stat().st_size > 0
        except OSError:
            readable = False

    out = ev.model_dump(mode="json")
    out["exists_on_disk"] = exists
    out["readable"] = readable
    return out
