"""Phase 7 gate (SPEC 7): an incremental audit gives exactly the same result as a full one.

Each scenario: full audit → change the drive → incremental audit, compared with a brand-new
full audit of the same drive (separate store). fake_drive reports only the item that changed
(not the files below a re-shared folder), the worst case for the incremental path.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from dpg.core.audit.model import FileAudit
from dpg.core.audit.runner import AuditRunner, AuditScope
from dpg.core.drive.client import DriveClient
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import ColumnCipher
from tests.fakes.fake_drive import FakeDrive

ME = "teacher@school.example"


def _store(path: Path) -> AuditStore:
    return AuditStore(path, ColumnCipher(os.urandom(32)))


def _world() -> tuple[FakeDrive, dict[str, str]]:
    f = FakeDrive(me=ME)
    ids = {"top": f.add_folder("업무")}
    ids["sub"] = f.add_folder("하위", ids["top"])
    ids["a"] = f.add_file("a.txt", ids["sub"], content=b"a")
    ids["b"] = f.add_file("b.txt", ids["top"], content=b"b")
    ids["c"] = f.add_file("c.txt", content=b"c")
    f.share(ids["c"], "anyone", "reader")
    ids["other"] = f.add_folder("다른 폴더")
    ids["sd"] = f.add_shared_drive("학년", {ME: "organizer", "t2@school.example": "writer"})
    ids["sdf"] = f.add_folder("공유 폴더", ids["sd"])
    ids["sdfile"] = f.add_file("sd.txt", ids["sdf"], content=b"s")
    return f, ids


def _by_id(items: list[FileAudit]) -> dict[str, FileAudit]:
    return {a.file_id: a for a in items}


def _new_file(f: FakeDrive, ids: dict[str, str]) -> None:
    f.add_file("새 파일.txt", ids["sub"], content=b"n")


def _share_link(f: FakeDrive, ids: dict[str, str]) -> None:
    f.share(ids["b"], "anyone", "writer")


def _unshare(f: FakeDrive, ids: dict[str, str]) -> None:
    f.items[ids["c"]].permissions = []
    f.touch(ids["c"])


def _share_folder(f: FakeDrive, ids: dict[str, str]) -> None:
    # only the folder is reported; its children inherit the new external share
    f.share(ids["top"], "user", "reader", email="parent@gmail.example")


def _trash_folder(f: FakeDrive, ids: dict[str, str]) -> None:
    f.items[ids["sub"]].trashed = True
    f.items[ids["a"]].trashed = True
    f.touch(ids["sub"])  # children are not reported


def _move_into_shared(f: FakeDrive, ids: dict[str, str]) -> None:
    f.share(ids["other"], "anyone", "reader")
    f.items[ids["c"]].parent = ids["other"]
    f.touch(ids["c"])


def _move_folder(f: FakeDrive, ids: dict[str, str]) -> None:
    f.share(ids["other"], "domain", "reader", domain="school.example")
    f.items[ids["sub"]].parent = ids["other"]
    f.touch(ids["sub"])  # its file 'a' is not reported


def _rename_and_edit(f: FakeDrive, ids: dict[str, str]) -> None:
    f.items[ids["a"]].name = "a-renamed.txt"
    f.items[ids["a"]].content = b"changed"
    f.items[ids["a"]].modified_time = f._tick()
    f.touch(ids["a"])


def _shared_drive_change(f: FakeDrive, ids: dict[str, str]) -> None:
    f.share(ids["sdfile"], "user", "writer", email="parent@gmail.example")
    f.drives[ids["sd"]].members["t3@school.example"] = "reader"  # membership: not a file change


def _nothing(f: FakeDrive, ids: dict[str, str]) -> None:
    pass


SCENARIOS: dict[str, Callable[[FakeDrive, dict[str, str]], None]] = {
    "new_file": _new_file,
    "share_link": _share_link,
    "unshare": _unshare,
    "share_folder_inherited": _share_folder,
    "trash_folder": _trash_folder,
    "move_into_shared_folder": _move_into_shared,
    "move_folder": _move_folder,
    "rename_and_edit": _rename_and_edit,
    "shared_drive": _shared_drive_change,
    "nothing": _nothing,
}


@pytest.mark.parametrize("scope_text", ["mine", "drive:SD", "folder:TOP"])
@pytest.mark.parametrize("name", list(SCENARIOS))
def test_incremental_equals_full(tmp_path: Path, name: str, scope_text: str) -> None:
    fake, ids = _world()
    scope = AuditScope.parse(scope_text.replace("SD", ids["sd"]).replace("TOP", ids["top"]))
    client = DriveClient(fake.service())
    store = _store(tmp_path / "inc.db")
    first = AuditRunner(client, store, account=ME).run(scope)
    SCENARIOS[name](fake, ids)
    inc = AuditRunner(client, store, account=ME).run_incremental(scope)
    assert inc is not None
    assert inc.incremental
    full = AuditRunner(client, _store(tmp_path / "full.db"), account=ME).run(scope)
    assert _by_id(inc.items) == _by_id(full.items), name
    if name == "nothing":
        assert inc.changed == set()
    assert first.scan_id != inc.scan_id
    assert fake.write_calls == []


def test_second_incremental_continues_from_the_first(tmp_path: Path) -> None:
    fake, ids = _world()
    client = DriveClient(fake.service())
    store = _store(tmp_path / "a.db")
    scope = AuditScope.parse("mine")
    AuditRunner(client, store, account=ME).run(scope)
    _new_file(fake, ids)
    one = AuditRunner(client, store, account=ME).run_incremental(scope)
    _share_link(fake, ids)
    two = AuditRunner(client, store, account=ME).run_incremental(scope)
    assert one is not None
    assert two is not None
    assert two.changed == {ids["b"]}
    full = AuditRunner(client, _store(tmp_path / "b.db"), account=ME).run(scope)
    assert _by_id(two.items) == _by_id(full.items)


def test_expired_token_or_no_history_means_full_audit(tmp_path: Path) -> None:
    fake, _ids = _world()
    client = DriveClient(fake.service())
    store = _store(tmp_path / "a.db")
    scope = AuditScope.parse("mine")
    assert AuditRunner(client, store, account=ME).run_incremental(scope) is None  # no history
    AuditRunner(client, store, account=ME).run(scope)
    fake.expire_change_tokens()
    assert AuditRunner(client, store, account=ME).run_incremental(scope) is None
    assert (
        AuditRunner(client, store, account=ME).run_incremental(AuditScope.parse("shared")) is None
    )


def test_detections_survive_for_unchanged_files(tmp_path: Path) -> None:
    from dpg.core.detect.runner import DetectRunner

    fake, ids = _world()
    client = DriveClient(fake.service())
    store = _store(tmp_path / "a.db")
    scope = AuditScope.parse("mine")
    first = AuditRunner(client, store, account=ME).run(scope)
    DetectRunner(client, store).run(first.scan_id, first.items)
    _rename_and_edit(fake, ids)
    inc = AuditRunner(client, store, account=ME).run_incremental(scope)
    assert inc is not None
    assert inc.content_changed == {ids["a"]}
    kept = store.load_detections(inc.scan_id)
    assert ids["a"] not in kept  # must be re-read
    assert ids["b"] in kept  # unchanged: not downloaded again
    gets = fake.call_count("files.get_media")
    DetectRunner(client, store).run(inc.scan_id, inc.items)
    assert fake.call_count("files.get_media") == gets + 1
