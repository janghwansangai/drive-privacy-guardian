"""Phase 2 gate (SPEC 7): audit scenarios against fake_drive — and zero write calls."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from dpg.core.audit import runner as runner_mod
from dpg.core.audit.model import Exposure, FileAudit, ItemStatus, Origin
from dpg.core.audit.runner import AuditCancelled, AuditRunner, AuditScope, Progress
from dpg.core.drive.client import DriveClient, DriveHttpError
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import ColumnCipher
from tests.fakes.fake_drive import FakeDrive

ME = "teacher@school.example"


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    s = AuditStore(tmp_path / "audit.db", ColumnCipher(os.urandom(32)))
    yield s  # type: ignore[misc]
    s.close()


def run(fake: FakeDrive, store: AuditStore, scope: str, **kw: object) -> dict[str, FileAudit]:
    runner = AuditRunner(DriveClient(fake.service(), sleep=lambda s: None), store, account=ME, **kw)  # type: ignore[arg-type]
    result = runner.run(AuditScope.parse(scope))
    assert fake.write_calls == [], "audit must never call a write API"
    return {a.file_id: a for a in result.items}


# --- My Drive -------------------------------------------------------------------------------


@pytest.fixture
def my_drive() -> tuple[FakeDrive, dict[str, str]]:
    f = FakeDrive(me=ME)
    ids: dict[str, str] = {}
    ids["private"] = f.add_file("private.txt")
    ids["link_view"] = f.add_file("공지.pdf")
    f.share(ids["link_view"], "anyone", "reader")
    ids["link_edit"] = f.add_file("편집공개.docx")
    f.share(ids["link_edit"], "anyone", "writer")
    ids["findable"] = f.add_file("검색공개.txt")
    f.share(ids["findable"], "anyone", "reader", allow_discovery=True)
    ids["external"] = f.add_file("외부.xlsx")
    f.share(ids["external"], "user", "writer", email="parent@gmail.example")
    ids["internal"] = f.add_file("내부.txt")
    f.share(ids["internal"], "user", "reader", email="colleague@school.example")
    ids["domain"] = f.add_file("도메인.txt")
    f.share(ids["domain"], "domain", "reader", domain="school.example")
    ids["folder"] = f.add_folder("공유폴더")
    f.share(ids["folder"], "user", "reader", email="guest@other.example")
    ids["child"] = f.add_file("child.txt", parent=ids["folder"])
    ids["child_direct"] = f.add_file("child2.txt", parent=ids["folder"])
    f.share(ids["child_direct"], "anyone", "reader")
    ids["limited"] = f.add_folder(
        "제한폴더", parent=ids["folder"], inherited_permissions_disabled=True
    )
    ids["in_limited"] = f.add_file("in_limited.txt", parent=ids["limited"])
    ids["copy_restricted"] = f.add_file("다운로드제한.pdf", copy_requires_writer_permission=True)
    f.share(ids["copy_restricted"], "user", "reader", email="ext@gmail.example")
    ids["trashed"] = f.add_file("휴지통.txt")
    f.items[ids["trashed"]].trashed = True
    return f, ids


def test_my_drive_exposure_classes(
    my_drive: tuple[FakeDrive, dict[str, str]], store: AuditStore
) -> None:
    fake, ids = my_drive
    got = run(fake, store, "mine")
    exp = {k: got[v].exposure for k, v in ids.items() if v in got}
    assert exp["private"] == Exposure.RESTRICTED
    assert exp["link_view"] == Exposure.LINK_VIEW
    assert exp["link_edit"] == Exposure.LINK_EDIT
    assert exp["findable"] == Exposure.LINK_VIEW
    assert got[ids["findable"]].link_discoverable
    assert exp["external"] == Exposure.EXTERNAL
    assert exp["internal"] == Exposure.RESTRICTED  # colleague in own domain
    assert got[ids["internal"]].internal_accounts == 1
    assert exp["domain"] == Exposure.DOMAIN
    assert exp["child"] == Exposure.EXTERNAL  # inherited from the shared folder
    assert exp["child_direct"] == Exposure.LINK_VIEW
    assert ids["trashed"] not in got
    assert all(a.status is ItemStatus.OK for a in got.values())

    # risk ordering (SPEC 6.1)
    score = {k: got[v].risk_score for k, v in ids.items() if v in got}
    assert (
        score["link_edit"]
        > score["link_view"]
        > score["external"]
        > score["domain"]
        > score["private"]
        == 0
    )
    assert score["findable"] > score["link_view"]
    assert got[ids["external"]].editor_count == 1
    assert got[ids["copy_restricted"]].download_restricted is True


def test_my_drive_inheritance_inference(
    my_drive: tuple[FakeDrive, dict[str, str]], store: AuditStore
) -> None:
    fake, ids = my_drive
    got = run(fake, store, "mine")
    child = got[ids["child"]]
    guest = next(p for p in child.permissions if p.email == "guest@other.example")
    assert guest.origin is Origin.INHERITED_LIKELY
    anyone = next(p for p in got[ids["child_direct"]].permissions if p.type == "anyone")
    assert anyone.origin is Origin.DIRECT
    folder_guest = next(
        p for p in got[ids["folder"]].permissions if p.email == "guest@other.example"
    )
    assert folder_guest.origin is Origin.DIRECT  # parent is My Drive root


def test_limited_access_folder(
    my_drive: tuple[FakeDrive, dict[str, str]], store: AuditStore
) -> None:
    fake, ids = my_drive
    got = run(fake, store, "mine")
    limited = got[ids["limited"]]
    assert limited.limited_access_folder
    assert limited.exposure == Exposure.RESTRICTED  # the guest can see the name only
    assert any("제한된 액세스" in n for n in limited.notes)
    assert got[ids["in_limited"]].exposure == Exposure.RESTRICTED


# --- shared with me / insufficient permissions ---------------------------------------------


def test_shared_with_me_insufficient_is_not_safe(store: AuditStore) -> None:
    fake = FakeDrive(me=ME)
    reader_only = fake.add_file("남의 파일", owner="other@school.example")
    fake.share(reader_only, "user", "reader", email=ME)
    public_unreadable = fake.add_file("남의 공개 파일", owner="other@school.example")
    fake.share(public_unreadable, "user", "reader", email=ME)
    fake.share(public_unreadable, "anyone", "reader")
    editable = fake.add_file("편집 가능", owner="other@school.example")
    fake.share(editable, "user", "writer", email=ME)
    fake.share(editable, "user", "reader", email="outsider@gmail.example")

    got = run(fake, store, "shared")
    assert got[reader_only].status is ItemStatus.INSUFFICIENT
    assert got[reader_only].exposure is None  # unknown, never "restricted"
    assert got[reader_only].risk_score is None
    assert got[public_unreadable].status is ItemStatus.INSUFFICIENT
    assert got[public_unreadable].exposure == Exposure.LINK_VIEW  # from the visibility query
    assert got[editable].status is ItemStatus.OK
    assert got[editable].exposure == Exposure.EXTERNAL


# --- shared drives --------------------------------------------------------------------------


def test_shared_drive_inheritance(store: AuditStore) -> None:
    fake = FakeDrive(me=ME)
    drive = fake.add_shared_drive(
        "교무부", members={ME: "organizer", "peer@school.example": "writer"}
    )
    top = fake.add_file("top.hwp", parent=drive)
    sub = fake.add_folder("공개폴더", parent=drive)
    fake.share(sub, "anyone", "reader")
    deep = fake.add_folder("deep", parent=sub)
    deep_file = fake.add_file("deep.xlsx", parent=deep)
    ext_file = fake.add_file("ext.docx", parent=drive)
    fake.share(ext_file, "user", "writer", email="partner@gmail.example")

    got = run(fake, store, f"drive:{drive}")
    assert got[top].exposure == Exposure.RESTRICTED
    assert got[sub].exposure == Exposure.LINK_VIEW
    assert got[deep_file].exposure == Exposure.LINK_VIEW  # derived through two levels
    anyone = next(p for p in got[deep_file].permissions if p.type == "anyone")
    assert (anyone.origin, anyone.inherited_from) == (Origin.INHERITED, sub)
    assert got[ext_file].exposure == Exposure.EXTERNAL
    assert {
        p.origin
        for p in got[ext_file].permissions
        if p.type == "user" and p.email == "partner@gmail.example"
    } == {Origin.DIRECT}
    # permissions.list only for items with direct permissions (+ the drive itself)
    listed = [kw["fileId"] for name, kw in fake.calls if name == "permissions.list"]
    assert sorted(listed) == sorted([drive, sub, ext_file])


def test_shared_drive_as_reader_member(store: AuditStore) -> None:
    fake = FakeDrive(me=ME)
    drive = fake.add_shared_drive(
        "타 부서", members={"boss@school.example": "organizer", ME: "reader"}
    )
    aug = fake.add_folder("aug", parent=drive)
    fake.share(aug, "user", "reader", email="x@gmail.example")
    under = fake.add_file("under", parent=aug)
    plain = fake.add_file("plain", parent=drive)
    got = run(fake, store, f"drive:{drive}")
    assert got[aug].status is ItemStatus.INSUFFICIENT
    assert got[under].status is ItemStatus.INSUFFICIENT
    assert got[plain].status is ItemStatus.OK


def test_folder_scope(my_drive: tuple[FakeDrive, dict[str, str]], store: AuditStore) -> None:
    fake, ids = my_drive
    got = run(fake, store, f"folder:{ids['folder']}")
    assert set(got) == {
        ids[k] for k in ("folder", "child", "child_direct", "limited", "in_limited")
    }


# --- robustness -----------------------------------------------------------------------------


def _big_drive(n_folders: int = 100, per_folder: int = 100) -> FakeDrive:
    fake = FakeDrive(me=ME)
    for i in range(n_folders):
        folder = fake.add_folder(f"반{i}")
        if i % 10 == 0:
            fake.share(folder, "user", "reader", email=f"guest{i}@gmail.example")
        for j in range(per_folder):
            fid = fake.add_file(f"f{i}-{j}.txt", parent=folder)
            if j == 0:
                fake.share(fid, "anyone", "reader")
    return fake


@pytest.mark.slow
def test_ten_thousand_files(store: AuditStore) -> None:
    fake = _big_drive()
    got = run(fake, store, "mine")
    assert len(got) == 100 * 100 + 100
    link = sum(1 for a in got.values() if a.exposure == Exposure.LINK_VIEW)
    ext = sum(1 for a in got.values() if a.exposure == Exposure.EXTERNAL)
    assert link == 100
    assert ext == 10 * 99 + 10  # shared folders and their non-public children
    assert fake.call_count("permissions.list") == 0  # My Drive: permissions came inline


def test_resume_after_failure(store: AuditStore) -> None:
    fake = _big_drive(30, 100)  # 3,030 items -> 4 pages
    fake.inject_error(
        "files.list",
        500,
        times=None,
        when=lambda kw: (
            kw.get("pageToken") == "p2000"
            and kw.get("fields", "").startswith("nextPageToken,incompleteSearch")
        ),
    )
    runner = AuditRunner(
        DriveClient(fake.service(), sleep=lambda s: None, max_retries=2), store, account=ME
    )
    with pytest.raises(DriveHttpError):
        runner.run(AuditScope.parse("mine"))
    first_pages = [
        kw["pageToken"]
        for n, kw in fake.calls
        if n == "files.list" and kw["fields"].startswith("nextPageToken,incomplete")
    ]
    assert first_pages[:2] == [None, "p1000"]

    fake._injections.clear()
    fake.calls.clear()
    result = runner.run(AuditScope.parse("mine"))
    assert result.resumed
    resumed_pages = [
        kw["pageToken"]
        for n, kw in fake.calls
        if n == "files.list" and kw["fields"].startswith("nextPageToken,incomplete")
    ]
    assert resumed_pages == ["p2000", "p3000"]  # did not start over
    assert len(result.items) == 3030
    assert fake.write_calls == []

    fresh = AuditStore(store.path.with_name("fresh.db"), ColumnCipher(os.urandom(32)))
    try:
        clean = AuditRunner(DriveClient(fake.service()), fresh, account=ME).run(
            AuditScope.parse("mine")
        )
    finally:
        fresh.close()
    assert {a.file_id: a.exposure for a in clean.items} == {
        a.file_id: a.exposure for a in result.items
    }


def test_cancel_then_resume(store: AuditStore) -> None:
    fake = _big_drive(30, 100)
    cancel = threading.Event()

    def on_progress(p: Progress) -> None:
        if p.phase == "list" and p.listed >= 1000:
            cancel.set()

    runner = AuditRunner(
        DriveClient(fake.service()), store, account=ME, on_progress=on_progress, cancel=cancel
    )
    with pytest.raises(AuditCancelled):
        runner.run(AuditScope.parse("mine"))
    assert store.resumable_scan("mine") is not None
    cancel.clear()
    runner.on_progress = None
    result = runner.run(AuditScope.parse("mine"))
    assert result.resumed
    assert len(result.items) == 3030


def test_expired_page_token_relists(store: AuditStore) -> None:
    fake = _big_drive(15, 100)
    runner = AuditRunner(DriveClient(fake.service()), store, account=ME)
    scan_id = store.new_scan(
        "mine",
        {"phase": "list", "public": {}, "root_id": fake.root_id, "page_token": "expired-token"},
    )
    store.set_status(scan_id, "failed")
    result = runner.run(AuditScope.parse("mine"))
    assert result.resumed
    assert len(result.items) == 1515


def test_rate_limits_are_retried(store: AuditStore) -> None:
    fake = _big_drive(2, 10)
    fake.inject_error("files.list", 429, "rateLimitExceeded", times=2)
    fake.inject_error("files.list", 403, "userRateLimitExceeded", times=1)
    sleeps: list[float] = []
    runner = AuditRunner(DriveClient(fake.service(), sleep=sleeps.append), store, account=ME)
    result = runner.run(AuditScope.parse("mine"))
    assert len(result.items) == 22
    assert len(sleeps) == 3


def test_cancel_on_last_page_is_honoured(store: AuditStore) -> None:
    fake = _big_drive(2, 10)  # a single page
    cancel = threading.Event()

    def on_progress(p: Progress) -> None:
        if p.phase == "list":
            cancel.set()

    runner = AuditRunner(
        DriveClient(fake.service()), store, account=ME, on_progress=on_progress, cancel=cancel
    )
    with pytest.raises(AuditCancelled):
        runner.run(AuditScope.parse("mine"))


# --- big drives: createdTime windows, quick public scope ----------------------------------------


def _spread_years(fake: FakeDrive) -> None:
    """Creation times from 2009 to 2026 so every kind of window gets items."""
    for n, fid in enumerate(i for i in fake.items if i != fake.root_id):
        year = 2009 + n % 18
        month = 1 + (n * 5) % 12
        fake.items[fid].created_time = f"{year}-{month:02d}-15T08:00:00.000Z"


def _listing_queries(fake: FakeDrive) -> list[str]:
    return [
        kw["q"]
        for n, kw in fake.calls
        if n == "files.list" and kw["fields"].startswith("nextPageToken,incomplete")
    ]


def test_big_drive_listed_in_windows_equals_plain_listing(
    store: AuditStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _big_drive(30, 100)  # 3,030 items
    _spread_years(fake)
    plain = run(fake, store, "mine")
    monkeypatch.setattr(runner_mod, "SPLIT_ITEMS", 1000)
    fake.calls.clear()
    other = AuditStore(store.path.with_name("windows.db"), ColumnCipher(os.urandom(32)))
    try:
        windowed = run(fake, other, "mine")
    finally:
        other.close()
    queries = _listing_queries(fake)
    assert any("createdTime < '2012-01-01T00:00:00'" in q for q in queries)
    assert any("createdTime >= '2026-07-01T00:00:00'" in q or "2026-01-01" in q for q in queries)
    assert {k: (a.exposure, a.name) for k, a in windowed.items()} == {
        k: (a.exposure, a.name) for k, a in plain.items()
    }


def test_big_drive_resumes_at_the_failed_window(
    store: AuditStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner_mod, "SPLIT_ITEMS", 1000)
    fake = _big_drive(30, 100)
    _spread_years(fake)
    failing = "createdTime >= '2018-07-01T00:00:00'"
    fake.inject_error("files.list", 500, times=None, when=lambda kw: failing in kw.get("q", ""))
    runner = AuditRunner(
        DriveClient(fake.service(), sleep=lambda s: None, max_retries=1), store, account=ME
    )
    with pytest.raises(DriveHttpError):
        runner.run(AuditScope.parse("mine"))
    fake._injections.clear()
    fake.calls.clear()
    result = runner.run(AuditScope.parse("mine"))
    assert result.resumed
    queries = _listing_queries(fake)
    assert failing in queries[0]  # went on from the window that failed, not from the start
    assert not any("createdTime < '2012-01-01T00:00:00'" in q for q in queries)
    assert len(result.items) == 3030


def test_expired_token_on_a_big_drive_switches_to_windows(
    store: AuditStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner_mod, "SPLIT_ITEMS", 1000)
    fake = _big_drive(30, 100)
    runner = AuditRunner(DriveClient(fake.service()), store, account=ME)
    first = runner.run(AuditScope.parse("mine"))  # saves every row once
    scan_id = store.new_scan(
        "mine",
        {"phase": "list", "public": {}, "root_id": fake.root_id, "page_token": "expired-token"},
    )
    store.save_items(scan_id, list(store.iter_items(first.scan_id)))
    store.set_status(scan_id, "failed")
    fake.calls.clear()
    result = runner.run(AuditScope.parse("mine"))
    assert result.resumed
    assert all("createdTime" in q for q in _listing_queries(fake)[1:])
    assert len(result.items) == 3030


def test_public_scope_lists_only_link_shared_files(
    my_drive: tuple[FakeDrive, dict[str, str]], store: AuditStore
) -> None:
    fake, ids = my_drive
    items = run(fake, store, "public")
    assert ids["link_view"] in items
    assert ids["link_edit"] in items
    assert ids["findable"] in items
    assert ids["child_direct"] in items
    for private in ("private", "external", "internal", "domain", "child"):
        assert ids[private] not in items
    assert all(a.exposure >= Exposure.LINK_VIEW for a in items.values())
