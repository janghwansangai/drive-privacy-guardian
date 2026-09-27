"""Phase 6 gate (SPEC 7): archive decrypts / hashes match / originals can't be trashed before
verification / moves that would widen access are blocked. All on fake_drive."""

from __future__ import annotations

import datetime as dt
import logging
import os
from pathlib import Path

import pytest

from dpg.core.actions.executor import ActionExecutor
from dpg.core.actions.model import ActionKind, ChangeState, Op
from dpg.core.actions.planner import build_plan
from dpg.core.audit.analyze import internal_domains_for
from dpg.core.audit.model import FileAudit
from dpg.core.audit.runner import AuditRunner, AuditScope
from dpg.core.detect.leakscan import scan_paths
from dpg.core.drive.client import DriveClient
from dpg.core.organize import Category, build_move_plan, duplicate_groups, suggest
from dpg.core.policy import DetectStatus, FileDetection
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import ColumnCipher
from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveFormat
from dpg.core.vault.job import ArchiveFailed, ArchiveJob, trash_plan
from tests.fakes.fake_drive import FakeDrive

ME = "teacher@school.example"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
GDOC = "application/vnd.google-apps.document"


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    s = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    yield s  # type: ignore[misc]
    s.close()


def _drive() -> tuple[FakeDrive, dict[str, str]]:
    f = FakeDrive(me=ME, read_only=False)
    ids = {"old": f.add_folder("2023 업무")}
    ids["roster"] = f.add_file("명단.csv", ids["old"], content=b"name,phone\nA,010\n")
    f.share(ids["roster"], "anyone", "reader")
    f.share(ids["roster"], "user", "reader", email="parent@gmail.example")
    ids["gdoc"] = f.add_file(
        "상담기록", ids["old"], mime_type=GDOC, content=None, exports={DOCX: b"PK docx body"}
    )
    ids["dup"] = f.add_file("명단 사본.csv", content=b"name,phone\nA,010\n")
    ids["archive_dir"] = f.add_folder("보관함")
    ids["public_dir"] = f.add_folder("공개 폴더")
    f.share(ids["public_dir"], "anyone", "reader")
    ids["team_dir"] = f.add_folder("학년 폴더")
    f.share(ids["team_dir"], "user", "writer", email="colleague@school.example")
    ids["plain"] = f.add_file("안내문.txt", content=b"hello")
    f.share(ids["plain"], "user", "writer", email="colleague@school.example")
    return f, ids


def _audit(fake: FakeDrive, store: AuditStore) -> dict[str, FileAudit]:
    r = AuditRunner(DriveClient(fake.service()), store, account=ME).run(AuditScope.parse("mine"))
    return {a.file_id: a for a in r.items}


def test_archive_end_to_end_then_trash_and_undo(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    client = DriveClient(fake.service())
    ex = ActionExecutor(client, store)
    targets = [audits[ids["roster"]], audits[ids["gdoc"]]]

    # step 1: restrict first (link + external removed; notifications none)
    restrict = build_plan(
        ActionKind.RESTRICT_ALL,
        targets,
        account=ME,
        internal_domains=internal_domains_for(ME),
        all_items=list(audits.values()),
    )
    assert {c.before["type"] for c in restrict.changes} == {"anyone", "user"}
    assert ex.execute(restrict).count(ChangeState.DONE) == 2
    assert fake.visibility(fake.items[ids["roster"]]) == "limited"

    pw = archive.generate_password()
    originals = {
        "명단.csv": fake.items[ids["roster"]].content,
        "상담기록.docx": b"PK docx body",
    }
    result = ArchiveJob(client).run(
        targets, pw, ArchiveFormat.SEVEN_ZIP, ids["archive_dir"], dt.date(2026, 9, 26)
    )
    assert result.verified
    assert result.upload_verified
    assert result.safe_to_trash
    assert " (암호화 " in result.name  # D-087: named after the files inside
    assert result.name.endswith(".7z")
    uploaded = fake.items[result.uploaded_id or ""]
    assert uploaded.parent == ids["archive_dir"]
    assert uploaded.permissions == []
    # correct password → identical files; wrong password → failure
    assert archive.open_archive(uploaded.content or b"", pw) == originals
    with pytest.raises(archive.WrongPassword):
        archive.open_archive(uploaded.content or b"", "Wrong-Pass-1234")

    # step 7: trash only individually approved originals, then undo (restore)
    plan = trash_plan(result, [ids["roster"]], audits)
    assert [c.op for c in plan.changes] == [Op.TRASH]
    run = ex.execute(plan)
    assert run.count(ChangeState.DONE) == 1
    assert fake.items[ids["roster"]].trashed
    assert not fake.items[ids["gdoc"]].trashed
    assert fake.call_count("files.delete") == 0
    assert fake.call_count("files.emptyTrash") == 0
    assert ex.undo(run.run_id).count(ChangeState.UNDONE) == 1
    assert not fake.items[ids["roster"]].trashed


def test_no_trash_before_verification(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    fake.corrupt_uploads = True  # the Drive copy differs from what we built
    result = ArchiveJob(DriveClient(fake.service())).run(
        [audits[ids["roster"]]], "Aa1-pw", ArchiveFormat.SEVEN_ZIP, ids["archive_dir"]
    )
    assert result.verified
    assert not result.upload_verified
    assert not result.safe_to_trash
    with pytest.raises(ArchiveFailed):
        trash_plan(result, [ids["roster"]], audits)
    assert not any(n == "files.update" for n, _ in fake.write_calls)


def test_skips_folders_and_forbidden_downloads(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    fake.inject_error("files.get_media", 403, times=None, reason="cannotDownloadFile")
    with pytest.raises(ArchiveFailed):
        ArchiveJob(DriveClient(fake.service())).run(
            [audits[ids["old"]], audits[ids["roster"]]],
            "Aa1-pw",
            ArchiveFormat.AES_ZIP,
            ids["archive_dir"],
        )
    assert fake.call_count("files.create") == 0  # nothing uploaded when nothing collected


def test_password_never_stored_or_logged(
    store: AuditStore,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    pw = archive.generate_password()
    caplog.set_level(logging.DEBUG)
    client = DriveClient(fake.service())
    result = ArchiveJob(client).run([audits[ids["roster"]]], pw, ArchiveFormat.SEVEN_ZIP, "root")
    ActionExecutor(client, store).execute(trash_plan(result, [ids["roster"]], audits))
    store.close()
    blobs = [p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()]
    for needle in (pw, pw.replace("-", "")):
        assert needle not in caplog.text
        assert needle not in capsys.readouterr().out
        assert all(needle.encode() not in b for b in blobs)
    for call in fake.calls:  # never sent to Drive either (only the ciphertext is)
        assert pw not in repr(call)
    assert scan_paths([tmp_path]).total == 0


def test_move_blocked_when_destination_is_wider(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    everything = list(audits.values())
    # private file → public folder: blocked
    p1 = build_move_plan([audits[ids["dup"]]], audits[ids["public_dir"]], everything)
    assert p1.changes == []
    assert "차단" in p1.skipped[0].reason
    assert "링크가 있는 모든 사용자" in p1.skipped[0].reason
    # file shared with the colleague as writer → folder shared with the same colleague: fine
    p2 = build_move_plan([audits[ids["plain"]]], audits[ids["team_dir"]], everything)
    assert len(p2.changes) == 1
    # a private file into the team folder would add the colleague: blocked
    p3 = build_move_plan([audits[ids["dup"]]], audits[ids["team_dir"]], everything)
    assert p3.changes == []
    assert "다른 계정" in p3.skipped[0].reason
    # into a private folder: fine; a folder cannot go into itself
    p4 = build_move_plan(
        [audits[ids["roster"]], audits[ids["archive_dir"]]], audits[ids["archive_dir"]], everything
    )
    assert [c.file_id for c in p4.changes] == [ids["roster"]]

    ex = ActionExecutor(DriveClient(fake.service()), store)
    run = ex.execute(p4)
    assert run.count(ChangeState.DONE) == 1
    assert fake.items[ids["roster"]].parent == ids["archive_dir"]
    assert ex.undo(run.run_id).count(ChangeState.UNDONE) == 1
    assert fake.items[ids["roster"]].parent == ids["old"]
    assert all(n != "files.update" or kw["fileId"] == ids["roster"] for n, kw in fake.write_calls)


def test_move_conflict_if_file_moved_meanwhile(store: AuditStore) -> None:
    fake, ids = _drive()
    audits = _audit(fake, store)
    plan = build_move_plan([audits[ids["roster"]]], audits[ids["archive_dir"]], audits.values())
    fake.items[ids["roster"]].parent = fake.root_id  # someone moved it
    run = ActionExecutor(DriveClient(fake.service()), store).execute(plan)
    assert run.count(ChangeState.CONFLICT) == 1


def test_duplicates_by_size_and_hash_not_name(store: AuditStore) -> None:
    fake, ids = _drive()
    fake.add_file("명단.csv", content=b"different content, same name")
    audits = _audit(fake, store)
    groups = duplicate_groups(audits.values())
    assert [sorted(a.file_id for a in g) for g in groups] == [sorted([ids["roster"], ids["dup"]])]
    assert all(a.mime_type != GDOC for g in groups for a in g)


def test_category_suggestions() -> None:
    now = dt.datetime(2026, 9, 26, tzinfo=dt.UTC)
    from dpg.core.audit.model import Exposure, ItemStatus
    from dpg.core.detect.rules import Confidence, KindSummary

    def audit(modified: str, exposure: Exposure = Exposure.RESTRICTED) -> FileAudit:
        return FileAudit(
            "f", "x", "text/csv", False, None, "p", ME, True, modified, ItemStatus.OK, exposure, 0
        )

    rrn = {"rrn": KindSummary(3, Confidence.HIGH)}
    det = FileDetection("f", DetectStatus.DETECTED, rrn)
    assert suggest(audit("2022-01-01T00:00:00Z"), det, now).category is Category.DISPOSAL
    assert suggest(audit("2025-12-01T00:00:00Z"), det, now).category is Category.ARCHIVE
    assert suggest(audit("2026-09-01T00:00:00Z"), det, now).category is Category.PROTECT
    clean = FileDetection("f", DetectStatus.NOT_FOUND)
    assert suggest(audit("2026-09-01T00:00:00Z"), clean, now).category is Category.GENERAL
    assert (
        suggest(audit("2026-09-01T00:00:00Z", Exposure.DOMAIN), clean, now).category
        is Category.INTERNAL
    )
    # unknown is never "일반"
    unscannable = FileDetection("f", DetectStatus.UNSCANNABLE)
    assert suggest(audit("2026-09-01T00:00:00Z"), unscannable, now).category is None
    assert suggest(audit("2026-09-01T00:00:00Z"), None, now).category is None


def test_restore_in_place_then_trash_archive_and_undo(store: AuditStore) -> None:
    from dpg.core.vault.job import RestoreJob, archive_trash_plan

    fake, ids = _drive()
    audits = _audit(fake, store)
    client = DriveClient(fake.service())
    made = ArchiveJob(client).run(
        [audits[ids["roster"]]], "Aa1-pw", ArchiveFormat.SEVEN_ZIP, ids["archive_dir"]
    )
    arc = made.uploaded_id or ""
    # wrong password: nothing uploaded, archive untouched
    creates = fake.call_count("files.create")
    with pytest.raises(ArchiveFailed):
        RestoreJob(client).run(arc, made.name, "Wrong-1", ids["archive_dir"])
    assert fake.call_count("files.create") == creates
    fake.add_file("명단.csv", ids["archive_dir"], content=b"other")  # a name clash
    restored = RestoreJob(client).run(arc, made.name, "Aa1-pw", ids["archive_dir"])
    assert restored.safe_to_trash_archive
    assert restored.renamed == {"명단.csv": "명단 (복원).csv"}
    new = fake.items[restored.uploaded["명단 (복원).csv"]]
    assert new.parent == ids["archive_dir"]
    assert new.content == fake.items[ids["roster"]].content
    ex = ActionExecutor(client, store)
    run = ex.execute(archive_trash_plan(restored))
    assert run.count(ChangeState.DONE) == 1
    assert fake.items[arc].trashed
    assert fake.call_count("files.delete") == 0
    assert ex.undo(run.run_id).count(ChangeState.UNDONE) == 1
    assert not fake.items[arc].trashed


def test_archive_trash_needs_verified_restore(store: AuditStore) -> None:
    from dpg.core.vault.job import RestoreJob, archive_trash_plan

    fake, ids = _drive()
    audits = _audit(fake, store)
    client = DriveClient(fake.service())
    made = ArchiveJob(client).run([audits[ids["plain"]]], "Aa1-pw", ArchiveFormat.AES_ZIP, "root")
    fake.corrupt_uploads = True
    restored = RestoreJob(client).run(made.uploaded_id or "", made.name, "Aa1-pw", fake.root_id)
    assert not restored.safe_to_trash_archive
    with pytest.raises(ArchiveFailed):
        archive_trash_plan(restored)


def test_restricted_file_with_personal_data_gets_a_recommendation() -> None:
    from dpg.core.audit.model import Exposure, ItemStatus
    from dpg.core.detect.rules import Confidence, KindSummary
    from dpg.core.policy import Level, recommend

    a = FileAudit(
        "f", "x", "text/csv", False, None, "p", ME, True, "2026-09-01T00:00:00Z",
        ItemStatus.OK, Exposure.RESTRICTED, 0,
    )  # fmt: skip
    det = FileDetection("f", DetectStatus.DETECTED, {"rrn": KindSummary(3, Confidence.HIGH)})
    recs = recommend(a, det, dt.datetime(2026, 9, 26, tzinfo=dt.UTC))
    assert recs
    assert recs[0].level is Level.KEEP
    assert "암호화 보관" in recs[0].text
