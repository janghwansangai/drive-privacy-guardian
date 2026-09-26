"""Phase 4 gate: detection over fake_drive holding the synthetic fixtures (read-only)."""

from __future__ import annotations

import datetime as dt
import os
import threading
from pathlib import Path

import pytest

from dpg.core.audit.model import Exposure
from dpg.core.audit.runner import AuditRunner, AuditScope
from dpg.core.detect.runner import DetectCancelled, DetectRunner, load_detections, review
from dpg.core.drive.client import DriveClient
from dpg.core.extract import UnscannableReason
from dpg.core.policy import DetectStatus, Level, recommend
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import ColumnCipher
from tests.fakes.fake_drive import FakeDrive

ME = "teacher@school.example"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
MIME = {
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".hwp": "application/x-hwp",
    ".hwpx": "application/hwp+zip",
}


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    s = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    yield s  # type: ignore[misc]
    s.close()


def _drive() -> tuple[FakeDrive, dict[str, str]]:
    fake = FakeDrive(me=ME)
    folder = fake.add_folder("6학년 자료")
    ids: dict[str, str] = {"folder": folder}
    for path in sorted(FIXTURES.iterdir()):
        if path.name == "manifest.json":
            continue
        ids[path.name] = fake.add_file(
            path.name, parent=folder, mime_type=MIME[path.suffix], content=path.read_bytes()
        )
    ids["gdoc"] = fake.add_item(
        "구글문서 명단",
        "application/vnd.google-apps.document",
        parent=folder,
        exports={"text/plain": "연락처 010-0123-4567".encode()},
    )
    ids["gsheet"] = fake.add_item(
        "구글시트",
        "application/vnd.google-apps.spreadsheet",
        parent=folder,
        exports={MIME[".xlsx"]: (FIXTURES / "6-2_학생_연락처.xlsx").read_bytes()},
    )
    ids["huge_export"] = fake.add_item(
        "큰 문서",
        "application/vnd.google-apps.document",
        parent=folder,
        exports={"text/plain": b"x" * (11 * 1024 * 1024)},
    )
    ids["photo"] = fake.add_file(
        "스캔본.jpg", parent=folder, mime_type="image/jpeg", content=b"\xff\xd8\xff"
    )
    ids["zip"] = fake.add_file(
        "백업.zip", parent=folder, mime_type="application/zip", content=b"PK"
    )
    fake.share(ids["6-2_학생_연락처.csv"], "anyone", "reader")
    fake.share(ids["학생명단_가상.hwpx"], "user", "reader", email="parent@gmail.example")
    fake.share(ids["스캔_가상.pdf"], "anyone", "reader")
    return fake, ids


def _scan(fake: FakeDrive, store: AuditStore, **kw: object) -> tuple[object, dict]:
    client = DriveClient(fake.service(), sleep=lambda s: None)
    result = AuditRunner(client, store, account=ME).run(AuditScope.parse("mine"))
    dets = DetectRunner(client, store, **kw).run(result.scan_id, result.items)  # type: ignore[arg-type]
    assert fake.write_calls == []
    return result, dets


def test_detection_statuses(store: AuditStore) -> None:
    fake, ids = _drive()
    _result, dets = _scan(fake, store)
    by = {name: dets[fid] for name, fid in ids.items()}

    assert by["6-2_학생_연락처.csv"].status is DetectStatus.DETECTED
    assert set(by["6-2_학생_연락처.csv"].kinds) >= {
        "rrn",
        "mobile",
        "address",
        "student_roster",
        "filename_hint",
    }
    assert by["6-2_학생_연락처.csv"].kinds["rrn"].count == 30
    assert by["상담기록_가상.hwp"].kinds["student_roster"].count == 1
    assert by["보호자_안내문.pdf"].kinds["account"].count == 2
    assert by["gdoc"].kinds["mobile"].count == 1
    assert by["gsheet"].kinds["rrn"].count == 30
    assert by["negatives.txt"].status is DetectStatus.NOT_FOUND

    # 검사 불가 — never reported as clean
    unscannable = {
        "스캔_가상.pdf": UnscannableReason.IMAGE_ONLY,
        "암호_가상.hwp": UnscannableReason.ENCRYPTED,
        "배포용_가상.hwp": UnscannableReason.DISTRIBUTION,
        "huge_export": UnscannableReason.EXPORT_LIMIT,
        "photo": UnscannableReason.IMAGE_ONLY,
        "zip": UnscannableReason.UNSUPPORTED,
    }
    for name, reason in unscannable.items():
        assert by[name].status is DetectStatus.UNSCANNABLE, name
        assert by[name].reason is reason, name
    # the folder is checked by name only
    assert by["folder"].status is DetectStatus.NOT_FOUND


def test_recommendations(store: AuditStore) -> None:
    fake, ids = _drive()
    result, dets = _scan(fake, store)
    audits = {a.file_id: a for a in result.items}  # type: ignore[attr-defined]
    csv = audits[ids["6-2_학생_연락처.csv"]]
    assert csv.exposure == Exposure.LINK_VIEW
    top = recommend(csv, dets[csv.file_id])[0]
    assert (top.level, top.action) == (Level.URGENT, "remove_link")
    roster = audits[ids["학생명단_가상.hwpx"]]
    assert any(r.text == "외부 계정 확인 후 제거" for r in recommend(roster, dets[roster.file_id]))
    scan = audits[ids["스캔_가상.pdf"]]
    assert any("수동 검토" in r.text for r in recommend(scan, dets[scan.file_id]))
    old = audits[ids["보호자_안내문.pdf"]]
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=800)
    assert any(r.action == "archive" for r in recommend(old, dets[old.file_id], now=later))


def test_resume_cancel_and_persistence(store: AuditStore) -> None:
    fake, _ids = _drive()
    client = DriveClient(fake.service(), sleep=lambda s: None)
    result = AuditRunner(client, store, account=ME).run(AuditScope.parse("mine"))
    cancel = threading.Event()
    seen: list[int] = []

    def progress(p: object) -> None:
        seen.append(p.done)  # type: ignore[attr-defined]
        if p.done == 3:  # type: ignore[attr-defined]
            cancel.set()

    with pytest.raises(DetectCancelled):
        DetectRunner(client, store, on_progress=progress, cancel=cancel).run(
            result.scan_id, result.items
        )
    assert len(load_detections(store, result.scan_id)) == 3
    downloads_before = fake.call_count("files.get_media") + fake.call_count("files.export_media")
    dets = DetectRunner(client, store).run(result.scan_id, result.items)
    assert len(dets) == len(result.items)
    downloads = fake.call_count("files.get_media") + fake.call_count("files.export_media")
    assert downloads - downloads_before < len(result.items)  # finished files not re-read
    reloaded = load_detections(store, result.scan_id)
    assert {k: v.status for k, v in reloaded.items()} == {k: v.status for k, v in dets.items()}


def test_exclusions(store: AuditStore) -> None:
    fake, ids = _drive()
    store.add_exclusion(ids["6-2_학생_연락처.csv"])  # "이 파일 제외"
    store.add_exclusion(ids["folder"], "mobile")  # "이 규칙 이 폴더 제외"
    _result, dets = _scan(fake, store)
    assert dets[ids["6-2_학생_연락처.csv"]].status is DetectStatus.EXCLUDED
    assert "mobile" not in dets[ids["6-2_학생_연락처.xlsx"]].kinds
    assert "rrn" in dets[ids["6-2_학생_연락처.xlsx"]].kinds


def test_deleted_and_forbidden_files(store: AuditStore) -> None:
    fake, ids = _drive()
    fake.inject_error(
        "files.get_media", 404, "notFound", when=lambda kw: kw["fileId"] == ids["업무메모.txt"]
    )
    fake.inject_error(
        "files.get_media",
        403,
        "cannotDownloadFile",
        when=lambda kw: kw["fileId"] == ids["negatives.txt"],
    )
    _result, dets = _scan(fake, store)
    assert dets[ids["업무메모.txt"]].status is DetectStatus.FAILED
    assert dets[ids["negatives.txt"]].status is DetectStatus.UNSCANNABLE
    assert dets[ids["negatives.txt"]].reason is UnscannableReason.NOT_DOWNLOADABLE


def test_review_is_masked(store: AuditStore) -> None:
    fake, ids = _drive()
    result, _dets = _scan(fake, store)
    item = next(a for a in result.items if a.file_id == ids["업무메모.txt"])  # type: ignore[attr-defined]
    lines = review(DriveClient(fake.service()), item)
    assert {line.kind for line in lines} >= {"rrn", "card", "passport"}
    raw = (FIXTURES / "업무메모.txt").read_text(encoding="utf-8")
    import re

    for value in re.findall(r"\d{6}-\d{7}|9999-\d{4}-\d{4}-\d{4}", raw):
        assert all(value not in line.snippet for line in lines)
