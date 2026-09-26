"""Phase 4 privacy gate (SPEC 5.4, 7): after detecting personal data in synthetic files, the log,
DB, report and temp folder contain zero detections; no temp files are created; parser crashes
never leak document text."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import pytest

from dpg.cli.main import main
from dpg.core.auth import AccessLevel, AuthManager
from dpg.core.detect.leakscan import scan_paths
from dpg.core.detect.patterns import count_matches
from dpg.core.net_guard import global_guard
from tests.fakes.fake_drive import FakeDrive
from tests.fakes.fake_google_auth import FakeGoogle, MemorySecretStore
from tests.integration.test_detect_scenarios import FIXTURES, MIME

pytestmark = pytest.mark.enable_socket  # fake browser uses the loopback listener

ME = "teacher@school.example"


def _files_since(root: Path, since: float) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.stat().st_mtime >= since:
                out.append(p)
        except OSError:
            continue
    return out


def _setup() -> tuple[FakeGoogle, MemorySecretStore, FakeDrive]:
    google, store, fake = FakeGoogle(email=ME), MemorySecretStore(), FakeDrive(me=ME)
    for path in sorted(FIXTURES.iterdir()):
        if path.suffix in MIME:
            fid = fake.add_file(path.name, mime_type=MIME[path.suffix], content=path.read_bytes())
            fake.share(fid, "anyone", "reader")
    return google, store, fake


def test_detect_outputs_contain_no_personal_data(
    isolated_app_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    google, store, fake = _setup()

    def manager() -> AuthManager:
        return AuthManager(store, http_factory=google.http, open_browser=google.browser)

    m = manager()
    m.import_client(google.client_json())
    m.login(AccessLevel.DETECT)
    report = tmp_path / "out" / "report.xlsx"
    temp_root = Path(tempfile.gettempdir()).resolve()
    before = {p for p in temp_root.iterdir()} if temp_root.exists() else set()
    started = time.time() - 1
    try:
        code = main(
            ["detect", "--scope", "mine", "--out", str(report)],
            manager_factory=manager,
            service_factory=lambda _m: fake.service(),
        )
    finally:
        global_guard().uninstall()
    out = capsys.readouterr()
    assert code == 0, out.err
    assert "즉시 조치가 권장되는 파일" in out.out
    assert fake.write_calls == []

    # log, DB, report: zero detections by the leak scanner
    leak = scan_paths([isolated_app_home, report])
    assert leak.total == 0, leak.summary()
    # console must not echo values either
    assert count_matches(out.out + out.err) == {}
    # no temp files created by the app (everything happens in memory, SPEC 5.2)
    new_temp = (
        [p for p in (set(temp_root.iterdir()) - before) if not p.name.startswith("pytest-")]
        if temp_root.exists()
        else []
    )
    assert new_temp == []
    temp_hits = scan_paths(
        [p for p in _files_since(temp_root, started) if "pytest-of-" not in str(p)]
    )
    assert temp_hits.total == 0, temp_hits.summary()


def test_parser_crash_does_not_leak_text(
    isolated_app_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A library exception whose message contains document text must not reach logs."""
    import logging

    from dpg.core.detect.runner import DetectRunner
    from dpg.core.drive.client import DriveClient
    from dpg.core.extract import formats
    from dpg.core.logging import LOG_FILE_NAME, configure_logging
    from dpg.core.store.audit_store import AuditStore
    from dpg.core.store.crypto import ColumnCipher

    def boom(data: bytes) -> object:
        raise ValueError(f"cannot parse near '{data.decode(errors='ignore')[:60]}'")

    monkeypatch.setattr(formats, "extract_txt", boom)
    from dpg.core import extract as extract_pkg

    monkeypatch.setitem(extract_pkg._BY_MIME, "text/plain", boom)
    log_dir = isolated_app_home / "logs"
    configure_logging(log_dir, level=logging.DEBUG)
    fake = FakeDrive(me=ME)
    fid = fake.add_file(
        "메모.txt",
        mime_type="text/plain",
        content="주민번호 750101-3123454 연락처 010-0123-4567".encode(),
    )
    store = AuditStore(isolated_app_home / "t.db", ColumnCipher(os.urandom(32)))
    try:
        from dpg.core.audit.runner import AuditRunner, AuditScope

        client = DriveClient(fake.service())
        result = AuditRunner(client, store, account=ME).run(AuditScope.parse("mine"))
        dets = DetectRunner(client, store).run(result.scan_id, result.items)
    finally:
        store.close()
        configure_logging(None)
    assert dets[fid].status.value == "unscannable"
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "750101" not in text
    assert "0123-4567" not in text
    assert scan_paths([isolated_app_home]).total == 0
