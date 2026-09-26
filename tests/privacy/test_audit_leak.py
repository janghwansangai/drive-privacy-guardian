"""SPEC 5.4/5.5 for Phase 2: after auditing files whose names contain personal data, the log,
the DB and the default (masked) report contain zero detections — via the real CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from dpg.cli.main import main
from dpg.core.auth import AccessLevel, AuthManager
from dpg.core.detect.leakscan import scan_paths
from dpg.core.net_guard import global_guard
from tests.fakes.fake_drive import FakeDrive
from tests.fakes.fake_google_auth import FakeGoogle, MemorySecretStore

pytestmark = pytest.mark.enable_socket  # loopback login in the fake browser

# Synthetic values only (future birth year, unassigned phone range, reserved domains).
PII_NAMES = [
    "김가나 750101-3123454 상담일지.hwp",
    "6-2 학생 연락처 010-0123-4567.xlsx",
    "보호자 abcdefg@example.com 명단.csv",
]


def test_audit_outputs_contain_no_personal_data(
    isolated_app_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    google = FakeGoogle(email="teacher@school.example")
    store = MemorySecretStore()
    fake = FakeDrive(me="teacher@school.example")
    for name in PII_NAMES:
        fid = fake.add_file(name)
        fake.share(fid, "user", "writer", email="parent@example.org")
        fake.share(fid, "anyone", "reader")

    def manager() -> AuthManager:
        return AuthManager(store, http_factory=google.http, open_browser=google.browser)

    m = manager()
    m.import_client(google.client_json())
    m.login(AccessLevel.AUDIT)
    report = tmp_path / "report.csv"
    try:
        code = main(
            ["audit", "--scope", "mine", "--out", str(report)],
            manager_factory=manager,
            service_factory=lambda _m: fake.service(),
        )
    finally:
        global_guard().uninstall()
    out = capsys.readouterr()
    assert code == 0, out.err
    assert "링크 공개(보기) 3" in out.out
    assert fake.write_calls == []

    # Console output must not echo file names or share-target e-mails either.
    for needle in ("750101", "010-0123", "abcdefg@", "parent@example.org", "상담일지"):
        assert needle not in out.out + out.err

    leak = scan_paths([isolated_app_home, report])
    assert leak.total == 0, leak.summary()
    db_files = list((isolated_app_home / "data").glob("*.db"))
    assert len(db_files) == 1
    raw = db_files[0].read_bytes()
    assert "상담일지".encode() not in raw
    assert "학생 연락처".encode() not in raw
