"""DriveClient error mapping, encrypted store, report formatting, scope parsing."""

from __future__ import annotations

import csv
import datetime as dt
import os
from pathlib import Path

import pytest

from dpg.core.audit.analyze import internal_domains_for
from dpg.core.audit.model import Exposure, FileAudit, ItemStatus
from dpg.core.audit.report import mask_email, mask_name, safe_cell, write_csv
from dpg.core.audit.runner import AuditScope
from dpg.core.auth.errors import InsufficientScope, NetworkError, ReauthRequired
from dpg.core.drive.client import DriveClient, DriveHttpError
from dpg.core.store.audit_store import AuditStore, ItemRow, db_path_for
from dpg.core.store.crypto import ColumnCipher, DecryptError, account_key_id
from tests.fakes.fake_drive import FakeDrive
from tests.fakes.fake_google_auth import MemorySecretStore

# --- DriveClient ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "reason", "error"),
    [
        (401, "authError", ReauthRequired),
        (403, "insufficientPermissions", InsufficientScope),
        (404, "notFound", DriveHttpError),
        (400, "invalid", DriveHttpError),
    ],
)
def test_non_retryable_errors(status: int, reason: str, error: type[Exception]) -> None:
    fake = FakeDrive()
    fake.inject_error("about.get", status, reason)
    sleeps: list[float] = []
    with pytest.raises(error):
        DriveClient(fake.service(), sleep=sleeps.append).about_email()
    assert sleeps == []


def test_persistent_server_error_gives_up() -> None:
    fake = FakeDrive()
    fake.inject_error("about.get", 503, times=None)
    sleeps: list[float] = []
    with pytest.raises(DriveHttpError) as exc:
        DriveClient(fake.service(), sleep=sleeps.append, max_retries=3).about_email()
    assert exc.value.status == 503
    assert len(sleeps) == 3
    assert all(0 <= s <= 32 for s in sleeps)


def test_network_errors_retried_then_reported() -> None:
    class Flaky:
        calls = 0

        def execute(self, num_retries: int = 0) -> dict[str, object]:
            Flaky.calls += 1
            raise TimeoutError("timed out")

    class Svc:
        def about(self) -> Svc:
            return self

        def get(self, **kw: object) -> Flaky:
            return Flaky()

    with pytest.raises(NetworkError):
        DriveClient(Svc(), sleep=lambda s: None, max_retries=2).about_email()
    assert Flaky.calls == 3


def test_long_outage_waits_and_continues_when_asked() -> None:
    """Long scans: the connection comes back after a while → the same request succeeds."""
    now = [0.0]

    class Flaky:
        calls = 0

        def execute(self, num_retries: int = 0) -> dict[str, object]:
            Flaky.calls += 1
            if Flaky.calls <= 7:  # 3 attempts + 3 attempts + 1 → then the network is back
                raise OSError("network down")
            return {"user": {"emailAddress": "t@example.com"}}

    class Svc:
        def about(self) -> Svc:
            return self

        def get(self, **kw: object) -> Flaky:
            return Flaky()

    waits: list[float] = []

    def offline(waited: float) -> bool:
        waits.append(waited)
        now[0] += 20
        return True

    client = DriveClient(
        Svc(), sleep=lambda s: None, max_retries=2, on_offline=offline, clock=lambda: now[0]
    )
    assert client.about_email() == "t@example.com"
    assert waits == [0.0, 20.0]


def test_long_outage_gives_up_when_the_callback_says_so() -> None:
    class Down:
        def execute(self, num_retries: int = 0) -> dict[str, object]:
            raise OSError("network down")

    class Svc:
        def about(self) -> Svc:
            return self

        def get(self, **kw: object) -> Down:
            return Down()

    asked: list[float] = []
    client = DriveClient(
        Svc(), sleep=lambda s: None, max_retries=1, on_offline=lambda w: asked.append(w) or False
    )
    with pytest.raises(NetworkError):
        client.about_email()
    assert asked == [0.0]


# --- store ------------------------------------------------------------------------------------


def _row(fid: str, name: str) -> ItemRow:
    return ItemRow(
        fid,
        "item",
        None,
        None,
        "inline",
        {"id": fid, "name": name, "owners": [{"emailAddress": "t@school.example"}]},
        [{"id": "p1", "type": "user", "emailAddress": "guest@gmail.example"}],
    )


def test_sensitive_columns_are_encrypted(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    scan = store.new_scan("mine", {"phase": "list"})
    store.save_items(scan, [_row("1FakeA", "김가나 상담일지.hwp")])
    rows = list(store.iter_items(scan))
    assert rows[0].meta["name"] == "김가나 상담일지.hwp"
    store.close()
    raw = (tmp_path / "a.db").read_bytes()
    for needle in ("김가나".encode(), "상담일지".encode(), b"guest@gmail", b"t@school"):
        assert needle not in raw
    assert b"1FakeA" in raw  # class-D file IDs stay queryable
    if os.name == "posix":
        assert (tmp_path / "a.db").stat().st_mode & 0o777 == 0o600


def test_wrong_key_cannot_read(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    scan = store.new_scan("mine", {})
    store.save_items(scan, [_row("1", "x")])
    store.close()
    other = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    assert list(other.iter_items(scan)) == []  # undecryptable rows are skipped
    other.close()
    with pytest.raises(DecryptError):
        ColumnCipher(os.urandom(32)).decrypt(os.urandom(40), "aad")


def test_ciphertext_bound_to_row(tmp_path: Path) -> None:
    c = ColumnCipher(os.urandom(32))
    blob = c.encrypt({"a": 1}, "1:fileA")
    with pytest.raises(DecryptError):
        c.decrypt(blob, "1:fileB")  # a row copied onto another file ID does not decrypt


def test_open_for_account_uses_keychain_and_hashed_name(isolated_app_home: Path) -> None:
    secrets = MemorySecretStore()
    store = AuditStore.open_for("teacher@school.example", secrets)
    store.close()
    path = db_path_for("teacher@school.example")
    assert path.exists()
    assert "teacher" not in path.name
    assert path.name == account_key_id("teacher@school.example") + ".db"
    assert list(secrets.data) == [f"db-key-{account_key_id('teacher@school.example')}"]
    # key lost -> unreadable DB is discarded and recreated
    secrets.data.clear()
    AuditStore.open_for("teacher@school.example", secrets).close()
    assert len(secrets.data) == 1


def test_retention_purge(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "a.db", ColumnCipher(os.urandom(32)))
    old = store.new_scan("mine", {})
    store.save_items(old, [_row("1", "x")])
    past = (dt.datetime.now(dt.UTC) - dt.timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store._db.execute("UPDATE scans SET started_at = ? WHERE scan_id = ?", (past, old))
    recent = store.new_scan("mine", {})
    assert store.purge_older_than(30) == 1
    assert store.count_items(old) == 0
    assert store.resumable_scan("mine") is not None
    assert store.resumable_scan("mine").scan_id == recent  # type: ignore[union-attr]
    store.close()


def test_delete_all_removes_db_and_key(isolated_app_home: Path) -> None:
    secrets = MemorySecretStore()
    store = AuditStore.open_for("t@school.example", secrets)
    path = store.path
    store.delete_all(secrets, "t@school.example")
    assert not path.exists()
    assert secrets.data == {}


# --- report -----------------------------------------------------------------------------------


def test_masking_helpers() -> None:
    assert mask_name("김가나 상담일지.hwp") == "김*******.hwp"
    assert mask_name("README") == "R*****"
    assert mask_name(".hidden") == ".******"
    assert mask_email("parent01@gmail.example") == "pa******@gmail.example"
    assert mask_email("ab@x.example") == "ab*@x.example"


@pytest.mark.parametrize("value", ['=HYPERLINK("http://evil")', "+1", "-2", "@SUM(A1)"])
def test_formula_injection_neutralized(value: str) -> None:
    assert safe_cell(value).startswith("'")
    assert safe_cell("정상 파일.xlsx") == "정상 파일.xlsx"


def _audit(**kw: object) -> FileAudit:
    base: dict[str, object] = dict(
        file_id="1Fake",
        name="=cmd|' /C calc'!A0.xlsx",
        mime_type="text/plain",
        is_folder=False,
        drive_id=None,
        parent_id=None,
        owner_email="t@school.example",
        owned_by_me=True,
        modified_time="2026-01-01T00:00:00Z",
        status=ItemStatus.OK,
        exposure=Exposure.EXTERNAL,
        risk_score=60,
        external_accounts=[("parent01@gmail.example", "writer")],
    )
    base.update(kw)
    return FileAudit(**base)  # type: ignore[arg-type]


def test_csv_report(tmp_path: Path) -> None:
    items = [
        _audit(),
        _audit(
            file_id="2Fake",
            name="unknown.txt",
            status=ItemStatus.INSUFFICIENT,
            exposure=None,
            risk_score=None,
            external_accounts=[],
        ),
    ]
    out = tmp_path / "r.csv"
    assert write_csv(out, items) == 2
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM so Excel reads Korean
    rows = list(csv.reader(out.read_text(encoding="utf-8-sig").splitlines()))
    header, first, second = rows
    assert first[0] == "2Fake"  # unknown risk sorts first (needs a human look)
    assert second[header.index("파일명")].startswith("'=")  # masked + formula-neutralized
    assert "parent01" not in out.read_text(encoding="utf-8-sig")
    assert first[header.index("노출도")] == "알 수 없음"
    assert first[header.index("조회 상태")] == "권한 부족/정보 불완전"
    if os.name == "posix":
        assert out.stat().st_mode & 0o777 == 0o600
    write_csv(out, items, mask=False)
    assert "parent01@gmail.example" in out.read_text(encoding="utf-8-sig")


# --- misc -------------------------------------------------------------------------------------


def test_scope_parse() -> None:
    assert AuditScope.parse("mine").key == "mine"
    assert AuditScope.parse("drive:0AbC").key == "drive:0AbC"
    assert AuditScope.parse("FOLDER:1x").kind == "folder"
    for bad in ("drive", "folder:", "everything", "mine:x"):
        with pytest.raises(ValueError, match="범위"):
            AuditScope.parse(bad)


def test_internal_domains() -> None:
    assert internal_domains_for("t@school.example") == {"school.example"}
    assert internal_domains_for("me@gmail.com") == set()  # other gmail users are external
    assert internal_domains_for("me@gmail.com", ["School.Example "]) == {"school.example"}


def test_cli_report_permission_error_is_explained(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    from dpg.cli import audit_cmd

    def deny(*a: object, **k: object) -> int:
        raise PermissionError(1, "Operation not permitted")

    class Result:
        items: tuple[FileAudit, ...] = ()

    monkeypatch.setattr(audit_cmd, "write_report", deny)
    # exercise only the report-writing branch
    args = argparse.Namespace(out=Path("/denied/r.csv"), no_mask=False)
    code = audit_cmd._write_report(args, Result())  # type: ignore[arg-type]
    assert code == 5
    assert "파일 및 폴더" in capsys.readouterr().err
