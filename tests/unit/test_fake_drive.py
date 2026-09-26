from __future__ import annotations

import pytest
from googleapiclient.errors import HttpError

from tests.fakes.fake_drive import (
    FakeDrive,
    ForbiddenCallError,
    WriteAttemptError,
    parse_fields,
)

ME = "teacher@school.example"


@pytest.fixture
def fake() -> FakeDrive:
    return FakeDrive(me=ME)


def _ids(resp: dict) -> list[str]:
    return [f["id"] for f in resp["files"]]


def test_default_fields_are_minimal(fake: FakeDrive) -> None:
    fid = fake.add_file("a.txt")
    resp = fake.service().files().list().execute()
    assert resp["files"] == [
        {"kind": "drive#file", "id": fid, "name": "a.txt", "mimeType": "text/plain"}
    ]


def test_fields_selection_nested(fake: FakeDrive) -> None:
    fid = fake.add_file("a.txt")
    fake.share(fid, "anyone", "reader")
    resp = (
        fake.service()
        .files()
        .list(fields="nextPageToken, files(id, permissions(id,role,type))")
        .execute()
    )
    perms = resp["files"][0]["permissions"]
    assert {"id": "anyoneWithLink", "role": "reader", "type": "anyone"} in perms
    assert all(set(p) <= {"id", "role", "type"} for p in perms)


def test_parse_fields() -> None:
    assert parse_fields("a,b(c,d(e)),f") == {
        "a": None,
        "b": {"c": None, "d": {"e": None}},
        "f": None,
    }


def test_pagination(fake: FakeDrive) -> None:
    for i in range(25):
        fake.add_file(f"f{i}.txt")
    files = fake.service().files()
    seen: list[str] = []
    token = None
    pages = 0
    while True:
        resp = files.list(pageSize=10, pageToken=token, fields="nextPageToken,files(id)").execute()
        seen += _ids(resp)
        pages += 1
        token = resp.get("nextPageToken")
        if not token:
            break
    assert pages == 3
    assert len(seen) == len(set(seen)) == 25


def test_query_language(fake: FakeDrive) -> None:
    folder = fake.add_folder("F")
    a = fake.add_file("a 연락처.xlsx", parent=folder)
    b = fake.add_file("b.txt", parent=folder)
    fake.share(a, "anyone", "writer")
    fake.items[b].trashed = True
    files = fake.service().files()

    def q(query: str) -> set[str]:
        return set(_ids(files.list(q=query, fields="files(id)").execute()))

    assert q(f"'{folder}' in parents") == {a, b}
    assert q(f"'{folder}' in parents and trashed = false") == {a}
    assert q("visibility = 'anyoneWithLink'") == {a}
    assert q("name contains '연락처'") == {a}
    assert q(f"mimeType = '{'application/vnd.google-apps.folder'}'") == {folder}
    assert q("'me' in owners and not trashed = true") == {folder, a}
    assert q("(name = 'b.txt' or name = 'a 연락처.xlsx') and trashed = true") == {b}
    with pytest.raises(HttpError) as exc:
        files.list(q="name = ").execute()
    assert exc.value.resp.status == 400
    with pytest.raises(NotImplementedError):
        files.list(q="starred = true").execute()


def test_shared_with_me_and_foreign_files(fake: FakeDrive) -> None:
    other = fake.add_file("from colleague", owner="colleague@school.example")
    hidden = fake.add_file("not shared", owner="colleague@school.example")
    fake.share(other, "user", "reader", email=ME)
    files = fake.service().files()
    assert _ids(files.list(q="sharedWithMe", fields="files(id)").execute()) == [other]
    assert hidden not in _ids(files.list(fields="files(id)").execute())
    with pytest.raises(HttpError) as exc:
        files.get(fileId=hidden).execute()
    assert exc.value.resp.status == 404


def test_permissions_403_for_reader(fake: FakeDrive) -> None:
    other = fake.add_file("read only", owner="colleague@school.example")
    fake.share(other, "user", "reader", email=ME)
    with pytest.raises(HttpError) as exc:
        fake.service().permissions().list(fileId=other).execute()
    assert exc.value.resp.status == 403
    assert exc.value.error_details[0]["reason"] == "insufficientFilePermissions"


def test_my_drive_inheritance(fake: FakeDrive) -> None:
    folder = fake.add_folder("공유 폴더")
    fake.share(folder, "user", "writer", email="outsider@gmail.example")
    child = fake.add_file("child.docx", parent=folder)
    perms = (
        fake.service()
        .permissions()
        .list(fileId=child, fields="permissions(id,role,emailAddress,permissionDetails)")
        .execute()["permissions"]
    )
    emails = {p.get("emailAddress"): p["role"] for p in perms}
    assert emails == {ME: "owner", "outsider@gmail.example": "writer"}
    assert all("permissionDetails" not in p for p in perms)  # V5: My Drive has no details


def test_shared_drive_details_and_flags(fake: FakeDrive) -> None:
    drive = fake.add_shared_drive(
        "교무부", members={ME: "organizer", "peer@school.example": "writer"}
    )
    sub = fake.add_folder("sub", parent=drive)
    fake.share(sub, "user", "reader", email="ext@gmail.example")
    f = fake.add_file("x.hwp", parent=sub)
    svc = fake.service()

    with pytest.raises(HttpError):  # supportsAllDrives missing
        svc.files().get(fileId=f).execute()
    with pytest.raises(HttpError):  # includeItemsFromAllDrives without supportsAllDrives
        svc.files().list(includeItemsFromAllDrives=True).execute()

    listed = (
        svc.files()
        .list(
            corpora="drive",
            driveId=drive,
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            fields="files(id,driveId)",
        )
        .execute()
    )
    assert {x["id"] for x in listed["files"]} == {sub, f}
    assert all(x["driveId"] == drive for x in listed["files"])

    perms = (
        svc.permissions()
        .list(
            fileId=f, supportsAllDrives=True, fields="permissions(emailAddress,permissionDetails)"
        )
        .execute()["permissions"]
    )
    by_email = {p["emailAddress"]: p["permissionDetails"] for p in perms}
    assert by_email["ext@gmail.example"] == [
        {"permissionType": "file", "role": "reader", "inherited": True, "inheritedFrom": sub}
    ]
    assert by_email[ME][0]["permissionType"] == "member"


def test_error_injection(fake: FakeDrive) -> None:
    fake.add_file("a")
    fake.inject_error("files.list", 429, "rateLimitExceeded", times=2)
    req = fake.service().files().list()
    for _ in range(2):
        with pytest.raises(HttpError) as exc:
            req.execute()
        assert exc.value.resp.status == 429
    assert req.execute()["files"]


def test_read_only_blocks_writes(fake: FakeDrive) -> None:
    fid = fake.add_file("a")
    svc = fake.service()
    with pytest.raises(WriteAttemptError):
        svc.permissions().create(fileId=fid, body={"type": "anyone", "role": "reader"})
    with pytest.raises(WriteAttemptError):
        svc.files().update(fileId=fid, body={"trashed": True})
    assert [name for name, _ in fake.write_calls] == ["permissions.create", "files.update"]


@pytest.mark.parametrize("read_only", [True, False])
def test_permanent_delete_always_forbidden(read_only: bool) -> None:
    fake = FakeDrive(me=ME, read_only=read_only)
    fid = fake.add_file("a")
    with pytest.raises(ForbiddenCallError):
        fake.service().files().delete(fileId=fid)
    with pytest.raises(ForbiddenCallError):
        fake.service().files().emptyTrash()


def test_writable_mode_permission_changes() -> None:
    fake = FakeDrive(me=ME, read_only=False)
    folder = fake.add_folder("F")
    fake.share(folder, "user", "reader", email="inherited@school.example")
    fid = fake.add_file("a", parent=folder)
    pid = fake.share(fid, "anyone", "writer")
    perms = fake.service().permissions()
    perms.update(fileId=fid, permissionId=pid, body={"role": "reader"}).execute()
    assert fake.visibility(fake.items[fid]) == "anyoneWithLink"
    perms.delete(fileId=fid, permissionId=pid).execute()
    assert fake.visibility(fake.items[fid]) == "limited"
    inherited_id = next(
        p["id"]
        for p in fake.effective_permissions(fake.items[fid])
        if p.get("emailAddress") == "inherited@school.example"
    )
    with pytest.raises(HttpError) as exc:  # inherited permission cannot be removed on the child
        perms.delete(fileId=fid, permissionId=inherited_id).execute()
    assert exc.value.resp.status == 403


def test_media_and_export(fake: FakeDrive) -> None:
    raw = fake.add_file("a.txt", content=b"hello")
    gdoc = fake.add_item(
        "doc", "application/vnd.google-apps.document", exports={"text/plain": b"exported"}
    )
    files = fake.service().files()
    assert files.get_media(fileId=raw).execute() == b"hello"
    assert files.export_media(fileId=gdoc, mimeType="text/plain").execute() == b"exported"
    with pytest.raises(HttpError):
        files.get_media(fileId=gdoc).execute()
    meta = files.get(fileId=raw, fields="size,md5Checksum").execute()
    assert meta["size"] == "5"


def test_scale_10k_listing_is_fast(fake: FakeDrive) -> None:
    folder = fake.add_folder("big")
    for i in range(10_000):
        fake.add_file(f"f{i}", parent=folder)
    files = fake.service().files()
    total, token = 0, None
    while True:
        resp = files.list(
            pageSize=1000, pageToken=token, fields="nextPageToken,files(id)"
        ).execute()
        total += len(resp["files"])
        token = resp.get("nextPageToken")
        if not token:
            break
    assert total == 10_001
    assert fake.write_calls == []
