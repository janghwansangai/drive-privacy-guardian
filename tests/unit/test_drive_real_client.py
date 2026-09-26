"""DriveClient against the *real* google-api-python-client (static discovery, no network).

fake_drive accepts any keyword; the real client validates parameter names against the Drive v3
discovery document. A recording GuardedHttp answers with canned JSON, so this also proves every
request goes to the allow-listed host, via GET only.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httplib2
import pytest

from dpg.core.drive.client import DriveClient, build_drive_service
from dpg.core.net_guard.http import GuardedHttp


class CannedHttp(GuardedHttp):
    def __init__(self) -> None:
        super().__init__()
        self.seen: list[tuple[str, str, dict[str, list[str]]]] = []

    def _send(
        self,
        uri: str,
        method: str,
        body: Any,
        headers: Any,
        redirections: int,
        connection_type: Any,
    ) -> tuple[httplib2.Response, bytes]:
        parts = urlsplit(uri)
        self.seen.append((method, parts.path, parse_qs(parts.query)))
        if parts.path.endswith("/about"):
            payload: dict[str, Any] = {"user": {"emailAddress": "t@school.example"}}
        elif parts.path.endswith("/permissions"):
            payload = {"permissions": [{"id": "anyoneWithLink", "type": "anyone"}]}
        elif parts.path.endswith("/drives"):
            payload = {"drives": [{"id": "0AD", "name": "d"}]}
        elif parts.path.endswith("/changes/startPageToken"):
            payload = {"startPageToken": "100"}
        elif parts.path.endswith("/changes"):
            payload = {"changes": [{"fileId": "1A", "removed": True}], "newStartPageToken": "101"}
        elif parts.path.endswith("/files"):
            payload = {"files": [{"id": "1A"}], "incompleteSearch": False}
        else:
            payload = {"id": "1A", "mimeType": "text/plain"}
        response = httplib2.Response({"status": "200", "content-type": "application/json"})
        return response, json.dumps(payload).encode()


def test_real_client_parameters_and_hosts() -> None:
    http = CannedHttp()
    client = DriveClient(build_drive_service(http))
    assert client.about_email() == "t@school.example"
    page = client.list_files_page(q="'me' in owners and trashed = false", page_token=None)
    assert [f["id"] for f in page.items] == ["1A"]
    client.list_files_page(q="trashed = false", page_token="tok", drive_id="0AD")
    assert client.list_ids(q="visibility = 'anyoneWithLink'") == {"1A"}
    client.get_file("root")
    assert client.list_permissions("1A")[0]["type"] == "anyone"
    assert [d["id"] for d in client.list_shared_drives()] == ["0AD"]

    assert {m for m, _, _ in http.seen} == {"GET"}  # read-only
    assert all(path.startswith("/drive/v3/") for _, path, _ in http.seen)

    list_calls = [q for _, path, q in http.seen if path == "/drive/v3/files"]
    first = list_calls[0]
    assert first["corpora"] == ["user"]
    assert first["supportsAllDrives"] == ["true"]
    assert first["includeItemsFromAllDrives"] == ["true"]
    assert first["pageSize"] == ["1000"]
    assert "permissions(" in first["fields"][0]
    drive_call = list_calls[1]
    assert drive_call["corpora"] == ["drive"]
    assert drive_call["driveId"] == ["0AD"]
    assert drive_call["pageToken"] == ["tok"]

    perm_call = next(q for _, path, q in http.seen if path.endswith("/permissions"))
    assert perm_call["pageSize"] == ["100"]
    assert "permissionDetails(" in perm_call["fields"][0]


def test_real_client_download_and_export() -> None:
    http = CannedHttp()
    client = DriveClient(build_drive_service(http))
    assert client.download("1A", max_bytes=10_000)
    assert client.export("1A", "text/plain")
    media = next(q for _m, path, q in http.seen if path == "/drive/v3/files/1A" and "alt" in q)
    assert media["alt"] == ["media"]
    assert media["supportsAllDrives"] == ["true"]
    export = next(q for _m, path, q in http.seen if path == "/drive/v3/files/1A/export")
    assert export["mimeType"] == ["text/plain"]
    assert {m for m, _, _ in http.seen} == {"GET"}


def test_real_client_write_parameters() -> None:
    """Writer requests are valid for the Drive v3 discovery document (names, methods)."""
    from dpg.core.actions.writer import DriveWriter

    http = CannedHttp()
    writer = DriveWriter(DriveClient(build_drive_service(http)))
    writer.delete_permission("1A", "anyoneWithLink")
    writer.update_permission_role("1A", "p1", "reader")
    writer.create_permission(
        "1A", {"id": "p1", "type": "user", "role": "writer", "emailAddress": "x@example.com"}
    )
    writer.update_file(
        "1A",
        {
            "downloadRestrictions": {
                "itemDownloadRestriction": {
                    "restrictedForReaders": True,
                    "restrictedForWriters": False,
                }
            }
        },
    )
    methods = [(m, path) for m, path, _q in http.seen]
    assert methods == [
        ("DELETE", "/drive/v3/files/1A/permissions/anyoneWithLink"),
        ("PATCH", "/drive/v3/files/1A/permissions/p1"),
        ("POST", "/drive/v3/files/1A/permissions"),
        ("PATCH", "/drive/v3/files/1A"),
    ]
    create_q = http.seen[2][2]
    assert create_q["sendNotificationEmail"] == ["false"]
    assert all(q.get("supportsAllDrives") == ["true"] for _m, _p, q in http.seen)
    for bad in ({"trashed": True}, {"name": "x"}, {}):
        with pytest.raises(ValueError, match="sharing-related"):
            writer.update_file("1A", bad)


def test_real_client_changes_parameters() -> None:
    http = CannedHttp()
    client = DriveClient(build_drive_service(http))
    assert client.start_page_token() == "100"
    changes, token = client.list_changes("100")
    assert token == "101"
    assert changes == [{"fileId": "1A", "removed": True}]
    client.list_changes("100", drive_id="0AD")
    calls = [q for _m, path, q in http.seen if path == "/drive/v3/changes"]
    assert calls[0]["pageToken"] == ["100"]
    assert calls[0]["includeRemoved"] == ["true"]
    assert "file(" in calls[0]["fields"][0]
    assert calls[1]["driveId"] == ["0AD"]
    assert {m for m, _, _ in http.seen} == {"GET"}


def test_real_client_phase6_write_parameters() -> None:
    """Move / trash / upload / new folder requests are valid for the discovery document."""
    from dpg.core.actions.writer import DriveWriter

    http = CannedHttp()
    writer = DriveWriter(DriveClient(build_drive_service(http)))
    writer.move_file("1A", "new", "old")
    writer.set_trashed("1A", True)
    writer.upload("보관_2026-09-26_ab12.7z", "root", b"7z-bytes", "application/x-7z-compressed")
    writer.create_folder("2026 보관", "root")
    seen = [(m, path) for m, path, _q in http.seen]
    assert seen[0] == ("PATCH", "/drive/v3/files/1A")
    assert http.seen[0][2]["addParents"] == ["new"]
    assert http.seen[0][2]["removeParents"] == ["old"]
    assert seen[1] == ("PATCH", "/drive/v3/files/1A")
    assert seen[2] == ("POST", "/upload/drive/v3/files")
    assert seen[3] == ("POST", "/drive/v3/files")
    assert not any(m == "DELETE" for m, _p in seen)
