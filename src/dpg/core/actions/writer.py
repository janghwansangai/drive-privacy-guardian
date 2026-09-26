"""The only code in the app that sends write requests to Drive (CLAUDE.md, SPEC 1.2-3).

Allowed operations are deliberately narrow: permission delete/update/create (create only to
undo a removal), two file settings, moving a file between folders, moving a file to the
trash / restoring it (recoverable for 30 days), uploading a new file (encrypted archive or
its restored contents) and creating an empty folder (a move destination).
There is no method for deleting files permanently or emptying the trash.
"""

from __future__ import annotations

from typing import Any

from googleapiclient.http import MediaInMemoryUpload

from dpg.core.drive.client import DriveClient

ALLOWED_FILE_FIELDS = frozenset({"writersCanShare", "downloadRestrictions"})
_RECREATE_FIELDS = (
    "type",
    "role",
    "emailAddress",
    "domain",
    "allowFileDiscovery",
    "expirationTime",
)


class DriveWriter:
    def __init__(self, client: DriveClient) -> None:
        self._client = client
        self._service = client.service

    def delete_permission(self, file_id: str, perm_id: str) -> None:
        self._client.execute(
            self._service.permissions().delete(
                fileId=file_id, permissionId=perm_id, supportsAllDrives=True
            )
        )

    def update_permission_role(self, file_id: str, perm_id: str, role: str) -> None:
        if role == "owner":
            raise ValueError("ownership changes are out of scope")
        self._client.execute(
            self._service.permissions().update(
                fileId=file_id, permissionId=perm_id, body={"role": role}, supportsAllDrives=True
            )
        )

    def create_permission(self, file_id: str, before: dict[str, Any]) -> None:
        """Re-create a removed permission (undo). Never e-mails the person (V9)."""
        body = {k: before[k] for k in _RECREATE_FIELDS if k in before}
        if body.get("role") == "owner":
            raise ValueError("ownership changes are out of scope")
        kwargs: dict[str, Any] = dict(fileId=file_id, body=body, supportsAllDrives=True)
        if body.get("type") in ("user", "group"):
            kwargs["sendNotificationEmail"] = False
        self._client.execute(self._service.permissions().create(**kwargs))

    def update_file(self, file_id: str, fields: dict[str, Any]) -> None:
        if not fields or set(fields) - ALLOWED_FILE_FIELDS:
            raise ValueError("only sharing-related file settings may be changed here")
        self._client.execute(
            self._service.files().update(fileId=file_id, body=fields, supportsAllDrives=True)
        )

    def move_file(self, file_id: str, new_parent: str, old_parent: str) -> None:
        self._client.execute(
            self._service.files().update(
                fileId=file_id,
                addParents=new_parent,
                removeParents=old_parent,
                body={},
                supportsAllDrives=True,
            )
        )

    def set_trashed(self, file_id: str, trashed: bool) -> None:
        """Move to / restore from the trash. Permanent deletion is deliberately impossible."""
        self._client.execute(
            self._service.files().update(
                fileId=file_id, body={"trashed": bool(trashed)}, supportsAllDrives=True
            )
        )

    def upload(self, name: str, parent: str, data: bytes, mime_type: str) -> dict[str, Any]:
        """Upload a new file (the encrypted archive). Returns id, size, md5Checksum."""
        media = MediaInMemoryUpload(data, mimetype=mime_type, resumable=len(data) > 5 * 1024**2)
        result: dict[str, Any] = self._client.execute(
            self._service.files().create(
                body={"name": name, "parents": [parent]},
                media_body=media,
                fields="id,name,size,md5Checksum,parents",
                supportsAllDrives=True,
            )
        )
        return result

    def create_folder(self, name: str, parent: str) -> dict[str, Any]:
        """Create an empty folder (e.g. a new move destination). It inherits the parent's
        sharing, exactly like a folder made in the Drive web UI."""
        clean = name.strip()
        if not clean or len(clean) > 255 or "/" in clean:
            raise ValueError("invalid folder name")
        result: dict[str, Any] = self._client.execute(
            self._service.files().create(
                body={
                    "name": clean,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [parent],
                },
                fields="id,name,parents",
                supportsAllDrives=True,
            )
        )
        return result
