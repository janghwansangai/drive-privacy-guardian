"""Read-only Drive API access: listing, permissions, pagination, backoff (SPEC 6.1).

This module only ever issues read requests. Every write goes through `dpg.core.actions`
(Phase 5). Field lists follow the official reference (V3–V5, DECISIONS.md).
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import google.auth.exceptions
import httplib2
from googleapiclient.errors import HttpError

from dpg.core.auth.errors import AuthError, InsufficientScope, NetworkError, ReauthRequired
from dpg.core.auth.manager import is_invalid_grant
from dpg.core.logging import get_logger

log = get_logger("drive")

FOLDER_MIME = "application/vnd.google-apps.folder"

PERMISSION_FIELDS = (
    "id,type,role,emailAddress,domain,allowFileDiscovery,view,inheritedPermissionsDisabled,"
    "deleted,expirationTime"
)
FILE_FIELDS = (
    "id,name,mimeType,size,md5Checksum,parents,driveId,trashed,modifiedTime,owners(emailAddress,me),ownedByMe,"
    "shared,writersCanShare,copyRequiresWriterPermission,inheritedPermissionsDisabled,"
    "hasAugmentedPermissions,downloadRestrictions,capabilities(canShare,canListChildren),"
    f"permissions({PERMISSION_FIELDS})"
)
LIST_FIELDS = f"nextPageToken,incompleteSearch,files({FILE_FIELDS})"
PERMISSION_LIST_FIELDS = (
    f"nextPageToken,permissions({PERMISSION_FIELDS},"
    "permissionDetails(permissionType,role,inherited,inheritedFrom))"
)

# Archives this app uploads: 보관_2026-09-26_7f3a9c2e.7z (4-hex tags: before the recovery key).
VAULT_NAME_RE = re.compile(r"^보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})\.(7z|zip)$")

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRY_403_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded"})
SCOPE_403_REASONS = frozenset({"insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"})


class DriveHttpError(Exception):
    """A non-retryable per-request API error (the caller decides what it means for an item)."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"HTTP {status} {reason}")
        self.status = status
        self.reason = reason


def http_reason(exc: HttpError) -> str:
    try:
        body = json.loads(exc.content.decode("utf-8"))
        err = body.get("error", {})
        for item in err.get("errors", []) or []:
            if item.get("reason"):
                return str(item["reason"])
        for detail in err.get("details", []) or []:
            if isinstance(detail, dict) and detail.get("reason"):
                return str(detail["reason"])
        return str(err.get("status", "unknown"))
    except (ValueError, AttributeError, UnicodeDecodeError):
        return "unknown"


@dataclass(frozen=True)
class Page:
    items: list[dict[str, Any]]
    next_token: str | None
    incomplete: bool


class DriveClient:
    def __init__(
        self,
        service: Any,
        *,
        max_retries: int = 6,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._service = service
        self._max_retries = max_retries
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 — jitter, not security
        self.retries = 0  # observable for tests / progress UI

    # -- plumbing -------------------------------------------------------------------------------

    @property
    def service(self) -> Any:
        """The underlying API service. Only `dpg.core.actions.writer` may issue writes on it."""
        return self._service

    def execute(self, request: Any) -> Any:
        """Execute with the shared retry/backoff and error mapping."""
        return self._execute(request)

    def _execute(self, request: Any) -> Any:
        attempt = 0
        while True:
            try:
                return request.execute(num_retries=0)
            except HttpError as exc:
                status = int(exc.resp.status)
                reason = http_reason(exc)
                retryable = status in RETRY_STATUSES or (
                    status == 403 and reason in RETRY_403_REASONS
                )
                if status == 403 and reason in SCOPE_403_REASONS:
                    raise InsufficientScope() from None
                if status == 401:
                    raise ReauthRequired() from None
                if not retryable or attempt >= self._max_retries:
                    raise DriveHttpError(status, reason) from None
            except google.auth.exceptions.RefreshError as exc:
                if is_invalid_grant(exc):
                    raise ReauthRequired() from None
                raise AuthError("로그인 정보를 갱신하지 못했습니다.") from None
            except (OSError, httplib2.HttpLib2Error, google.auth.exceptions.TransportError):
                if attempt >= self._max_retries:
                    raise NetworkError() from None
            # exponential backoff with full jitter, capped at 32 s
            delay = self._rng.uniform(0, min(32.0, 2.0**attempt))
            attempt += 1
            self.retries += 1
            log.info("retry %s after %.1fs", attempt, delay)
            self._sleep(delay)

    # -- reads ----------------------------------------------------------------------------------

    def about_email(self) -> str | None:
        body = self._execute(self._service.about().get(fields="user(emailAddress)"))
        email = body.get("user", {}).get("emailAddress")
        return str(email) if email else None

    def list_files_page(
        self,
        *,
        q: str,
        page_token: str | None,
        drive_id: str | None = None,
        page_size: int = 1000,
    ) -> Page:
        kwargs: dict[str, Any] = dict(
            q=q,
            pageSize=page_size,
            pageToken=page_token,
            fields=LIST_FIELDS,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        if drive_id is not None:
            kwargs.update(corpora="drive", driveId=drive_id)
        else:
            kwargs.update(corpora="user")
        body = self._execute(self._service.files().list(**kwargs))
        return Page(
            list(body.get("files", [])),
            body.get("nextPageToken"),
            bool(body.get("incompleteSearch", False)),
        )

    def list_ids(self, *, q: str, drive_id: str | None = None) -> set[str]:
        ids: set[str] = set()
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = dict(
                q=q,
                pageSize=1000,
                pageToken=token,
                fields="nextPageToken,files(id)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            if drive_id is not None:
                kwargs.update(corpora="drive", driveId=drive_id)
            body = self._execute(self._service.files().list(**kwargs))
            ids.update(f["id"] for f in body.get("files", []))
            token = body.get("nextPageToken")
            if not token:
                return ids

    def get_file(self, file_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._execute(
            self._service.files().get(fileId=file_id, fields=FILE_FIELDS, supportsAllDrives=True)
        )
        return result

    def list_permissions(self, file_id: str) -> list[dict[str, Any]]:
        perms: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            body = self._execute(
                self._service.permissions().list(
                    fileId=file_id,
                    pageSize=100,
                    pageToken=token,
                    fields=PERMISSION_LIST_FIELDS,
                    supportsAllDrives=True,
                )
            )
            perms.extend(body.get("permissions", []))
            token = body.get("nextPageToken")
            if not token:
                return perms

    def download(self, file_id: str, max_bytes: int) -> bytes:
        """Binary content (files.get alt=media) into memory. Caller checks `size` first."""
        data = self._execute(
            self._service.files().get_media(fileId=file_id, supportsAllDrives=True)
        )
        if not isinstance(data, bytes) or len(data) > max_bytes:
            raise DriveHttpError(413, "tooLarge")
        return data

    def export(self, file_id: str, mime_type: str) -> bytes:
        """Google Docs/Sheets/Slides export (server limit 10 MB, V7)."""
        data = self._execute(self._service.files().export(fileId=file_id, mimeType=mime_type))
        if not isinstance(data, bytes):
            raise DriveHttpError(500, "unexpectedExport")
        return data

    def list_child_names(self, folder_id: str) -> set[str]:
        """Names of the (non-trashed) items directly inside a folder."""
        names: set[str] = set()
        token: str | None = None
        safe = folder_id.replace("\\", "").replace("'", "")
        while True:
            body = self._execute(
                self._service.files().list(
                    q=f"'{safe}' in parents and trashed = false",
                    pageSize=1000,
                    pageToken=token,
                    fields="nextPageToken,files(name)",
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                    corpora="allDrives",
                )
            )
            names.update(str(f.get("name", "")) for f in body.get("files", []))
            token = body.get("nextPageToken")
            if not token:
                return names

    # -- changes (Phase 7: incremental audit, V-checked 2026-09-26) ------------------------------

    def start_page_token(self, drive_id: str | None = None) -> str:
        kwargs: dict[str, Any] = dict(supportsAllDrives=True)
        if drive_id is not None:
            kwargs["driveId"] = drive_id
        body = self._execute(self._service.changes().getStartPageToken(**kwargs))
        return str(body["startPageToken"])

    def list_changes(
        self, token: str, drive_id: str | None = None
    ) -> tuple[list[dict[str, Any]], str]:
        """All changes since `token` and the token to use next time.

        Raises DriveHttpError (400/404/410) when the token is no longer valid — the caller then
        falls back to a full audit.
        """
        changes: list[dict[str, Any]] = []
        page: str | None = token
        while True:
            kwargs: dict[str, Any] = dict(
                pageToken=page,
                pageSize=1000,
                includeRemoved=True,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                spaces="drive",
                fields=f"nextPageToken,newStartPageToken,changes(fileId,removed,file({FILE_FIELDS}))",
            )
            if drive_id is not None:
                kwargs["driveId"] = drive_id
            body = self._execute(self._service.changes().list(**kwargs))
            changes.extend(body.get("changes", []))
            if body.get("newStartPageToken"):
                return changes, str(body["newStartPageToken"])
            page = body.get("nextPageToken")
            if not page:
                raise DriveHttpError(500, "noStartPageToken")

    def list_shared_drives(self) -> Iterator[dict[str, Any]]:
        token: str | None = None
        while True:
            body = self._execute(
                self._service.drives().list(
                    pageSize=100, pageToken=token, fields="nextPageToken,drives(id,name)"
                )
            )
            yield from body.get("drives", [])
            token = body.get("nextPageToken")
            if not token:
                return


def build_drive_service(http: Any) -> Any:
    """Real Drive v3 service over an already-authorized, guarded http object.

    Uses the discovery document bundled with google-api-python-client (no network fetch).
    """
    from googleapiclient.discovery import build

    return build("drive", "v3", http=http, cache_discovery=False, static_discovery=True)
