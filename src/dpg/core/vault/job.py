"""Encrypted archiving workflow (SPEC 6.5 steps 2–7).

Step 1 (restrict the originals) is a normal permission-change plan (`RESTRICT_ALL`) run through
the action executor first. Then, all in memory:

    collect (download / export) → create archive → verify (decrypt + SHA-256 per file)
    → upload under a neutral name → download again + SHA-256 → only then allow trashing.

The trash plan can only be built from a result whose both verifications passed, and each
original still needs individual approval in the UI. Nothing is ever deleted permanently.
"""

from __future__ import annotations

import datetime as dt
import mimetypes
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from dpg.core.actions.model import ActionKind, Change, Op, Plan, Skip
from dpg.core.actions.writer import DriveWriter
from dpg.core.audit.model import FileAudit, ItemStatus
from dpg.core.drive.client import DriveClient, DriveHttpError
from dpg.core.logging import get_logger
from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveFormat

log = get_logger("vault")

MAX_TOTAL_BYTES = 1024**3  # everything is held in memory: keep one archive under 1 GB
MAX_FILE_BYTES = 500 * 1024**2
ARCHIVE_MIME = {
    ArchiveFormat.SEVEN_ZIP: "application/x-7z-compressed",
    ArchiveFormat.AES_ZIP: "application/zip",
}

# Google Workspace types → (export MIME, extension). Office formats keep the document usable.
GOOGLE_EXPORT = {
    "application/vnd.google-apps.document": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".docx",
    ),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xlsx",
    ),
    "application/vnd.google-apps.presentation": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".pptx",
    ),
    "application/vnd.google-apps.drawing": ("application/pdf", ".pdf"),
}


class ArchiveCancelled(Exception):
    pass


class ArchiveFailed(Exception):
    """A step failed; the message is Korean and safe to show (no file contents)."""


@dataclass
class ArchiveResult:
    name: str
    fmt: ArchiveFormat
    members: dict[str, str] = field(default_factory=dict)  # original file id -> member name
    skipped: list[Skip] = field(default_factory=list)
    sha256: str | None = None
    size: int = 0
    verified: bool = False  # the archive decrypts to exactly the originals
    uploaded_id: str | None = None
    upload_verified: bool = False  # the copy on Drive is byte-identical to what we built

    @property
    def safe_to_trash(self) -> bool:
        return self.verified and self.upload_verified and bool(self.members)


@dataclass(frozen=True)
class ArchiveProgress:
    step: str  # Korean
    done: int
    total: int


def member_name(item: FileAudit) -> str:
    """The file name inside the archive (Google documents get their export extension)."""
    if item.mime_type in GOOGLE_EXPORT:
        ext = GOOGLE_EXPORT[item.mime_type][1]
        return item.name if item.name.lower().endswith(ext) else item.name + ext
    return item.name


class ArchiveJob:
    def __init__(
        self,
        client: DriveClient,
        *,
        on_progress: Callable[[ArchiveProgress], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.writer = DriveWriter(client)
        self.on_progress = on_progress
        self.cancel = cancel

    def _tick(self, step: str, done: int, total: int) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise ArchiveCancelled()
        if self.on_progress is not None:
            self.on_progress(ArchiveProgress(step, done, total))

    # -- step 2 ---------------------------------------------------------------------------------

    def collect(self, items: list[FileAudit], result: ArchiveResult) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        wanted: list[FileAudit] = []
        for a in items:
            if a.is_folder:
                result.skipped.append(Skip(a.file_id, "폴더는 보관하지 않음(안의 파일을 선택)"))
            elif a.status is not ItemStatus.OK:
                result.skipped.append(Skip(a.file_id, "공유 정보를 확인하지 못함"))
            elif a.mime_type.startswith("application/vnd.google-apps.") and (
                a.mime_type not in GOOGLE_EXPORT
            ):
                result.skipped.append(Skip(a.file_id, "이 구글 형식은 내보낼 수 없음"))
            elif a.size is not None and a.size > MAX_FILE_BYTES:
                result.skipped.append(Skip(a.file_id, "파일이 너무 큼(500MB 초과)"))
            else:
                wanted.append(a)
        names = archive.unique_names([member_name(a) for a in wanted])
        total = 0
        for i, (a, name) in enumerate(zip(wanted, names, strict=True)):
            self._tick("내려받는 중", i, len(wanted))
            try:
                if a.mime_type in GOOGLE_EXPORT:
                    data = self.client.export(a.file_id, GOOGLE_EXPORT[a.mime_type][0])
                else:
                    data = self.client.download(a.file_id, MAX_FILE_BYTES)
            except DriveHttpError as exc:
                reason = (
                    "내보내기 한도(10MB) 초과"
                    if exc.reason == "exportSizeLimitExceeded"
                    else "다운로드가 금지된 파일"
                    if exc.status == 403
                    else f"받기 실패({exc.status})"
                )
                result.skipped.append(Skip(a.file_id, reason))
                continue
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ArchiveFailed(
                    "한 번에 보관할 수 있는 크기(1GB)를 넘었습니다. 나눠서 보관하세요."
                )
            files[name] = data
            result.members[a.file_id] = name
        self._tick("내려받기 완료", len(wanted), len(wanted))
        return files

    # -- steps 3–6 ------------------------------------------------------------------------------

    def run(
        self,
        items: list[FileAudit],
        password: str,
        fmt: ArchiveFormat,
        upload_parent: str,
        today: dt.date | None = None,
        name: str | None = None,
    ) -> ArchiveResult:
        """`name` lets the caller pick the archive name first (its tag salts a recovery-key
        password); by default a fresh neutral name is generated."""
        result = ArchiveResult(
            name or archive.archive_name(fmt, today, [member_name(i) for i in items]), fmt
        )
        originals = self.collect(items, result)
        if not originals:
            raise ArchiveFailed("보관할 수 있는 파일이 없습니다.")
        self._tick("암호화하는 중", 0, 1)
        blob = archive.create(originals, password, fmt)
        result.sha256, result.size = archive.sha256(blob), len(blob)
        self._tick("검증하는 중(복호화 후 비교)", 0, 1)
        check = archive.verify(blob, password, originals)
        result.verified = check.ok
        if not check.ok:
            raise ArchiveFailed("만든 보관 파일을 풀어 비교했더니 원본과 달라 중단했습니다.")
        del originals
        self._tick("올리는 중", 0, 1)
        try:
            meta = self.writer.upload(result.name, upload_parent, blob, ARCHIVE_MIME[fmt])
        except DriveHttpError as exc:
            raise ArchiveFailed(f"업로드 실패({exc.status}). 원본은 그대로입니다.") from None
        result.uploaded_id = str(meta["id"])
        self._tick("올린 파일 확인 중", 0, 1)
        try:
            back = self.client.download(result.uploaded_id, len(blob) + 1)
        except DriveHttpError:
            back = b""
        result.upload_verified = archive.sha256(back) == result.sha256
        log.info(
            "archive done members=%s verified=%s upload_verified=%s",
            len(result.members),
            result.verified,
            result.upload_verified,
        )
        return result


def trash_plan(result: ArchiveResult, approved: list[str], by_id: dict[str, FileAudit]) -> Plan:
    """SPEC 6.5-7: only after both verifications, only individually approved originals."""
    if not result.safe_to_trash:
        raise ArchiveFailed("검증이 끝나지 않아 원본을 정리할 수 없습니다.")
    plan = Plan(ActionKind.TRASH)
    for fid in approved:
        if fid not in result.members:
            plan.skipped.append(Skip(fid, "이 보관 파일에 들어 있지 않음"))
            continue
        a = by_id.get(fid)
        if a is not None and not a.owned_by_me:
            plan.skipped.append(Skip(fid, "내 소유가 아니라 휴지통으로 옮기지 않음"))
            continue
        plan.changes.append(
            Change(
                fid,
                Op.TRASH,
                None,
                {"trashed": False},
                {"trashed": True},
                f"휴지통으로 이동 (보관 파일 {result.name}에 검증된 사본 있음, "
                "30일 안에 복원 가능)",
            )
        )
    return plan


# -- unpack on Drive (restore) ------------------------------------------------------------------


@dataclass
class RestoreResult:
    archive_id: str
    archive_name: str
    parent: str
    uploaded: dict[str, str] = field(default_factory=dict)  # file name on Drive -> new file id
    renamed: dict[str, str] = field(default_factory=dict)  # member name -> name used (clash)
    verified: bool = False  # every uploaded file re-downloaded and SHA-256 matched

    @property
    def safe_to_trash_archive(self) -> bool:
        return self.verified and bool(self.uploaded)


def _restore_name(name: str, taken: set[str]) -> str:
    base = name.rsplit("/", 1)[-1] or "이름없음"
    if base not in taken:
        return base
    stem, dot, ext = base.rpartition(".")
    n = 1
    while True:
        cand = f"{stem} (복원{n if n > 1 else ''}).{ext}" if dot and stem else f"{base} (복원{n})"
        if cand not in taken:
            return cand
        n += 1


class RestoreJob:
    """Download an archive into memory, decrypt it, and put the files back in the archive's
    folder on Drive. Each upload is verified by SHA-256 before the archive may be trashed."""

    def __init__(
        self,
        client: DriveClient,
        *,
        on_progress: Callable[[ArchiveProgress], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.writer = DriveWriter(client)
        self.on_progress = on_progress
        self.cancel = cancel

    def _tick(self, step: str, done: int, total: int) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise ArchiveCancelled()
        if self.on_progress is not None:
            self.on_progress(ArchiveProgress(step, done, total))

    def run(self, archive_id: str, archive_name: str, password: str, parent: str) -> RestoreResult:
        result = RestoreResult(archive_id, archive_name, parent)
        self._tick("보관 파일 받는 중(메모리에만)", 0, 1)
        blob = self.client.download(archive_id, archive.MAX_ARCHIVE_BYTES)
        try:
            files = archive.open_archive(blob, password)
        except archive.WrongPassword:
            raise ArchiveFailed("비밀번호가 틀렸거나 파일이 손상되었습니다.") from None
        except archive.ArchiveError as exc:
            raise ArchiveFailed(str(exc)) from None
        del blob
        taken = self.client.list_child_names(parent)
        verified = True
        for i, (member, data) in enumerate(files.items()):
            self._tick("풀어서 원래 폴더에 올리는 중", i, len(files))
            name = _restore_name(member, taken)
            taken.add(name)
            if name != member:
                result.renamed[member] = name
            mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
            try:
                meta = self.writer.upload(name, parent, data, mime)
            except DriveHttpError as exc:
                raise ArchiveFailed(
                    f"'{name}' 올리기 실패({exc.status}). 보관 파일은 그대로 두었습니다."
                ) from None
            fid = str(meta["id"])
            result.uploaded[name] = fid
            try:
                back = self.client.download(fid, len(data) + 1)
            except DriveHttpError:
                back = b""
            verified = verified and archive.sha256(back) == archive.sha256(data)
        result.verified = verified
        self._tick("완료", len(files), len(files))
        log.info("restore done files=%s verified=%s", len(result.uploaded), verified)
        return result


def archive_trash_plan(result: RestoreResult) -> Plan:
    """After a verified restore, the (now redundant) archive goes to the trash — undoable."""
    if not result.safe_to_trash_archive:
        raise ArchiveFailed("푼 파일 확인이 끝나지 않아 보관 파일을 그대로 두었습니다.")
    plan = Plan(ActionKind.TRASH)
    plan.changes.append(
        Change(
            result.archive_id,
            Op.TRASH,
            None,
            {"trashed": False},
            {"trashed": True},
            f"보관 파일 {result.archive_name} 휴지통으로 이동 (파일 {len(result.uploaded)}개를 "
            "원래 폴더에 풀어 확인함, 30일 안에 복원 가능)",
        )
    )
    return plan
