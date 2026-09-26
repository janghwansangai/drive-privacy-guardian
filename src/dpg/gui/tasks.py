"""Run blocking work (login, audit) off the UI thread.

Error text shown to the user comes only from `user_message_for`, never from `str(exc)`,
which could carry data from a document or an API response.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QThread, Signal

from dpg.core.audit.runner import AuditCancelled
from dpg.core.auth import AuthError
from dpg.core.drive.client import DriveHttpError
from dpg.core.logging import get_logger

log = get_logger("gui")

ProgressFn = Callable[[Any], None]


class Task(QThread):
    succeeded = Signal(object)
    failed = Signal(object)
    progress = Signal(object)

    def __init__(self, fn: Callable[[ProgressFn], Any]) -> None:
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn(self.progress.emit)
        except BaseException as exc:
            if not isinstance(exc, (AuthError, AuditCancelled, DriveHttpError)):
                log.exception("background task failed")
            self.failed.emit(exc)
            return
        self.succeeded.emit(result)


def user_message_for(exc: BaseException) -> str:
    if isinstance(exc, AuthError):
        return exc.user_message
    if isinstance(exc, AuditCancelled):
        return "감사를 중단했습니다. 다시 시작하면 이어서 진행합니다."
    if isinstance(exc, DriveHttpError):
        return (
            f"구글 드라이브 오류로 멈췄습니다 (HTTP {exc.status}, {exc.reason}). "
            "다시 시작하면 이어서 진행합니다."
        )
    from dpg.core.vault.job import ArchiveCancelled, ArchiveFailed

    if isinstance(exc, ArchiveFailed):
        return str(exc)
    if isinstance(exc, ArchiveCancelled):
        return "중단했습니다. 원본과 보관 파일은 그대로입니다."
    if isinstance(exc, ValueError):
        return "입력값을 확인해 주세요."
    return (
        f"예상하지 못한 오류가 발생했습니다 ({type(exc).__name__}). "
        "문제가 계속되면 로그 파일과 함께 알려 주세요."
    )
