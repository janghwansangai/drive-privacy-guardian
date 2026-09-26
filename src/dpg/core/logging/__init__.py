"""Structured logging with a mandatory masking filter (SPEC 5.4).

Rules:
- Every handler attached by `configure_logging` carries `MaskingFilter`. Filters on *handlers*
  (not loggers) are used because logger-level filters do not see records propagated from
  child loggers.
- Log file IDs, never file names or document text.
- Exception text is rendered and masked inside the filter; tracebacks never include locals.
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dpg.core.detect.patterns import mask_text

__all__ = ["LOG_FILE_NAME", "MaskingFilter", "configure_logging", "get_logger"]

LOG_FILE_NAME = "dpg.log"
_ROOT = "dpg"


class MaskingFilter(logging.Filter):
    """Rewrites each record so that message, args, exception and stack text are masked."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a bad format string must not leak raw args
            message = f"<unformattable log message: {type(record.msg).__name__}>"
        record.msg = mask_text(message)
        record.args = None

        if record.exc_info:
            exc_text = "".join(traceback.format_exception(*record.exc_info))
            record.exc_text = mask_text(exc_text.rstrip("\n"))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = mask_text(record.exc_text)

        if record.stack_info:
            record.stack_info = mask_text(record.stack_info)
        return True


def _secure_create(path: Path) -> None:
    """Create the log file with owner-only permissions before the handler opens it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)


def configure_logging(
    log_dir: Path | None = None,
    level: int = logging.INFO,
    *,
    console: bool = False,
) -> logging.Logger:
    """Configure the `dpg` logger tree. Idempotent: previous dpg handlers are replaced."""
    logger = logging.getLogger(_ROOT)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handlers: list[logging.Handler] = []
    if log_dir is not None:
        path = log_dir / LOG_FILE_NAME
        _secure_create(path)
        handlers.append(
            RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        )
    if console:
        handlers.append(logging.StreamHandler(sys.stderr))

    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(MaskingFilter())
        logger.addHandler(handler)
    if not handlers:
        logger.addHandler(logging.NullHandler())
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child of the `dpg` logger (e.g. get_logger("audit") -> "dpg.audit")."""
    return logging.getLogger(f"{_ROOT}.{name}" if not name.startswith(_ROOT) else name)
