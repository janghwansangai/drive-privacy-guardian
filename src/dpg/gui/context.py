"""Everything the GUI needs from the outside world, injectable for tests.

Dialogs go through `notify`/`confirm` so tests never block on a modal message box.
"""

from __future__ import annotations

import json
import os
import webbrowser
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import QDialog, QMessageBox, QWidget

from dpg.core.auth import AuthManager
from dpg.core.paths import app_data_dir, ensure_private_dir


@dataclass
class Prefs:
    """Non-secret preferences (secrets live only in the keychain)."""

    auto_logout_on_exit: bool = False  # SPEC 5.3: for shared/public PCs
    dry_run_mode: bool = False  # SPEC 6.2: stop after the pre-execution re-check
    internal_domains: list[str] = field(default_factory=list)
    retention_days: int = 30  # SPEC 5.1: audit records are deleted after this many days
    live_refresh: bool = True  # Phase 7: check Drive's change list every minute while open
    checklist_done: list[str] = field(default_factory=list)  # SPEC 6.7 ticked items
    recovery_fingerprint: str = ""  # non-secret id of the recovery key (D-074)

    @staticmethod
    def path() -> Path:
        return app_data_dir() / "prefs.json"

    @classmethod
    def load(cls) -> Prefs:
        try:
            data = json.loads(cls.path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        return cls(
            auto_logout_on_exit=bool(data.get("auto_logout_on_exit", False)),
            dry_run_mode=bool(data.get("dry_run_mode", False)),
            internal_domains=[str(d) for d in data.get("internal_domains", [])][:20],
            retention_days=_clamp_days(data.get("retention_days", 30)),
            live_refresh=bool(data.get("live_refresh", True)),
            checklist_done=[str(k) for k in data.get("checklist_done", [])][:200],
            recovery_fingerprint=str(data.get("recovery_fingerprint", ""))[:16],
        )

    def save(self) -> None:
        path = self.path()
        ensure_private_dir(path.parent)
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, ensure_ascii=False, indent=2)


RETENTION_CHOICES = (7, 30, 90, 180, 365)


def _clamp_days(value: object) -> int:
    try:
        days = int(str(value))
    except ValueError:
        return 30
    return min(max(days, 1), 365)


def _notify(parent: QWidget | None, title: str, text: str, error: bool = False) -> None:
    box = QMessageBox.critical if error else QMessageBox.information
    box(parent, title, text)


def _confirm(parent: QWidget | None, title: str, text: str, yes: str, no: str) -> bool:
    box = QMessageBox(QMessageBox.Icon.Question, title, text, parent=parent)
    yes_btn = box.addButton(yes, QMessageBox.ButtonRole.AcceptRole)
    box.addButton(no, QMessageBox.ButtonRole.RejectRole)
    box.exec()
    return box.clickedButton() is yes_btn


@dataclass
class AppContext:
    manager_factory: Callable[[], AuthManager]
    service_factory: Callable[[AuthManager], Any]
    open_url: Callable[[str], bool] = webbrowser.open
    notify: Callable[..., None] = _notify
    confirm: Callable[..., bool] = _confirm
    show_dialog: Callable[[QDialog], object] = lambda dialog: dialog.exec()
    prefs: Prefs = field(default_factory=Prefs.load)

    _manager: AuthManager | None = None

    @property
    def manager(self) -> AuthManager:
        if self._manager is None:
            self._manager = self.manager_factory()
        return self._manager
