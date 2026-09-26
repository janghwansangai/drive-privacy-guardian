"""Per-user application data locations (SPEC 5.1: user data folder, owner-only permissions)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_NAME = "Drive Privacy Guardian"
ENV_HOME = "DPG_HOME"  # override for tests and portable use


def app_data_dir() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override)
    platform = sys.platform  # plain variable: keeps every branch type-checked on every OS
    if platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    if platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "DrivePrivacyGuardian"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "drive-privacy-guardian"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` (and parents) and restrict it to the current user on POSIX."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def log_dir() -> Path:
    return app_data_dir() / "logs"
