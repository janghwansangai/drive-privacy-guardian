""" "모든 기록 삭제" (SPEC 5.1): local records, their keys, logs — optionally more.

Everything here is local; nothing on Google Drive is touched. Deleting a DB key makes any
leftover copy of that DB (backups, undeleted blocks) unreadable as well.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from dpg.core.auth.secret_store import SecretStore
from dpg.core.logging import get_logger
from dpg.core.paths import app_data_dir, log_dir
from dpg.core.vault.recovery import RECOVERY_KEY_NAME

log = get_logger("store")

VAULT_INDEX_KEY = "vault:index"


def remember_vault_password(secrets: SecretStore, archive_name: str, password: str) -> None:
    """Keychain entry for an archive + an index of names (the keychain cannot be listed)."""
    secrets.set(f"vault:{archive_name}", password)
    names = vault_names(secrets)
    if archive_name not in names:
        secrets.set(VAULT_INDEX_KEY, json.dumps([*names, archive_name], ensure_ascii=False))


def vault_names(secrets: SecretStore) -> list[str]:
    try:
        data = json.loads(secrets.get(VAULT_INDEX_KEY) or "[]")
    except ValueError:
        return []
    return [str(n) for n in data] if isinstance(data, list) else []


@dataclass
class WipeReport:
    databases: int = 0
    keys: int = 0
    logs: int = 0
    vault_passwords: int = 0
    recovery_key: bool = False  # the keychain copy; the paper copy still works


def wipe_local_records(secrets: SecretStore, *, include_vault_passwords: bool) -> WipeReport:
    """Delete audit/detection/change-history databases, their keys and the log files.

    Vault passwords are kept unless asked: without them the archives on Drive can no longer be
    opened by this computer's keychain (they may still be written down elsewhere).
    """
    report = WipeReport()
    data = app_data_dir() / "data"
    if data.is_dir():
        for db in sorted(data.glob("*.db")):
            secrets.delete(f"db-key-{db.stem}")
            report.keys += 1
            for suffix in ("", "-journal", "-wal", "-shm"):
                p = db.with_name(db.name + suffix)
                if p.exists():
                    p.unlink()
            report.databases += 1
    logs = log_dir()
    if logs.is_dir():
        for f in logs.iterdir():
            if f.is_file():
                try:
                    f.unlink()
                except OSError:  # Windows: the current log file is open — empty it instead
                    f.write_bytes(b"")
                report.logs += 1
    if include_vault_passwords:
        for name in vault_names(secrets):
            secrets.delete(f"vault:{name}")
            report.vault_passwords += 1
        secrets.delete(VAULT_INDEX_KEY)
        if secrets.get(RECOVERY_KEY_NAME):
            secrets.delete(RECOVERY_KEY_NAME)
            report.recovery_key = True
    log.info(
        "local records wiped dbs=%s logs=%s vault=%s",
        report.databases,
        report.logs,
        report.vault_passwords,
    )
    return report
