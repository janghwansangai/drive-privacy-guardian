"""SPEC 5.1 "모든 기록 삭제": local DBs, their keys and logs go; vault passwords only on request."""

from __future__ import annotations

from pathlib import Path

from dpg.core.logging import configure_logging, get_logger
from dpg.core.paths import ensure_private_dir, log_dir
from dpg.core.store.audit_store import AuditStore
from dpg.core.store.crypto import db_key_name
from dpg.core.store.wipe import remember_vault_password, vault_names, wipe_local_records
from tests.fakes.fake_google_auth import MemorySecretStore

ACCOUNTS = ("teacher@school.example", "other@school.example")


def _populate(secrets: MemorySecretStore) -> None:
    for acc in ACCOUNTS:
        store = AuditStore.open_for(acc, secrets)
        store.new_scan("mine", {"phase": "public"})
        store.close()
    configure_logging(ensure_private_dir(log_dir()))
    get_logger("test").info("hello")
    remember_vault_password(secrets, "보관_2026-09-26_ab12.7z", "Pw-1")
    remember_vault_password(secrets, "보관_2026-09-26_cd34.zip", "Pw-2")
    remember_vault_password(secrets, "보관_2026-09-26_ab12.7z", "Pw-1")  # no duplicate


def test_wipe_keeps_vault_passwords_by_default(isolated_app_home: Path) -> None:
    secrets = MemorySecretStore()
    _populate(secrets)
    assert vault_names(secrets) == ["보관_2026-09-26_ab12.7z", "보관_2026-09-26_cd34.zip"]
    report = wipe_local_records(secrets, include_vault_passwords=False)
    assert report.databases == 2
    assert not list((isolated_app_home / "data").glob("*.db*"))
    assert all(secrets.get(db_key_name(a)) is None for a in ACCOUNTS)
    assert not any(f.stat().st_size for f in log_dir().glob("*"))  # logs gone or emptied
    assert secrets.get("vault:보관_2026-09-26_ab12.7z") == "Pw-1"


def test_wipe_can_remove_vault_passwords(isolated_app_home: Path) -> None:
    secrets = MemorySecretStore()
    _populate(secrets)
    report = wipe_local_records(secrets, include_vault_passwords=True)
    assert report.vault_passwords == 2
    assert not any(k.startswith("vault:") for k in secrets.data)
    # a fresh store after wiping starts empty (new key, new DB)
    store = AuditStore.open_for(ACCOUNTS[0], secrets)
    assert store.latest_done_scan() is None
    store.close()
