"""SQLite store for audit scans (SPEC 5.1).

- One DB per account, named by a hash of the account (no e-mail in file names).
- Class-D columns (file ID, MIME kind, status, exposure, score) are plaintext; everything that
  may identify a person (file names, owner/share e-mails) is in the AES-GCM `secret` column.
- Checkpoints contain only IDs and page tokens.
- `secure_delete` is on so deleted rows are overwritten; scans older than the retention period
  are purged when the store opens (default 30 days).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dpg.core.auth.secret_store import SecretStore
from dpg.core.logging import get_logger
from dpg.core.paths import app_data_dir, ensure_private_dir
from dpg.core.store.crypto import (
    ColumnCipher,
    DecryptError,
    account_key_id,
    create_key,
    delete_key,
    load_key,
)

log = get_logger("store")

SCHEMA_VERSION = 3
DEFAULT_RETENTION_DAYS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
    scan_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    status      TEXT NOT NULL,
    checkpoint  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS items (
    scan_id     INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    file_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    drive_id    TEXT,
    parent_id   TEXT,
    perm_source TEXT NOT NULL,
    status      TEXT,
    exposure    INTEGER,
    risk        INTEGER,
    error_code  TEXT,
    secret      BLOB NOT NULL,
    PRIMARY KEY (scan_id, file_id)
);
-- Phase 4: detection results. Only kind / count / confidence / positional location (class D);
-- detected values are never stored (principle 2).
CREATE TABLE IF NOT EXISTS detections (
    scan_id     INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    file_id     TEXT NOT NULL,
    status      TEXT NOT NULL,
    reason      TEXT,
    error_code  TEXT,
    summary     TEXT NOT NULL,
    scanned_at  TEXT NOT NULL,
    PRIMARY KEY (scan_id, file_id)
);
-- Phase 5: permission-change runs. Before/after states hold e-mails -> encrypted column.
CREATE TABLE IF NOT EXISTS action_runs (
    run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    dry_run     INTEGER NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS action_changes (
    run_id      INTEGER NOT NULL REFERENCES action_runs(run_id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    file_id     TEXT NOT NULL,
    op          TEXT NOT NULL,
    perm_id     TEXT,
    state       TEXT NOT NULL,
    error       TEXT,
    secret      BLOB NOT NULL,
    PRIMARY KEY (run_id, seq)
);
-- "이 파일 제외" (rule='*') / "이 규칙 이 폴더 제외" (target=folder, rule=kind)
CREATE TABLE IF NOT EXISTS exclusions (
    target_id   TEXT NOT NULL,
    rule        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (target_id, rule)
);
"""


def _iso(t: dt.datetime) -> str:
    # "Z" suffix: two adjacent "+00:00" timestamps in a SQLite record would otherwise run
    # together into a long hyphenated number (a false positive for the leak scanner).
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _iso(dt.datetime.now(dt.UTC))


@dataclass
class ScanRow:
    scan_id: int
    scope: str
    status: str
    checkpoint: dict[str, Any]
    started_at: str


@dataclass
class ItemRow:
    file_id: str
    kind: str  # "item" | "drive_root"
    drive_id: str | None
    parent_id: str | None
    perm_source: str
    meta: dict[str, Any]
    perms: list[dict[str, Any]] | None
    status: str | None = None
    exposure: int | None = None
    risk: int | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class TreeRow:
    """An item's plaintext columns (no names, no e-mails): enough to walk the folder tree."""

    file_id: str
    kind: str
    parent_id: str | None
    perm_source: str
    drive_id: str | None


def db_path_for(account: str) -> Path:
    return app_data_dir() / "data" / f"{account_key_id(account)}.db"


class AuditStore:
    def __init__(
        self, path: Path, cipher: ColumnCipher, retention_days: int = DEFAULT_RETENTION_DAYS
    ) -> None:
        ensure_private_dir(path.parent)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        if os.name == "posix":
            os.chmod(path, 0o600)
        self.path = path
        self._cipher = cipher
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript(_SCHEMA)
        self._db.execute(
            "INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        self.purge_older_than(retention_days)

    @classmethod
    def open_for(
        cls, account: str, secrets: SecretStore, retention_days: int = DEFAULT_RETENTION_DAYS
    ) -> AuditStore:
        path = db_path_for(account)
        key = load_key(secrets, account)
        if key is None:
            if path.exists():
                # Key lost (keychain reset): the old DB is unreadable by design. Start over.
                log.info("db key missing; discarding unreadable database")
                path.unlink()
            key = create_key(secrets, account)
        return cls(path, ColumnCipher(key), retention_days)

    def close(self) -> None:
        self._db.close()

    # -- scans ----------------------------------------------------------------------------------

    def new_scan(self, scope: str, checkpoint: dict[str, Any]) -> int:
        cur = self._db.execute(
            "INSERT INTO scans(scope, status, checkpoint, started_at) VALUES (?, 'running', ?, ?)",
            (scope, json.dumps(checkpoint), _now()),
        )
        if cur.lastrowid is None:
            raise RuntimeError("scan row was not created")
        return int(cur.lastrowid)

    def resumable_scan(self, scope: str) -> ScanRow | None:
        row = self._db.execute(
            "SELECT scan_id, scope, status, checkpoint, started_at FROM scans "
            "WHERE scope = ? AND status IN ('running', 'failed', 'cancelled') "
            "ORDER BY scan_id DESC LIMIT 1",
            (scope,),
        ).fetchone()
        if row is None:
            return None
        return ScanRow(row[0], row[1], row[2], json.loads(row[3]), row[4])

    def set_status(self, scan_id: int, status: str, error: str | None = None) -> None:
        finished = _now() if status in ("done", "failed", "cancelled") else None
        self._db.execute(
            "UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE scan_id = ?",
            (status, error, finished, scan_id),
        )

    def save_checkpoint(self, scan_id: int, checkpoint: dict[str, Any]) -> None:
        self._db.execute(
            "UPDATE scans SET checkpoint = ?, status = 'running' WHERE scan_id = ?",
            (json.dumps(checkpoint), scan_id),
        )

    def latest_done_scan(self, scope: str | None = None) -> ScanRow | None:
        sql = "SELECT scan_id, scope, status, checkpoint, started_at FROM scans WHERE status='done'"
        params: tuple[Any, ...] = ()
        if scope is not None:
            sql += " AND scope = ?"
            params = (scope,)
        row = self._db.execute(sql + " ORDER BY scan_id DESC LIMIT 1", params).fetchone()
        return None if row is None else ScanRow(row[0], row[1], row[2], json.loads(row[3]), row[4])

    def set_changes_token(self, scan_id: int, token: str) -> None:
        """Advance a finished scan's change token without touching its status."""
        row = self._db.execute(
            "SELECT checkpoint FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row is None:
            return
        cp = json.loads(row[0])
        cp["changes_token"] = token
        self._db.execute("UPDATE scans SET checkpoint=? WHERE scan_id=?", (json.dumps(cp), scan_id))

    def copy_scan(self, src: int, scope: str, checkpoint: dict[str, Any]) -> int:
        """New scan starting from a finished one (incremental audit). Item secrets are
        re-encrypted because the scan id is part of their AAD; detections are copied as is."""
        new = self.new_scan(scope, checkpoint)
        for batch in self.item_batches(src):  # a batch at a time: a big drive never sits in memory
            self.save_items(new, batch)
        self._db.execute(
            "INSERT INTO detections(scan_id, file_id, status, reason, error_code, summary,"
            " scanned_at) SELECT ?, file_id, status, reason, error_code, summary, scanned_at"
            " FROM detections WHERE scan_id = ?",
            (new, src),
        )
        return new

    def delete_items(self, scan_id: int, file_ids: Iterable[str]) -> None:
        ids = [(scan_id, f) for f in file_ids]
        self._db.executemany("DELETE FROM items WHERE scan_id=? AND file_id=?", ids)
        self._db.executemany("DELETE FROM detections WHERE scan_id=? AND file_id=?", ids)

    def delete_detections(self, scan_id: int, file_ids: Iterable[str]) -> None:
        self._db.executemany(
            "DELETE FROM detections WHERE scan_id=? AND file_id=?",
            [(scan_id, f) for f in file_ids],
        )

    def delete_scans_before(self, scope: str, scan_id: int) -> int:
        """Drop this scope's earlier scans once a newer one is done. Only the latest result is
        ever read, and keeping every incremental copy would grow the file by the whole drive's
        size each time (a million-file drive: about 1 GB per copy)."""
        cur = self._db.execute(
            "DELETE FROM scans WHERE scope = ? AND scan_id < ?", (scope, scan_id)
        )
        return int(cur.rowcount)

    def purge_older_than(self, days: int) -> int:
        cutoff = _iso(dt.datetime.now(dt.UTC) - dt.timedelta(days=days))
        cur = self._db.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,))
        self._db.execute("DELETE FROM action_runs WHERE created_at < ?", (cutoff,))
        if cur.rowcount:
            self._db.execute("VACUUM")
        return int(cur.rowcount)

    # -- items ----------------------------------------------------------------------------------

    def _aad(self, scan_id: int, file_id: str) -> str:
        return f"{scan_id}:{file_id}"

    def save_items(
        self, scan_id: int, rows: Iterable[ItemRow], checkpoint: dict[str, Any] | None = None
    ) -> None:
        """Upsert items (and optionally the checkpoint) in one transaction."""
        self._db.execute("BEGIN")
        try:
            for r in rows:
                secret = self._cipher.encrypt(
                    {"meta": r.meta, "perms": r.perms}, self._aad(scan_id, r.file_id)
                )
                self._db.execute(
                    "INSERT INTO items(scan_id, file_id, kind, drive_id, parent_id, perm_source,"
                    " status, exposure, risk, error_code, secret)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(scan_id, file_id) DO UPDATE SET kind=excluded.kind,"
                    " drive_id=excluded.drive_id, parent_id=excluded.parent_id,"
                    " perm_source=excluded.perm_source, status=excluded.status,"
                    " exposure=excluded.exposure, risk=excluded.risk,"
                    " error_code=excluded.error_code, secret=excluded.secret",
                    (
                        scan_id,
                        r.file_id,
                        r.kind,
                        r.drive_id,
                        r.parent_id,
                        r.perm_source,
                        r.status,
                        r.exposure,
                        r.risk,
                        r.error_code,
                        secret,
                    ),
                )
            if checkpoint is not None:
                self._db.execute(
                    "UPDATE scans SET checkpoint = ? WHERE scan_id = ?",
                    (json.dumps(checkpoint), scan_id),
                )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def update_results(
        self, scan_id: int, results: Iterable[tuple[str, str, int | None, int | None, str | None]]
    ) -> None:
        """(file_id, status, exposure, risk, error_code) — plaintext class-D columns only."""
        self._db.execute("BEGIN")
        try:
            self._db.executemany(
                "UPDATE items SET status=?, exposure=?, risk=?, error_code=? "
                "WHERE scan_id=? AND file_id=?",
                [(s, e, r, c, scan_id, f) for f, s, e, r, c in results],
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def tree(self, scan_id: int) -> list[TreeRow]:
        """The plaintext columns only (no decryption): the shape of the drive, cheap even for a
        million items."""
        return [
            TreeRow(*row)
            for row in self._db.execute(
                "SELECT file_id, kind, parent_id, perm_source, drive_id FROM items"
                " WHERE scan_id = ? ORDER BY rowid",
                (scan_id,),
            )
        ]

    def get_items(self, scan_id: int, file_ids: Iterable[str]) -> list[ItemRow]:
        ids = sorted(set(file_ids))
        out: list[ItemRow] = []
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            marks = ",".join("?" * len(chunk))  # placeholders only: values are bound
            sql = (
                "SELECT file_id, kind, drive_id, parent_id, perm_source, status, exposure, risk,"  # noqa: S608 — "?" placeholders only
                " error_code, secret FROM items WHERE scan_id = ? AND file_id IN (" + marks + ")"
            )
            cur = self._db.execute(sql, (scan_id, *chunk))
            out.extend(self._decode(scan_id, cur.fetchall()))
        return out

    def item_batches(self, scan_id: int, size: int = 5000) -> Iterator[list[ItemRow]]:
        """All items, `size` at a time. Each batch is read completely before it is handed out,
        so the caller may write to the store between batches."""
        last = 0
        while True:
            rows = self._db.execute(
                "SELECT file_id, kind, drive_id, parent_id, perm_source, status, exposure, risk,"
                " error_code, secret, rowid FROM items WHERE scan_id = ? AND rowid > ?"
                " ORDER BY rowid LIMIT ?",
                (scan_id, last, size),
            ).fetchall()
            if not rows:
                return
            last = rows[-1][10]
            yield list(self._decode(scan_id, [r[:10] for r in rows]))

    def iter_items(self, scan_id: int) -> Iterator[ItemRow]:
        for batch in self.item_batches(scan_id):
            yield from batch

    def _decode(self, scan_id: int, rows: Iterable[Any]) -> Iterator[ItemRow]:
        for row in rows:
            try:
                data = self._cipher.decrypt(row[9], self._aad(scan_id, row[0]))
            except DecryptError:
                log.info("undecryptable item skipped")
                continue
            yield ItemRow(
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                data["meta"],
                data["perms"],
                row[5],
                row[6],
                row[7],
                row[8],
            )

    def count_items(self, scan_id: int) -> int:
        return int(
            self._db.execute("SELECT COUNT(*) FROM items WHERE scan_id = ?", (scan_id,)).fetchone()[
                0
            ]
        )

    # -- detections (Phase 4) ----------------------------------------------------------------

    def save_detection(
        self,
        scan_id: int,
        file_id: str,
        status: str,
        reason: str | None,
        error_code: str | None,
        summary: dict[str, Any],
    ) -> None:
        self._db.execute(
            "INSERT INTO detections(scan_id, file_id, status, reason, error_code, summary,"
            " scanned_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(scan_id, file_id) DO UPDATE SET"
            " status=excluded.status, reason=excluded.reason, error_code=excluded.error_code,"
            " summary=excluded.summary, scanned_at=excluded.scanned_at",
            (
                scan_id,
                file_id,
                status,
                reason,
                error_code,
                json.dumps(summary, ensure_ascii=False),
                _now(),
            ),
        )

    def load_detections(
        self, scan_id: int
    ) -> dict[str, tuple[str, str | None, str | None, dict[str, Any]]]:
        rows = self._db.execute(
            "SELECT file_id, status, reason, error_code, summary FROM detections WHERE scan_id=?",
            (scan_id,),
        )
        return {r[0]: (r[1], r[2], r[3], json.loads(r[4])) for r in rows}

    def add_exclusion(self, target_id: str, rule: str = "*") -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO exclusions VALUES (?, ?, ?)", (target_id, rule, _now())
        )

    def remove_exclusion(self, target_id: str, rule: str = "*") -> None:
        self._db.execute("DELETE FROM exclusions WHERE target_id=? AND rule=?", (target_id, rule))

    def exclusions(self) -> set[tuple[str, str]]:
        return {(r[0], r[1]) for r in self._db.execute("SELECT target_id, rule FROM exclusions")}

    # -- permission-change runs (Phase 5) -------------------------------------------------------

    def new_action_run(self, action: str, dry_run: bool) -> int:
        cur = self._db.execute(
            "INSERT INTO action_runs(action, dry_run, status, created_at) VALUES (?,?,?,?)",
            (action, int(dry_run), "running", _now()),
        )
        if cur.lastrowid is None:
            raise RuntimeError("action run row was not created")
        return int(cur.lastrowid)

    def finish_action_run(self, run_id: int, status: str) -> None:
        self._db.execute(
            "UPDATE action_runs SET status=?, finished_at=? WHERE run_id=?",
            (status, _now(), run_id),
        )

    def save_changes(self, run_id: int, changes: list[Any]) -> None:
        self._db.execute("BEGIN")
        try:
            for seq, c in enumerate(changes):
                secret = self._cipher.encrypt(
                    {"before": c.before, "after": c.after, "description": c.description},
                    f"action:{run_id}:{seq}",
                )
                self._db.execute(
                    "INSERT INTO action_changes VALUES (?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(run_id, seq) DO UPDATE SET state=excluded.state,"
                    " error=excluded.error, secret=excluded.secret",
                    (run_id, seq, c.file_id, c.op.value, c.perm_id, c.state.value, c.error, secret),
                )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def load_changes(self, run_id: int) -> list[Any]:
        from dpg.core.actions.model import Change, ChangeState, Op

        out = []
        for seq, file_id, op, perm_id, state, error, secret in self._db.execute(
            "SELECT seq, file_id, op, perm_id, state, error, secret FROM action_changes"
            " WHERE run_id=? ORDER BY seq",
            (run_id,),
        ):
            data = self._cipher.decrypt(secret, f"action:{run_id}:{seq}")
            out.append(
                Change(
                    file_id,
                    Op(op),
                    perm_id,
                    data["before"],
                    data["after"],
                    data["description"],
                    ChangeState(state),
                    error,
                )
            )
        return out

    def action_runs(self, limit: int = 50) -> list[tuple[int, str, bool, str, str]]:
        """(run_id, action, dry_run, status, created_at), newest first."""
        return [
            (r[0], r[1], bool(r[2]), r[3], r[4])
            for r in self._db.execute(
                "SELECT run_id, action, dry_run, status, created_at FROM action_runs"
                " ORDER BY run_id DESC LIMIT ?",
                (limit,),
            )
        ]

    def delete_all(self, secrets: SecretStore, account: str) -> None:
        """ "모든 기록 삭제": drop the DB file and its key (Phase 7 adds the UI)."""
        self.close()
        for suffix in ("", "-journal", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                p.unlink()
        delete_key(secrets, account)
