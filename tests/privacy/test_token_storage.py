"""Phase 1 gate (SPEC 7): tokens and the client secret exist nowhere except the keychain.

Runs the full CLI flow (import → login → upgrade → refresh check → logout) against FakeGoogle,
then searches the app data folder, every temp file written during the test, and all console
output for every secret the fake issued.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import pytest

from dpg.cli.main import main
from dpg.core.auth import AuthManager
from dpg.core.auth.secret_store import KEY_CLIENT, KEY_TOKEN
from dpg.core.detect.leakscan import scan_paths
from dpg.core.net_guard import global_guard
from tests.fakes.fake_google_auth import FakeGoogle, MemorySecretStore

pytestmark = pytest.mark.enable_socket

_MAX_SCAN_BYTES = 5 * 1024 * 1024


def _files_written_since(root: Path, since: float, exclude: Path) -> list[Path]:
    found: list[Path] = []
    exclude = exclude.resolve()
    for dirpath, _dirs, files in os.walk(root.resolve(), onerror=lambda e: None):
        for name in files:
            p = Path(dirpath) / name
            try:
                st = p.stat()
            except OSError:
                continue
            if st.st_mtime >= since and st.st_size <= _MAX_SCAN_BYTES and exclude not in p.parents:
                found.append(p)
    return found


def test_secrets_only_in_keychain(
    isolated_app_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    started = time.time() - 1
    google = FakeGoogle()
    store = MemorySecretStore()

    def factory() -> AuthManager:
        return AuthManager(store, http_factory=google.http, open_browser=google.browser)

    # The user's downloaded client JSON lives outside the app folder; it is theirs to delete.
    download = tmp_path / "downloads" / "client_secret_x.json"
    download.parent.mkdir()
    download.write_text(google.client_json(), encoding="utf-8")

    output = ""
    try:
        for argv in (
            ["client", "import", str(download)],
            ["login", "--level", "audit"],
            ["login", "--level", "detect"],
            ["status", "--check"],
        ):
            assert main(argv, manager_factory=factory) == 0, argv
            captured = capsys.readouterr()
            output += captured.out + captured.err

        # While logged in, the keychain (and only the keychain) holds the refresh token.
        assert KEY_TOKEN in store.data
        assert KEY_CLIENT in store.data
        assert main(["logout"], manager_factory=factory) == 0
        captured = capsys.readouterr()
        output += captured.out + captured.err
    finally:
        global_guard().uninstall()

    secrets_ = google.all_secrets()
    assert len(secrets_) >= 6  # client secret, 2 codes, 2 refresh, several access tokens

    # 1) console output
    for s in secrets_:
        assert s not in output

    # 2) app data folder (logs etc.) + every temp file written during the test,
    #    excluding the user's own downloaded JSON
    candidates = _files_written_since(isolated_app_home, started, exclude=download.parent)
    candidates += _files_written_since(
        Path(tempfile.gettempdir()), started, exclude=download.parent
    )
    candidates = [p for p in set(candidates) if p != download.resolve()]
    assert any(p.suffix == ".log" for p in candidates), "expected the CLI to write a log"
    for path in candidates:
        data = path.read_bytes()
        for s in secrets_:
            assert s.encode() not in data, f"secret found in {path}"
    # Pattern scan (catches token-shaped strings, not just this run's values) on the app folder.
    # Temp files are only searched for exact values: other tests leave fake client JSONs there.
    report = scan_paths([isolated_app_home])
    token_hits = {
        p: c for p, c in report.hits.items() if {"oauth_token", "oauth_client_secret"} & set(c)
    }
    assert token_hits == {}

    # 3) nothing written into the app folder except logs
    written = [
        p.relative_to(isolated_app_home) for p in isolated_app_home.rglob("*") if p.is_file()
    ]
    assert all(p.parts[0] == "logs" for p in written), written

    if os.name == "posix":
        assert isolated_app_home.stat().st_mode & 0o777 == 0o700

    # 4) after logout the token is gone from the keychain; only the client remains
    assert set(store.data) == {KEY_CLIENT}
    assert all(key in (KEY_CLIENT, KEY_TOKEN) for key, _ in store.history)
