"""`--selftest`: prove a (frozen) build has everything it needs, without any network use.

Used by the release workflow right after PyInstaller and by users who want to check an
installation ("Drive Privacy Guardian --selftest"). Prints one line per check; exit code 0 only
if every check passes. No Google account, keychain entry or file on disk is touched.
"""

from __future__ import annotations

import os
from collections.abc import Callable

Check = tuple[str, Callable[[], str]]


def _net_guard() -> str:
    from dpg.core.net_guard import BlockedConnectionError, global_guard
    from dpg.core.net_guard.http import GuardedHttp

    guard = global_guard()
    guard.install()
    if not guard.probe_blocks("example.com"):
        raise AssertionError("socket layer did not block a non-Google host")
    try:
        GuardedHttp().request("https://example.com/")
    except BlockedConnectionError:
        return "외부 호스트 차단됨 (소켓·HTTP 두 계층)"
    raise AssertionError("HTTP layer did not block a non-Google host")


def _discovery() -> str:
    from dpg.core.drive.client import build_drive_service
    from dpg.core.net_guard.http import GuardedHttp

    service = build_drive_service(GuardedHttp())
    service.files()
    service.changes()
    return "Drive v3 (내장 문서)"


def _crypto() -> str:
    from dpg.core.store.crypto import ColumnCipher

    cipher = ColumnCipher(os.urandom(32))
    if cipher.decrypt(cipher.encrypt({"a": 1}, "x"), "x") != {"a": 1}:
        raise AssertionError("AES-GCM round trip failed")
    return "AES-GCM"


def _archive() -> str:
    from dpg.core.vault import archive

    for fmt in archive.ArchiveFormat:
        blob = archive.create({"t.txt": b"ok"}, "Aa1-selftest", fmt)
        if archive.open_archive(blob, "Aa1-selftest") != {"t.txt": b"ok"}:
            raise AssertionError(f"{fmt} round trip failed")
    return "7z AES-256 · AES-ZIP"


def _extractors() -> str:
    import olefile  # noqa: F401  (HWP)
    import openpyxl  # noqa: F401
    import pypdf  # noqa: F401
    from docx import Document  # noqa: F401

    from dpg.core.extract import plan_for

    plan_for("text/plain", "a.txt")
    return "PDF·DOCX·XLSX·HWP"


def _keyring() -> str:
    import keyring

    from dpg.core.auth.secret_store import is_secure_backend

    backend = keyring.get_keyring()
    name = type(backend).__module__
    if not is_secure_backend(backend):
        raise AssertionError(f"no OS keychain backend ({name})")
    return name.rsplit(".", 1)[-1]


def _qt() -> str:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QLabel

    app = QApplication.instance() or QApplication([])
    label = QLabel("자가 진단")
    label.show()
    app.processEvents()
    label.close()
    import sys

    if "PySide6.QtNetwork" in sys.modules:
        raise AssertionError("QtNetwork must not be loaded (network guard bypass)")
    return "PySide6 위젯"


CHECKS: list[Check] = [
    ("네트워크 가드", _net_guard),
    ("구글 API 문서", _discovery),
    ("DB 암호화", _crypto),
    ("보관 파일 암호화", _archive),
    ("문서 읽기", _extractors),
    ("OS 보안 저장소", _keyring),
    ("화면(Qt)", _qt),
]


def run(print_fn: Callable[[str], None] = print, *, skip: set[str] | None = None) -> int:
    from dpg import __version__

    print_fn(f"개인정보 보안관 (Drive Privacy Guardian) {__version__} 자가 진단")
    failed = 0
    for name, fn in CHECKS:
        if skip and name in skip:
            print_fn(f"  - {name}: 건너뜀")
            continue
        try:
            print_fn(f"  ✓ {name}: {fn()}")
        except Exception as exc:  # noqa: BLE001 — report every failure, never crash
            failed += 1
            print_fn(f"  ✗ {name}: {type(exc).__name__}: {exc}")
    print_fn("결과: 정상" if not failed else f"결과: 실패 {failed}개")
    return 1 if failed else 0
