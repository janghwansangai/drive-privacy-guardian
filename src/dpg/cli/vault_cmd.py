"""`dpg vault open` — decrypt an archive made by this app (SPEC 6.5 "복호화 기능 내장").

Works offline. The password is read with a hidden prompt only: there is deliberately no
command-line option or environment variable for it (it would end up in shell history / ps).
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dpg.core.vault import archive

PasswordPrompt = Callable[[str], str]
MAX_INPUT_BYTES = archive.MAX_ARCHIVE_BYTES


def add_parsers(sub: Any) -> None:
    vault = sub.add_parser("vault", help="암호화 보관 파일")
    vsub = vault.add_subparsers(dest="vault_command", required=True)
    op = vsub.add_parser("open", help="보관 파일(.7z/.zip)을 풀어 폴더에 저장합니다 (오프라인)")
    op.add_argument("archive", type=Path, help="보관 파일 경로")
    op.add_argument("--out", type=Path, required=True, help="풀어 놓을 폴더 (없으면 만듦)")


def cmd_vault(args: argparse.Namespace, prompt: PasswordPrompt | None = None) -> int:
    path: Path = args.archive
    if not path.is_file():
        print("✗ 보관 파일을 찾을 수 없습니다.", file=sys.stderr)
        return 1
    if path.stat().st_size > MAX_INPUT_BYTES:
        print("✗ 파일이 너무 큽니다.", file=sys.stderr)
        return 1
    data = path.read_bytes()
    password = (prompt or getpass.getpass)("보관 파일 비밀번호(화면에 표시되지 않음): ")
    try:
        files = archive.open_archive(data, password)
    except archive.WrongPassword:
        print("✗ 비밀번호가 틀렸거나 파일이 손상되었습니다.", file=sys.stderr)
        return 1
    except archive.ArchiveError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    finally:
        del password
    written = archive.extract_to(files, args.out)
    print(f"✓ 파일 {len(written)}개를 풀었습니다: {args.out}")
    return 0
