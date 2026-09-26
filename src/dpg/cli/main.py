"""`dpg` command-line entry point (development and testing).

Phase 1: client import/show/remove, login, logout, status.
Phase 2: audit, drives (read-only).
Phase 4: detect (audit + personal-data scan, read-only).
Phase 6: vault open (decrypt an archive, offline).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from dpg import __version__
from dpg.cli import audit_cmd, vault_cmd
from dpg.core.auth import AccessLevel, AuthError, AuthManager
from dpg.core.auth.client import MAX_CLIENT_JSON_BYTES
from dpg.core.auth.errors import NoClientConfigured
from dpg.core.auth.scopes import LEVEL_EXPLAIN_KO, LEVEL_LABEL_KO, parse_level
from dpg.core.logging import configure_logging
from dpg.core.net_guard import global_guard
from dpg.core.paths import app_data_dir, ensure_private_dir, log_dir

ManagerFactory = Callable[[], AuthManager]


def default_manager() -> AuthManager:
    from dpg.core.auth.secret_store import KeyringSecretStore

    return AuthManager(KeyringSecretStore())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dpg", description="Drive Privacy Guardian (개발용 CLI)")
    parser.add_argument("--version", action="version", version=f"dpg {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("netpolicy", help="허용된 네트워크 호스트 목록을 출력합니다")

    client = sub.add_parser("client", help="OAuth 클라이언트 설정")
    client_sub = client.add_subparsers(dest="client_command", required=True)
    imp = client_sub.add_parser("import", help="클라이언트 JSON을 불러와 키체인에 저장합니다")
    imp.add_argument("path", type=Path)
    imp.add_argument("--school", action="store_true", help="학교 관리자에게 받은 파일(B 방식)")
    client_sub.add_parser("show", help="설정된 클라이언트를 표시합니다")
    client_sub.add_parser("remove", help="클라이언트와 로그인 정보를 삭제합니다")

    login = sub.add_parser("login", help="구글 계정으로 로그인합니다")
    login.add_argument("--level", default="audit", choices=[lv.name.lower() for lv in AccessLevel])
    login.add_argument(
        "--no-browser", action="store_true", help="브라우저를 자동으로 열지 않습니다"
    )
    login.add_argument("--timeout", type=float, default=600.0)

    sub.add_parser("logout", help="로그아웃하고 토큰을 철회합니다")
    status = sub.add_parser("status", help="로그인 상태를 표시합니다")
    status.add_argument("--check", action="store_true", help="구글에 실제로 접속해 확인합니다")
    audit_cmd.add_parsers(sub)
    vault_cmd.add_parsers(sub)
    return parser


def _out(msg: str = "") -> None:
    print(msg)


def cmd_client(args: argparse.Namespace, manager: AuthManager) -> int:
    if args.client_command == "import":
        path: Path = args.path
        if not path.is_file():
            raise AuthError(f"파일을 찾을 수 없습니다: {path.name}")
        if path.stat().st_size > MAX_CLIENT_JSON_BYTES:
            raise AuthError(
                "파일이 너무 큽니다. 구글에서 받은 클라이언트 JSON 파일이 맞는지 확인해 주세요."
            )
        config = manager.import_client(path.read_bytes())
        source = "학교 관리자에게 받은" if args.school else "직접 만든"
        _out(f"✓ {source} OAuth 클라이언트를 키체인에 저장했습니다: {config.display_id}")
        _out("")
        _out("⚠ 보안을 위해 원본 JSON 파일을 삭제해 주세요 (휴지통도 비우기):")
        _out(f"   {path.resolve()}")
        _out("   앱은 이제 키체인에 저장된 정보만 사용합니다.")
        return 0
    if args.client_command == "show":
        shown = manager.client()
        if shown is None:
            _out("설정된 클라이언트가 없습니다.")
            return 1
        _out(f"클라이언트: {shown.display_id}")
        _out(f"프로젝트: {shown.project_id or '(알 수 없음)'}")
        return 0
    if args.client_command == "remove":
        result = manager.remove_client()
        _out("✓ 클라이언트 정보를 삭제했습니다.")
        _print_logout(result.had_token, result.revoked)
        return 0
    raise AssertionError(args.client_command)


def _print_logout(had_token: bool, revoked: bool) -> None:
    if not had_token:
        return
    if revoked:
        _out("✓ 구글에 저장된 앱 권한을 철회하고, 이 컴퓨터의 로그인 정보를 삭제했습니다.")
    else:
        _out("✓ 이 컴퓨터의 로그인 정보를 삭제했습니다.")
        _out(
            "⚠ 구글 쪽 권한 철회는 확인하지 못했습니다. "
            "아래 페이지에서 앱 연결을 직접 해제해 주세요:"
        )
        _out("   https://myaccount.google.com/connections")


def cmd_login(args: argparse.Namespace, manager: AuthManager) -> int:
    level = parse_level(args.level)
    if manager.client() is None:
        raise NoClientConfigured()
    current = manager.status()
    if current.level is not None and current.level < level:
        _out(f"이 기능은 추가 권한을 요청합니다: {LEVEL_LABEL_KO[level]}")
    _out(f"요청 권한: {LEVEL_LABEL_KO[level]}")
    _out(f"  {LEVEL_EXPLAIN_KO[level]}")
    _out("")

    def show_url(url: str) -> None:
        _out("브라우저에서 구글 로그인을 진행해 주세요.")
        _out("브라우저가 열리지 않으면 아래 주소를 복사해 브라우저에 붙여 넣으세요:")
        _out(url)
        _out("")

    result = manager.login(
        level,
        on_url=show_url,
        timeout=args.timeout,
        open_browser=(lambda _url: False) if args.no_browser else None,
    )
    _out(f"✓ 로그인됨: {result.account or '(계정 확인 실패)'}")
    if result.level is not None:
        _out(f"  허용된 권한: {LEVEL_LABEL_KO[result.level]}")
    if result.warning:
        _out(f"⚠ {result.warning}")
        return 3
    return 0


def cmd_status(args: argparse.Namespace, manager: AuthManager) -> int:
    st = manager.status()
    _out(f"클라이언트: {st.client_display_id or '설정 안 됨'}")
    if not st.logged_in:
        _out("로그인: 안 됨")
        return 1
    _out(f"로그인: {st.account or '(계정 미확인)'}")
    if st.level is not None:
        _out(f"권한: {LEVEL_LABEL_KO[st.level]}")
    if args.check:
        account = manager.verify()
        _out(f"✓ 구글 드라이브 연결 확인 완료: {account or '(계정 미확인)'}")
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    manager_factory: ManagerFactory | None = None,
    service_factory: audit_cmd.ServiceFactory | None = None,
) -> int:
    # Principle 1: the guard is installed before any command runs.
    guard = global_guard()
    guard.install()

    args = build_parser().parse_args(argv)
    if args.command is None:
        build_parser().print_help()
        return 0
    if args.command == "netpolicy":
        policy = guard.policy
        for host in sorted(policy.exact_hosts):
            _out(host)
        for sfx in policy.suffixes:
            _out(f"*{sfx}")
        _out("127.0.0.1 (로그인 리디렉션 전용)")
        return 0

    ensure_private_dir(app_data_dir())
    configure_logging(ensure_private_dir(log_dir()))
    if args.command == "vault":
        return vault_cmd.cmd_vault(args)
    try:
        manager = (manager_factory or default_manager)()
        if args.command == "client":
            return cmd_client(args, manager)
        if args.command == "login":
            return cmd_login(args, manager)
        if args.command == "logout":
            result = manager.logout()
            if not result.had_token:
                _out("로그인되어 있지 않습니다.")
            _print_logout(result.had_token, result.revoked)
            return 0
        if args.command == "status":
            return cmd_status(args, manager)
        if args.command == "audit":
            return audit_cmd.cmd_audit(args, manager, service_factory)
        if args.command == "drives":
            return audit_cmd.cmd_drives(manager, service_factory)
        if args.command == "detect":
            return audit_cmd.cmd_detect(args, manager, service_factory)
    except AuthError as exc:
        print(f"✗ {exc.user_message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("✗ 취소되었습니다.", file=sys.stderr)
        return 130
    finally:
        configure_logging(None)
    raise AssertionError(args.command)


if __name__ == "__main__":
    sys.exit(main())
