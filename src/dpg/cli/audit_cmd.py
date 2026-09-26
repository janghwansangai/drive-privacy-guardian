"""`dpg audit` and `dpg drives` (Phase 2, read-only)."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dpg.core.audit.model import EXPOSURE_LABEL_KO, Exposure
from dpg.core.audit.report import EXPORT_WARNING_KO, write_report
from dpg.core.audit.runner import AuditCancelled, AuditResult, AuditRunner, AuditScope, Progress
from dpg.core.auth import AccessLevel, AuthError, AuthManager
from dpg.core.auth.errors import InsufficientScope
from dpg.core.auth.scopes import LEVEL_EXPLAIN_KO
from dpg.core.detect.runner import DetectCancelled, DetectProgress, DetectRunner
from dpg.core.drive.client import DriveClient, DriveHttpError, build_drive_service
from dpg.core.policy import DETECT_STATUS_LABEL_KO, DetectStatus, FileDetection, Level, recommend
from dpg.core.store.audit_store import AuditStore

ServiceFactory = Callable[[AuthManager], Any]

PHASE_KO = {
    "public": "공개 링크 파일 확인 중",
    "list": "파일 목록 수집 중",
    "perms": "공유 설정 확인 중",
    "analyze": "분석 중",
}


def default_service(manager: AuthManager) -> Any:
    return build_drive_service(manager.authorized_http(AccessLevel.AUDIT))


def add_parsers(sub: Any) -> None:
    audit = sub.add_parser("audit", help="공유 권한을 읽기 전용으로 감사합니다")
    audit.add_argument(
        "--scope",
        default="mine",
        help="mine(내 소유) | shared(나에게 공유됨) | drive:<ID> | folder:<ID>",
    )
    audit.add_argument("--out", type=Path, help="CSV 보고서 저장 경로")
    audit.add_argument(
        "--internal-domain",
        action="append",
        default=[],
        help="내부로 볼 도메인 (여러 번 지정 가능, 예: school.go.kr)",
    )
    audit.add_argument(
        "--no-mask", action="store_true", help="보고서에 파일명·이메일을 가리지 않고 그대로 씁니다"
    )
    audit.add_argument(
        "--restart", action="store_true", help="중단된 감사를 이어가지 않고 처음부터 다시 합니다"
    )
    sub.add_parser("drives", help="접근 가능한 공유 드라이브 목록")

    detect = sub.add_parser("detect", help="권한 감사 + 개인정보 탐지 (읽기 전용)")
    detect.add_argument("--scope", default="mine", help="mine | shared | drive:<ID> | folder:<ID>")
    detect.add_argument("--out", type=Path, help="보고서 저장 경로 (.xlsx 또는 .csv)")
    detect.add_argument("--internal-domain", action="append", default=[])
    detect.add_argument("--no-mask", action="store_true")
    detect.add_argument("--restart", action="store_true")


def _run(runner: AuditRunner, store: AuditStore, scope: AuditScope, restart: bool) -> AuditResult:
    """Resume an interrupted audit, else re-check only changes, else a full audit."""
    if not restart and store.resumable_scan(scope.key) is None:
        inc = runner.run_incremental(scope)
        if inc is not None:
            print(f"(지난 검사 이후 바뀐 항목 {len(inc.changed):,}개만 다시 확인)", file=sys.stderr)
            return inc
    return runner.run(scope, resume=not restart)


def _print_progress(p: Progress) -> None:
    label = PHASE_KO.get(p.phase, p.phase)
    detail = ""
    if p.phase == "list":
        detail = f" {p.listed:,}개"
    elif p.phase == "perms" and p.perms_total:
        detail = f" {p.perms_done:,}/{p.perms_total:,}"
    retry = f" (재시도 {p.retries}회)" if p.retries else ""
    print(f"\r… {label}{detail}{retry}      ", end="", file=sys.stderr, flush=True)


def _summary(result: AuditResult) -> None:
    c = result.counts
    print(file=sys.stderr)
    print(
        f"✓ 감사 완료: {result.scope.label_ko} {c['total']:,}개"
        + (" (중단된 감사를 이어서 완료)" if result.resumed else "")
    )
    order = [
        Exposure.LINK_EDIT,
        Exposure.LINK_VIEW,
        Exposure.EXTERNAL,
        Exposure.DOMAIN,
        Exposure.RESTRICTED,
    ]
    print(
        "  "
        + " / ".join(f"{EXPOSURE_LABEL_KO[e]} {c[f'exposure:{e.name.lower()}']:,}" for e in order)
    )
    print(
        f"  권한 부족/정보 불완전 {c['status:insufficient']:,} / 조회 실패 {c['status:failed']:,}"
        f" / 노출도 알 수 없음 {c['exposure:unknown']:,}"
    )
    if c["exposure:unknown"]:
        print("  ※ '알 수 없음'은 안전하다는 뜻이 아닙니다. 소유자에게 확인이 필요합니다.")
    if result.incomplete_search:
        print("⚠ 구글이 일부 검색 결과를 생략했다고 알려 왔습니다. 범위를 좁혀 다시 감사해 주세요.")


def cmd_audit(
    args: argparse.Namespace, manager: AuthManager, service_factory: ServiceFactory | None = None
) -> int:
    try:
        scope = AuditScope.parse(args.scope)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    account = manager.verify()  # refreshes the token; fails early with a clear message
    if account is None:
        raise AuthError("계정을 확인하지 못했습니다. `dpg status --check`로 연결을 확인해 주세요.")
    service = (service_factory or default_service)(manager)
    store = AuditStore.open_for(account, manager.secret_store)
    try:
        runner = AuditRunner(
            DriveClient(service),
            store,
            account=account,
            internal_domains=tuple(args.internal_domain),
            on_progress=_print_progress,
        )
        try:
            result = _run(runner, store, scope, args.restart)
        except (AuditCancelled, KeyboardInterrupt):
            print(file=sys.stderr)
            print(
                "✗ 감사를 중단했습니다. 같은 명령을 다시 실행하면 이어서 진행합니다.",
                file=sys.stderr,
            )
            return 130
        except DriveHttpError as exc:
            print(file=sys.stderr)
            print(
                f"✗ 구글 드라이브 오류로 감사를 멈췄습니다 (HTTP {exc.status}, {exc.reason}). "
                "같은 명령을 다시 실행하면 이어서 진행합니다.",
                file=sys.stderr,
            )
            return 4
        _summary(result)
        return _write_report(args, result) if args.out else 0
    finally:
        store.close()


def _write_report(
    args: argparse.Namespace,
    result: AuditResult,
    detections: dict[str, FileDetection] | None = None,
) -> int:
    print(f"⚠ {EXPORT_WARNING_KO}")
    if args.no_mask:
        print("⚠ --no-mask: 파일명과 이메일이 가려지지 않은 채 저장됩니다.")
    try:
        n = write_report(args.out, result.items, mask=not args.no_mask, detections=detections)
    except PermissionError:
        print(
            "✗ 보고서를 저장할 권한이 없습니다. "
            "macOS가 터미널의 바탕화면·문서·다운로드 폴더 접근을 막았을 수 있습니다.\n"
            "  방법 1) 시스템 설정 → 개인정보 보호 및 보안 → 파일 및 폴더 → 터미널에서 허용\n"
            "  방법 2) 현재 폴더에 저장: --out dpg_report.csv\n"
            "  (감사 결과는 이미 저장되어 있습니다)",
            file=sys.stderr,
        )
        return 5
    except OSError as exc:
        print(
            f"✗ 보고서를 저장하지 못했습니다 ({type(exc).__name__}). "
            "다른 경로로 다시 시도해 주세요.",
            file=sys.stderr,
        )
        return 5
    print(f"✓ 보고서 저장: {args.out.resolve()} ({n:,}행)")
    return 0


def _print_detect_progress(p: DetectProgress) -> None:
    retry = f" (재시도 {p.retries}회)" if p.retries else ""
    print(
        f"\r… 개인정보 탐지 중 {p.done:,}/{p.total:,}{retry}      ",
        end="",
        file=sys.stderr,
        flush=True,
    )


def cmd_detect(
    args: argparse.Namespace, manager: AuthManager, service_factory: ServiceFactory | None = None
) -> int:
    try:
        scope = AuditScope.parse(args.scope)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    try:
        manager.credentials(AccessLevel.DETECT)
    except InsufficientScope:
        print("✗ 개인정보 탐지는 파일 내용을 읽는 권한이 추가로 필요합니다.", file=sys.stderr)
        print(f"  {LEVEL_EXPLAIN_KO[AccessLevel.DETECT]}", file=sys.stderr)
        print(
            "  `dpg login --level detect`로 권한을 추가한 뒤 다시 실행해 주세요.", file=sys.stderr
        )
        return 3
    account = manager.verify()
    if account is None:
        raise AuthError("계정을 확인하지 못했습니다. `dpg status --check`로 연결을 확인해 주세요.")
    client = DriveClient((service_factory or default_service)(manager))
    store = AuditStore.open_for(account, manager.secret_store)
    try:
        runner = AuditRunner(
            client,
            store,
            account=account,
            internal_domains=tuple(args.internal_domain),
            on_progress=_print_progress,
        )
        try:
            result = _run(runner, store, scope, args.restart)
            detections = DetectRunner(client, store, on_progress=_print_detect_progress).run(
                result.scan_id, result.items
            )
        except (AuditCancelled, DetectCancelled, KeyboardInterrupt):
            print(file=sys.stderr)
            print("✗ 중단했습니다. 같은 명령을 다시 실행하면 이어서 진행합니다.", file=sys.stderr)
            return 130
        except DriveHttpError as exc:
            print(file=sys.stderr)
            print(
                f"✗ 구글 드라이브 오류로 멈췄습니다 (HTTP {exc.status}, {exc.reason}). "
                "같은 명령을 다시 실행하면 이어서 진행합니다.",
                file=sys.stderr,
            )
            return 4
        _summary(result)
        c = Counter(d.status for d in detections.values())
        print(
            "  개인정보: "
            + " / ".join(f"{DETECT_STATUS_LABEL_KO[st]} {c[st]:,}" for st in DetectStatus)
        )
        urgent = sum(
            1
            for a in result.items
            if (recs := recommend(a, detections.get(a.file_id))) and recs[0].level >= Level.HIGH
        )
        if urgent:
            print(f"⚠ 즉시 조치가 권장되는 파일 {urgent:,}개 — 보고서의 '권장 조치'를 확인하세요.")
        if c[DetectStatus.UNSCANNABLE]:
            print("  ※ '검사 불가'는 안전하다는 뜻이 아닙니다(암호·스캔·크기 초과 등).")
        return _write_report(args, result, detections) if args.out else 0
    finally:
        store.close()


def cmd_drives(manager: AuthManager, service_factory: ServiceFactory | None = None) -> int:
    client = DriveClient((service_factory or default_service)(manager))
    found = False
    for d in client.list_shared_drives():
        found = True
        print(f"{d['id']}\t{d.get('name', '')}")
    if not found:
        print("접근 가능한 공유 드라이브가 없습니다.")
    return 0
