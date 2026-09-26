"""Static server/account security checklist (SPEC 6.7, R5).

Pure data: the checklist screen makes no network calls. Links only open in the user's browser
when clicked. Details live in docs/SERVER_SECURITY_KO.md.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckItem:
    key: str  # stable id (saved locally when ticked)
    title: str
    how: str
    link: str | None = None


@dataclass(frozen=True)
class Section:
    title: str
    items: tuple[CheckItem, ...]


CHECKLIST: tuple[Section, ...] = (
    Section(
        "구글 계정",
        (
            CheckItem(
                "g-2sv",
                "2단계 인증 또는 패스키 사용",
                "구글 계정 → 보안 → '2단계 인증'과 '패스키'를 켭니다.",
                "https://myaccount.google.com/security",
            ),
            CheckItem(
                "g-apps",
                "연결된 타사 앱 정기 점검 (학기마다)",
                "구글 계정 → 보안 → '타사 앱 및 서비스'에서 쓰지 않는 앱의 액세스를 삭제합니다.",
                "https://myaccount.google.com/connections",
            ),
            CheckItem(
                "g-shared-drive",
                "업무 자료는 공유 드라이브에 보관",
                "개인 드라이브 대신 학교 공유 드라이브를 쓰면 담당자가 바뀌어도 자료가 남고 "
                "권한 관리가 쉬워집니다.",
            ),
            CheckItem(
                "g-handover",
                "전보·퇴직 시 소유권 이전",
                "개인 드라이브의 업무 파일은 후임자나 공유 드라이브로 옮기고, "
                "개인정보 파일은 보존 기한을 확인해 파기합니다.",
            ),
            CheckItem(
                "g-dlp",
                "학교 관리자에게 Workspace DLP(데이터 손실 방지) 규칙 요청",
                "관리 콘솔의 DLP 규칙으로 주민등록번호 등이 든 파일의 외부 공유를 막을 수 있습니다 "
                "(에디션에 따라 제공 여부가 다름).",
            ),
            CheckItem(
                "g-cse",
                "(해당 시) 클라이언트 측 암호화(CSE) 검토",
                "Education Standard·Education Plus 에디션에서만 제공됩니다. "
                "관리자 설정이 필요하며, 암호화된 파일은 이 앱이 내용을 검사할 수 없습니다.",
            ),
        ),
    ),
    Section(
        "시놀로지 NAS",
        (
            CheckItem(
                "n-admin", "기본 admin 계정 비활성화", "새 관리자 계정을 만든 뒤 admin을 끕니다."
            ),
            CheckItem("n-2fa", "2단계 인증 켜기", "제어판 → 보안 → 계정에서 설정합니다."),
            CheckItem(
                "n-block", "자동 차단 켜기", "로그인 실패가 반복되는 IP를 자동으로 차단합니다."
            ),
            CheckItem("n-fw", "방화벽 켜기", "필요한 포트와 내부망만 허용합니다."),
            CheckItem(
                "n-vpn",
                "포트 포워딩 최소화, 외부 접속은 VPN(Tailscale 등)",
                "공유기에서 NAS 관리 포트를 인터넷에 직접 열지 않습니다.",
            ),
            CheckItem("n-enc", "공유 폴더 암호화", "개인정보가 있는 공유 폴더는 암호화합니다."),
            CheckItem(
                "n-snap",
                "스냅샷 (가능하면 변경 불가 스냅샷)",
                "랜섬웨어에 대비해 정기 스냅샷을 만듭니다.",
            ),
            CheckItem(
                "n-321",
                "오프라인 외장 백업 (3-2-1 원칙)",
                "사본 3개, 매체 2종, 1개는 분리 보관합니다.",
            ),
            CheckItem(
                "n-restore", "정기 복원 시험", "백업에서 실제로 파일을 되살려 보는 시험을 합니다."
            ),
        ),
    ),
    Section(
        "웹호스팅 (cPanel)",
        (
            CheckItem(
                "w-public",
                "공개 폴더에 개인정보 파일 두지 않기",
                "public_html 아래의 명단·신청서 파일을 확인해 지웁니다.",
            ),
            CheckItem(
                "w-index",
                "디렉터리 목록 차단",
                "cPanel → Directory Privacy/Indexes에서 목록 표시를 끕니다.",
            ),
            CheckItem(
                "w-admin",
                "관리자 페이지 접근 제한",
                "관리자 주소에 IP 제한이나 추가 비밀번호를 겁니다.",
            ),
            CheckItem("w-2fa", "cPanel 2단계 인증", "Security → Two-Factor Authentication."),
            CheckItem("w-ssl", "SSL(https) 적용", "모든 페이지를 https로만 제공합니다."),
            CheckItem("w-backup", "백업 확인", "호스팅 백업 주기와 복원 방법을 확인합니다."),
        ),
    ),
)


def all_keys() -> set[str]:
    return {i.key for s in CHECKLIST for i in s.items}
