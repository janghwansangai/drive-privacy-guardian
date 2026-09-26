"""Permission-change actions (SPEC 6.2): kinds, planned changes, states."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ActionKind(StrEnum):
    REMOVE_LINK = "remove_link"  # 링크 공개 해제 (제한됨으로)
    LINK_TO_VIEW = "link_to_view"  # 링크 권한 편집 → 보기
    REMOVE_EXTERNAL = "remove_external"  # 외부 계정 제거
    REMOVE_DOMAIN = "restrict_domain"  # 도메인 공개 해제
    EDITORS_TO_VIEWERS = "editors_to_viewers"  # 편집자 → 뷰어
    DISABLE_RESHARE = "disable_reshare"  # 편집자 재공유 금지
    RESTRICT_DOWNLOAD = "restrict_download"  # 뷰어·댓글 작성자 다운로드·인쇄·복사 제한
    RESTRICT_ALL = "restrict_all"  # 링크·도메인·외부 공유 모두 해제 (보관 전 단계, SPEC 6.5-1)
    MOVE = "move"  # 파일 정리: 폴더 이동 (SPEC 6.6)
    TRASH = "trash_original"  # 보관 검증 후 원본 휴지통 이동 (SPEC 6.5-7, 영구 삭제 없음)


# The sharing actions offered in the permission-change dialog (MOVE/TRASH have their own UI).
PERMISSION_ACTIONS = tuple(k for k in ActionKind if k not in ("move", "trash_original"))


# Wording follows Google Drive's own share dialog (공유 → 일반 액세스 / 사용자 / 설정 ⚙).
ACTION_LABEL_KO = {
    ActionKind.REMOVE_LINK: "일반 액세스: '링크가 있는 모든 사용자' → '제한됨'",
    ActionKind.LINK_TO_VIEW: "일반 액세스: 링크 사용자의 역할 '편집자' → '뷰어'",
    ActionKind.REMOVE_DOMAIN: "일반 액세스: 학교(도메인) 전체 공개 → '제한됨'",
    ActionKind.RESTRICT_ALL: "모두 '제한됨'으로 (링크·도메인 공개 해제 + 외부 사용자 액세스 권한 삭제)",  # noqa: E501 — user-facing Korean text
    ActionKind.REMOVE_EXTERNAL: "외부 사용자(학교 밖 계정) '액세스 권한 삭제'",
    ActionKind.EDITORS_TO_VIEWERS: "'편집자' 역할을 '뷰어'로 변경",
    ActionKind.DISABLE_RESHARE: "설정 ⚙ '편집자가 권한을 변경하고 공유할 수 있음' 끄기",
    ActionKind.RESTRICT_DOWNLOAD: "설정 ⚙ '뷰어 및 댓글 작성자에게 다운로드, 인쇄, 복사 옵션 표시' 끄기",  # noqa: E501 — user-facing Korean text
    ActionKind.MOVE: "폴더 이동 (정리)",
    ActionKind.TRASH: "원본 휴지통 이동 (보관 후)",
}

# Sections as they appear in Google's share dialog (for the change dialog's dropdown).
ACTION_SECTIONS_KO: tuple[tuple[str, tuple[ActionKind, ...]], ...] = (
    (
        "일반 액세스",
        (
            ActionKind.REMOVE_LINK,
            ActionKind.LINK_TO_VIEW,
            ActionKind.REMOVE_DOMAIN,
            ActionKind.RESTRICT_ALL,
        ),
    ),
    ("액세스 권한이 있는 사용자", (ActionKind.REMOVE_EXTERNAL, ActionKind.EDITORS_TO_VIEWERS)),
    ("설정 ⚙", (ActionKind.DISABLE_RESHARE, ActionKind.RESTRICT_DOWNLOAD)),
)

# Where the same switch is in Google Drive (공유 화면), shown under the dropdown.
ACTION_GOOGLE_HINT_KO = {
    ActionKind.REMOVE_LINK: "구글 드라이브: 공유 → 일반 액세스 → '제한됨' 선택과 같습니다.",
    ActionKind.LINK_TO_VIEW: "구글 드라이브: 공유 → 일반 액세스 → 오른쪽 역할을 '뷰어'로 바꾸는 것과 같습니다.",  # noqa: E501 — user-facing Korean text
    ActionKind.REMOVE_DOMAIN: "구글 드라이브: 공유 → 일반 액세스 → 학교 이름 대신 '제한됨' 선택과 같습니다.",  # noqa: E501 — user-facing Korean text
    ActionKind.RESTRICT_ALL: (
        "구글 드라이브: 일반 액세스를 '제한됨'으로 바꾸고, 학교 밖 사용자마다 "
        "역할 → '액세스 권한 삭제'를 누르는 것과 같습니다."
    ),
    ActionKind.REMOVE_EXTERNAL: (
        "구글 드라이브: 공유 → 액세스 권한이 있는 사용자 → 학교 밖 계정의 역할 → "
        "'액세스 권한 삭제'와 같습니다. 학교 계정은 그대로 둡니다."
    ),
    ActionKind.EDITORS_TO_VIEWERS: "구글 드라이브: 공유 → 사용자 옆 '편집자' → '뷰어' 선택과 같습니다.",  # noqa: E501 — user-facing Korean text
    ActionKind.DISABLE_RESHARE: "구글 드라이브: 공유 → 오른쪽 위 설정 ⚙ → 첫 번째 체크 해제와 같습니다.",  # noqa: E501 — user-facing Korean text
    ActionKind.RESTRICT_DOWNLOAD: "구글 드라이브: 공유 → 오른쪽 위 설정 ⚙ → 두 번째 체크 해제와 같습니다.",  # noqa: E501 — user-facing Korean text
}


class Op(StrEnum):
    DELETE_PERM = "delete_perm"
    UPDATE_PERM = "update_perm"
    UPDATE_FILE = "update_file"
    MOVE = "move"  # before/after: {"parent": folder id}
    TRASH = "trash"  # before {"trashed": False} → after {"trashed": True}; undo = restore


class ChangeState(StrEnum):
    PLANNED = "planned"
    CONFLICT = "conflict"  # changed since the plan was made — needs re-approval
    DRY_RUN_OK = "dry_run_ok"  # re-check passed; nothing written (dry run)
    DONE = "done"  # applied and verified
    FAILED = "failed"  # API refused or verification failed
    CANCELLED = "cancelled"  # user stopped the run before this change
    UNDONE = "undone"
    UNDO_FAILED = "undo_failed"
    NOT_UNDOABLE = "not_undoable"


STATE_LABEL_KO = {
    ChangeState.PLANNED: "계획됨",
    ChangeState.CONFLICT: "충돌 (계획 이후 바뀜 — 다시 확인 필요)",
    ChangeState.DRY_RUN_OK: "드라이런 통과 (실제 변경 없음)",
    ChangeState.DONE: "완료",
    ChangeState.FAILED: "실패",
    ChangeState.CANCELLED: "취소됨",
    ChangeState.UNDONE: "되돌림",
    ChangeState.UNDO_FAILED: "되돌리기 실패",
    ChangeState.NOT_UNDOABLE: "되돌릴 수 없음",
}


@dataclass
class Change:
    file_id: str
    op: Op
    perm_id: str | None
    before: dict[str, Any]  # permission resource subset, or file fields — may hold e-mails
    after: dict[str, Any] | None  # {"role": "reader"} / file fields; None for delete
    description: str  # Korean, for the preview (may name an account: never logged)
    state: ChangeState = ChangeState.PLANNED
    error: str | None = None


@dataclass(frozen=True)
class Skip:
    file_id: str
    reason: str  # Korean


@dataclass
class Plan:
    action: ActionKind
    changes: list[Change] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    folder_children: dict[str, int] = field(default_factory=dict)  # folder id -> items below

    @property
    def file_ids(self) -> list[str]:
        return list(dict.fromkeys(c.file_id for c in self.changes))

    @property
    def affected_accounts(self) -> int:
        """Distinct principals losing or changing access (anyone/domain count as one each)."""
        keys = {
            c.before.get("emailAddress") or c.before.get("domain") or c.before.get("type")
            for c in self.changes
            if c.op in (Op.DELETE_PERM, Op.UPDATE_PERM)
        }
        return len(keys)


@dataclass
class RunResult:
    run_id: int
    dry_run: bool
    changes: list[Change]

    def count(self, state: ChangeState) -> int:
        return sum(1 for c in self.changes if c.state is state)
