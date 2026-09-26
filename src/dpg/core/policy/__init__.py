"""Detection result model and recommended actions (SPEC 6.3 status classes, 6.4 policy).

Risk = sensitivity (detection) × exposure (sharing). The app only *recommends*; nothing here
changes a file.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

from dpg.core.audit.model import Exposure, FileAudit, ItemStatus
from dpg.core.detect.rules import HIGH_SENSITIVITY, Confidence, KindSummary
from dpg.core.extract.base import UnscannableReason


class DetectStatus(StrEnum):
    DETECTED = "detected"  # 탐지
    SUSPECT = "suspect"  # 의심 (사람 검토)
    NOT_FOUND = "not_found"  # 지원 범위 내에서 발견되지 않음
    UNSCANNABLE = "unscannable"  # 검사 불가
    FAILED = "failed"  # 처리 실패
    EXCLUDED = "excluded"  # 사용자가 제외


DETECT_STATUS_LABEL_KO = {
    DetectStatus.DETECTED: "탐지",
    DetectStatus.SUSPECT: "의심(검토 필요)",
    DetectStatus.NOT_FOUND: "지원 범위 내에서 발견되지 않음",
    DetectStatus.UNSCANNABLE: "검사 불가",
    DetectStatus.FAILED: "처리 실패",
    DetectStatus.EXCLUDED: "제외됨",
}


@dataclass
class FileDetection:
    file_id: str
    status: DetectStatus
    kinds: dict[str, KindSummary] = field(default_factory=dict)
    reason: UnscannableReason | None = None
    error_code: str | None = None
    partial: bool = False  # part of the file could not be read (never "clean")

    @property
    def high_sensitivity(self) -> bool:
        return any(
            k in HIGH_SENSITIVITY and s.confidence >= Confidence.MEDIUM
            for k, s in self.kinds.items()
        )

    @property
    def detected(self) -> bool:
        return self.status is DetectStatus.DETECTED


def status_for(kinds: dict[str, KindSummary]) -> DetectStatus:
    if any(s.confidence >= Confidence.MEDIUM for s in kinds.values()):
        return DetectStatus.DETECTED
    if kinds:
        return DetectStatus.SUSPECT
    return DetectStatus.NOT_FOUND


class Level(IntEnum):
    INFO = 0
    KEEP = 1  # 유지 권장
    REVIEW = 2  # 검토
    HIGH = 3  # 높음
    URGENT = 4  # 긴급


LEVEL_LABEL_KO = {
    Level.INFO: "",
    Level.KEEP: "유지",
    Level.REVIEW: "검토",
    Level.HIGH: "높음",
    Level.URGENT: "긴급",
}


@dataclass(frozen=True)
class Recommendation:
    level: Level
    text: str
    action: str | None = None  # machine key for Phase 5 (e.g. "remove_link")


OLD_DAYS = 365


def _age_days(modified: str | None, now: dt.datetime) -> int | None:
    if not modified:
        return None
    try:
        t = dt.datetime.fromisoformat(modified.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - t).days


def recommend(
    audit: FileAudit, det: FileDetection | None, now: dt.datetime | None = None
) -> list[Recommendation]:
    """All applicable recommendations, most severe first (SPEC 6.4 table)."""
    now = now or dt.datetime.now(dt.UTC)
    recs: list[Recommendation] = []
    link = audit.exposure in (Exposure.LINK_VIEW, Exposure.LINK_EDIT)
    if det is None:
        return recs
    roster = "student_roster" in det.kinds
    if det.detected and det.high_sensitivity and link:
        recs.append(Recommendation(Level.URGENT, "링크 공개 해제 (고위험 개인정보)", "remove_link"))
    elif det.detected and link:
        recs.append(Recommendation(Level.HIGH, "링크 공개 해제 권장", "remove_link"))
    if roster and audit.external_accounts:
        recs.append(Recommendation(Level.HIGH, "외부 계정 확인 후 제거", "remove_external"))
    elif det.detected and det.high_sensitivity and audit.exposure == Exposure.EXTERNAL:
        recs.append(Recommendation(Level.HIGH, "외부 공유 확인 후 제거", "remove_external"))
    if det.status in (DetectStatus.UNSCANNABLE, DetectStatus.FAILED) and link:
        recs.append(Recommendation(Level.REVIEW, "수동 검토 필요 (검사 불가 + 링크 공개)"))
    if det.detected and audit.exposure == Exposure.DOMAIN:
        recs.append(
            Recommendation(Level.REVIEW, "도메인 전체 공개 범위 축소 검토", "restrict_domain")
        )
    if det.detected and audit.exposure is None and audit.status is not ItemStatus.OK:
        recs.append(Recommendation(Level.REVIEW, "소유자에게 공유 상태 확인 요청"))
    age = _age_days(audit.modified_time, now)
    if det.detected and age is not None and age > OLD_DAYS:
        recs.append(
            Recommendation(
                Level.REVIEW,
                "오래된 개인정보 파일: 암호화 보관 또는 파기 검토 (학교 보존 기준 확인)",
                "archive",
            )
        )
    if det.detected and audit.exposure == Exposure.RESTRICTED and audit.internal_accounts:
        recs.append(
            Recommendation(
                Level.KEEP, "유지 권장(정상 협업), 다운로드 제한 검토", "restrict_download"
            )
        )
    if det.detected and audit.exposure == Exposure.RESTRICTED and not audit.internal_accounts:
        # Nobody else can open it today — still personal data, so say what to do with it.
        recs.append(
            Recommendation(
                Level.KEEP,
                "나만 볼 수 있음(공유 안 됨) — 유지. 업무가 끝났으면 암호화 보관 권장",
                "archive",
            )
        )
    if det.status in (DetectStatus.UNSCANNABLE, DetectStatus.FAILED) and not link:
        recs.append(Recommendation(Level.INFO, "내용을 읽지 못함: 직접 열어 개인정보 여부 확인"))
    if det.status is DetectStatus.SUSPECT:
        recs.append(Recommendation(Level.INFO, "의심 항목: 내용 확인 필요"))
    return sorted(recs, key=lambda r: -r.level)
