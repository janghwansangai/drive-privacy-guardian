"""Personal-data scan over audited files (SPEC 6.3). Read-only.

Per file: download/export into memory → extract → detect → keep only the summary
(kind, count, confidence, positions) → drop the bytes and text. Results are saved per file,
so an interrupted scan resumes where it stopped.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from dpg.core.audit.model import FileAudit
from dpg.core.detect.mask import masked_snippet
from dpg.core.detect.rules import (
    Confidence,
    KindSummary,
    detect_extracted,
    detect_filename,
    detect_table,
    detect_text_spans,
    summarize,
)
from dpg.core.drive.client import DriveClient, DriveHttpError
from dpg.core.extract import Plan, Unscannable, UnscannableReason, extract, plan_for
from dpg.core.extract.base import MAX_FILE_BYTES
from dpg.core.logging import get_logger
from dpg.core.policy import DetectStatus, FileDetection, status_for
from dpg.core.store.audit_store import AuditStore

log = get_logger("detect")


PARTIAL_KEY = "_partial"  # marker inside the stored summary: file read only in part


class DetectCancelled(Exception):
    pass


@dataclass(frozen=True)
class DetectProgress:
    done: int
    total: int
    retries: int = 0


def _summary_to_json(kinds: dict[str, KindSummary]) -> dict[str, dict[str, object]]:
    return {
        k: {"count": s.count, "confidence": int(s.confidence), "locations": s.locations}
        for k, s in kinds.items()
    }


def _summary_from_json(data: dict[str, dict[str, Any]]) -> dict[str, KindSummary]:
    return {
        k: KindSummary(
            int(v["count"]), Confidence(int(v["confidence"])), [str(x) for x in v["locations"]]
        )
        for k, v in data.items()
    }


def load_detections(store: AuditStore, scan_id: int) -> dict[str, FileDetection]:
    out: dict[str, FileDetection] = {}
    for fid, (status, reason, error, summary) in store.load_detections(scan_id).items():
        partial = summary.pop(PARTIAL_KEY, None) is not None
        out[fid] = FileDetection(
            fid,
            DetectStatus(status),
            _summary_from_json(summary),
            UnscannableReason(reason) if reason else None,
            error,
            partial,
        )
    return out


def _ancestors(item: FileAudit, by_id: dict[str, FileAudit]) -> Iterable[str]:
    seen: set[str] = set()
    cur = item.parent_id
    while cur and cur not in seen:
        seen.add(cur)
        yield cur
        parent = by_id.get(cur)
        cur = parent.parent_id if parent else None


def fetch_content(client: DriveClient, item: FileAudit, plan: Plan) -> bytes:
    """Download or export into memory; map Drive refusals to 검사 불가 reasons."""
    if plan.export_mime is not None:
        try:
            return client.export(item.file_id, plan.export_mime)
        except DriveHttpError as exc:
            if exc.reason == "exportSizeLimitExceeded":
                raise Unscannable(UnscannableReason.EXPORT_LIMIT) from None
            if exc.status == 403:
                raise Unscannable(UnscannableReason.NOT_DOWNLOADABLE) from None
            raise
    if item.size is not None and item.size > MAX_FILE_BYTES:
        raise Unscannable(UnscannableReason.TOO_LARGE)
    try:
        return client.download(item.file_id, MAX_FILE_BYTES)
    except DriveHttpError as exc:
        if exc.status == 413:
            raise Unscannable(UnscannableReason.TOO_LARGE) from None
        if exc.status == 403:
            raise Unscannable(UnscannableReason.NOT_DOWNLOADABLE) from None
        raise


class DetectRunner:
    def __init__(
        self,
        client: DriveClient,
        store: AuditStore,
        *,
        on_progress: Callable[[DetectProgress], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.on_progress = on_progress
        self.cancel = cancel

    def scan_one(self, item: FileAudit, excluded_rules: set[str]) -> FileDetection:
        name_findings = detect_filename(item.name)
        if item.is_folder:
            kinds = summarize(name_findings)
            return FileDetection(item.file_id, status_for(kinds), kinds)
        try:
            plan = plan_for(item.mime_type, item.name)
            data = fetch_content(self.client, item, plan)
            doc = extract(data, plan)
            del data
            findings = name_findings + detect_extracted(doc)
            partial = doc.partial or doc.truncated
            del doc
        except Unscannable as exc:
            kinds = {k: v for k, v in summarize(name_findings).items() if k not in excluded_rules}
            return FileDetection(item.file_id, DetectStatus.UNSCANNABLE, kinds, exc.reason)
        except DriveHttpError as exc:
            if exc.status == 404:
                return FileDetection(
                    item.file_id, DetectStatus.FAILED, error_code=f"{exc.status}:{exc.reason}"
                )
            raise
        kinds = {k: v for k, v in summarize(findings).items() if k not in excluded_rules}
        return FileDetection(item.file_id, status_for(kinds), kinds, partial=partial)

    def run(self, scan_id: int, items: list[FileAudit]) -> dict[str, FileDetection]:
        done_before = load_detections(self.store, scan_id)
        exclusions = self.store.exclusions()
        by_id = {a.file_id: a for a in items}
        results = dict(done_before)
        todo = [a for a in items if a.file_id not in done_before]
        total = len(items)
        for item in todo:
            if self.cancel is not None and self.cancel.is_set():
                raise DetectCancelled()
            targets = {item.file_id, *_ancestors(item, by_id)}
            if (item.file_id, "*") in exclusions:
                det = FileDetection(item.file_id, DetectStatus.EXCLUDED)
            else:
                rules = {rule for target, rule in exclusions if target in targets and rule != "*"}
                det = self.scan_one(item, rules)
            summary = _summary_to_json(det.kinds)
            if det.partial:
                summary[PARTIAL_KEY] = {"count": 1, "confidence": 1, "locations": []}
            self.store.save_detection(
                scan_id,
                item.file_id,
                det.status.value,
                det.reason.value if det.reason else None,
                det.error_code,
                summary,
            )
            results[item.file_id] = det
            if self.on_progress is not None:
                self.on_progress(DetectProgress(len(results), total, self.client.retries))
        log.info("detection done scan=%s files=%s", scan_id, len(results))
        return results


# -- review: re-read a file on demand, masked, in memory only (SPEC 6.3) --------------------------


@dataclass(frozen=True)
class ReviewLine:
    kind: str
    location: str
    snippet: str  # masked


def review(client: DriveClient, item: FileAudit, limit: int = 200) -> list[ReviewLine]:
    """Fetch the file again and return masked context lines. Nothing is stored or logged."""
    plan = plan_for(item.mime_type, item.name)
    doc = extract(fetch_content(client, item, plan), plan)
    lines: list[ReviewLine] = []
    for seg in doc.segments:
        for finding, span in detect_text_spans(seg.text, seg.location):
            lines.append(
                ReviewLine(
                    finding.kind, finding.location, masked_snippet(seg.text, span, finding.kind)
                )
            )
    for table in doc.tables:
        header_rows = [f for f in detect_table(table) if f.kind == "student_roster"]
        for f in header_rows:
            lines.append(ReviewLine(f.kind, f.location, "표 전체가 명단 형태입니다"))
        for r_index, row in enumerate(table.rows, start=1):
            for cell in row:
                for finding, span in detect_text_spans(cell, f"{table.location}, {r_index}행"):
                    lines.append(
                        ReviewLine(
                            finding.kind, finding.location, masked_snippet(cell, span, finding.kind)
                        )
                    )
        if len(lines) >= limit:
            break
    return lines[:limit]
