"""Leak scanner: search app-produced files (logs, DB, temp, reports) for personal-data patterns.

Used by tests/privacy (SPEC 5.4) and later by an in-app self-check. Reports counts and file
paths only; matched values are never returned.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from dpg.core.detect.patterns import count_matches

_MAX_BYTES_PER_FILE = 64 * 1024 * 1024


@dataclass
class LeakReport:
    files_scanned: int = 0
    hits: dict[Path, dict[str, int]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(sum(c.values()) for c in self.hits.values())

    def summary(self) -> str:
        """Human-readable summary without values (safe to print in test failures)."""
        lines = [f"scanned={self.files_scanned} hits={self.total}"]
        for path, counts in sorted(self.hits.items()):
            lines.append(f"  {path}: {dict(sorted(counts.items()))}")
        return "\n".join(lines)


def _decode_all(data: bytes) -> Iterable[str]:
    # UTF-8 covers our own logs/DB text. UTF-16 catches Windows-style writers.
    # errors="replace" (not "ignore"): dropping invalid bytes would glue together characters
    # that are not adjacent in the file, so random ciphertext could "form" an e-mail address.
    yield data.decode("utf-8", errors="replace")
    if b"\x00" in data:
        yield data.decode("utf-16-le", errors="replace")


def scan_bytes(data: bytes) -> dict[str, int]:
    merged: dict[str, int] = {}
    for text in _decode_all(data):
        for kind, n in count_matches(text).items():
            merged[kind] = max(merged.get(kind, 0), n)
    return merged


def scan_paths(paths: Iterable[Path]) -> LeakReport:
    report = LeakReport()
    for root in paths:
        candidates = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for path in candidates:
            with path.open("rb") as fh:
                data = fh.read(_MAX_BYTES_PER_FILE)
            report.files_scanned += 1
            counts = scan_bytes(data)
            if counts:
                report.hits[path] = counts
    return report
