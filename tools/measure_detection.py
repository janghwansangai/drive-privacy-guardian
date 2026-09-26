"""Precision / recall of the detector on the synthetic fixture set (SPEC 6.3, Phase 4 gate).

Counts per file and kind are compared with tests/fixtures/synthetic/manifest.json:
TP = min(found, expected), FP = found − TP, FN = expected − TP.

Usage: uv run python tools/measure_detection.py [--fixtures DIR] [--check]
  --check  exit 1 if a target (SPEC 6.3 initial goals) is missed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dpg.core.detect.rules import detect_extracted
from dpg.core.extract import Unscannable, extract, plan_for

DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic"

# SPEC 6.3 initial targets (adjust after measurement, record in DECISIONS.md)
RECALL_TARGETS = {"rrn": 0.95, "mobile": 0.95}
PRECISION_TARGETS = {"account": 0.90}


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


def measure(fixtures: Path) -> tuple[dict[str, Score], dict[str, str]]:
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    scores: dict[str, Score] = {}
    unscannable_ok: dict[str, str] = {}
    for name, expected in manifest["files"].items():
        data = (fixtures / name).read_bytes()
        doc = extract(data, plan_for("", name))
        found = Counter(f.kind for f in detect_extracted(doc))
        for kind in set(found) | set(expected):
            s = scores.setdefault(kind, Score())
            tp = min(found[kind], expected.get(kind, 0))
            s.tp += tp
            s.fp += found[kind] - tp
            s.fn += expected.get(kind, 0) - tp
    for name, reason in manifest.get("unscannable", {}).items():
        try:
            extract((fixtures / name).read_bytes(), plan_for("", name))
            unscannable_ok[name] = "NOT FLAGGED (scanned as normal)"
        except Unscannable as exc:
            unscannable_ok[name] = "ok" if exc.reason.value == reason else f"got {exc.reason}"
    return scores, unscannable_ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    scores, unscannable = measure(args.fixtures)
    print(f"{'유형':<20}{'TP':>5}{'FP':>5}{'FN':>5}{'정밀도':>9}{'재현율':>9}")
    for kind in sorted(scores):
        s = scores[kind]
        print(f"{kind:<20}{s.tp:>5}{s.fp:>5}{s.fn:>5}{s.precision:>9.1%}{s.recall:>9.1%}")
    print("검사 불가 판정:", unscannable)
    failures = [
        f"{k} recall {scores[k].recall:.1%} < {t:.0%}"
        for k, t in RECALL_TARGETS.items()
        if k in scores and scores[k].recall < t
    ]
    failures += [
        f"{k} precision {scores[k].precision:.1%} < {t:.0%}"
        for k, t in PRECISION_TARGETS.items()
        if k in scores and scores[k].precision < t
    ]
    failures += [f"{n}: {v}" for n, v in unscannable.items() if v != "ok"]
    for f in failures:
        print("MISSED TARGET:", f, file=sys.stderr)
    return 1 if (args.check and failures) else 0


if __name__ == "__main__":
    sys.exit(main())
