"""SPEC 5.4: after processing synthetic personal data, logs must contain zero detections."""

from __future__ import annotations

import logging
import os
import random
from collections.abc import Iterator
from pathlib import Path

import pytest

from dpg.core.detect.leakscan import scan_paths
from dpg.core.logging import LOG_FILE_NAME, MaskingFilter, configure_logging, get_logger
from tools import gen_synthetic as gen

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"


@pytest.fixture
def log_dir(tmp_path: Path) -> Iterator[Path]:
    d = tmp_path / "logs"
    configure_logging(d, level=logging.DEBUG)
    yield d
    configure_logging(None)  # close file handlers


def _synthetic_values() -> list[str]:
    rng = random.Random(42)
    return [
        gen.fake_rrn(rng),
        gen.fake_rrn(rng).replace("-", ""),
        gen.fake_mobile(rng),
        gen.fake_landline(rng),
        gen.fake_email(rng),
        gen.fake_card(rng),
        f"국민은행 {gen.fake_account(rng)}",
        gen.fake_passport(rng),
        gen.fake_license(rng),
        gen.fake_address(rng),
    ]


def test_scanner_detects_fixture_values() -> None:
    """Sanity check: the scanner is not trivially passing."""
    report = scan_paths([FIXTURES / "6-2_학생_연락처.csv", FIXTURES / "업무메모.txt"])
    assert report.total >= 30
    assert "rrn" in report.hits[FIXTURES / "6-2_학생_연락처.csv"]


def test_logs_contain_no_personal_data(log_dir: Path) -> None:
    values = _synthetic_values()
    log = get_logger("audit")
    deep = get_logger("extract.hwp")
    for v in values:
        log.info("processing value %s", v)
        deep.warning(f"f-string with {v}")
        log.debug("dict arg %(v)s", {"v": v})
        try:
            raise RuntimeError(f"parser failed near {v}")
        except RuntimeError:
            log.exception("extract failed")
        log.error("with stack %s", v, stack_info=True)

    configure_logging(None)
    log_file = log_dir / LOG_FILE_NAME
    assert log_file.stat().st_size > 0
    report = scan_paths([log_dir])
    assert report.total == 0, report.summary()
    text = log_file.read_text(encoding="utf-8")
    for expected in ("<RRN>", "<PHONE>", "<EMAIL>", "RuntimeError"):
        assert expected in text


def test_every_dpg_handler_has_masking_filter(log_dir: Path) -> None:
    # pytest attaches its own capture handler to non-propagating loggers; that is test
    # infrastructure, not app code.
    handlers = [
        h for h in logging.getLogger("dpg").handlers if not type(h).__module__.startswith("_pytest")
    ]
    assert handlers
    for h in handlers:
        assert any(isinstance(f, MaskingFilter) for f in h.filters), h


def test_dpg_logs_do_not_propagate_to_unmasked_root(log_dir: Path) -> None:
    assert logging.getLogger("dpg").propagate is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_log_file_is_owner_only(log_dir: Path) -> None:
    assert (log_dir / LOG_FILE_NAME).stat().st_mode & 0o777 == 0o600
    assert log_dir.stat().st_mode & 0o777 == 0o700
