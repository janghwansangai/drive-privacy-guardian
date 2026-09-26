from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from dpg.core.detect.validators import luhn_ok, rrn_birth_date, rrn_checksum_ok
from tools import gen_synthetic as gen

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"


def test_value_generators_are_fake_by_construction() -> None:
    rng = random.Random(1)
    for _ in range(2000):
        rrn = gen.fake_rrn(rng)
        born = rrn_birth_date(rrn)
        assert born is not None
        assert born.year >= gen.FUTURE_YEAR_MIN
        assert rrn_checksum_ok(rrn)
        assert not rrn_checksum_ok(gen.fake_rrn(rng, checksum_valid=False))
        assert gen.fake_mobile(rng).split("-")[1][0] in "01"
        assert gen.fake_landline(rng).split("-")[1][0] in "01"
        assert gen.fake_email(rng).split("@")[1] in gen.RESERVED_EMAIL_DOMAINS
        card = gen.fake_card(rng)
        assert card.startswith("9999")
        assert luhn_ok(card)
        assert gen.fake_account(rng).startswith("999-")
        assert not gen.find_non_synthetic(" ".join([rrn, gen.fake_mobile(rng), card]))


@pytest.mark.parametrize(
    "text",
    [
        "900101-1234568",  # plausible 1990 birth date
        "010-2345-6789",  # assignable mobile range
        "02-345-6789",
        "someone@gmail.com",
        "4111-1111-1111-1111",
    ],
)
def test_checker_flags_potentially_real_values(text: str) -> None:
    assert gen.find_non_synthetic(text)


def test_generate_is_deterministic_and_synthetic(tmp_path: Path) -> None:
    m1 = gen.generate(tmp_path / "a", seed=7)
    m2 = gen.generate(tmp_path / "b", seed=7)
    assert m1.files == m2.files
    for name in m1.files:
        assert gen.fixture_text(tmp_path / "a" / name) == gen.fixture_text(tmp_path / "b" / name)
        assert gen.find_non_synthetic(gen.fixture_text(tmp_path / "a" / name)) == []


def test_committed_fixtures_are_synthetic() -> None:
    """Phase 0 gate: committed fixture files contain no potentially real identifiers."""
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["generator_version"] == gen.GENERATOR_VERSION
    names = set(manifest["files"]) | set(manifest.get("unscannable", {}))
    assert names, "fixtures missing — run tools/gen_synthetic.py"
    on_disk = {p.name for p in FIXTURES.iterdir() if p.name != "manifest.json"}
    assert on_disk == names, "fixture dir and manifest disagree"
    for name in names:
        assert gen.find_non_synthetic(gen.fixture_text(FIXTURES / name)) == [], name


def test_committed_fixtures_match_generator(tmp_path: Path) -> None:
    """Committed fixtures must be exactly what the generator produces (no hand edits)."""
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    fresh = gen.generate(tmp_path, seed=manifest["seed"])
    assert fresh.files == manifest["files"]
    assert fresh.unscannable == manifest["unscannable"]
    for name in [*manifest["files"], *manifest["unscannable"]]:
        assert gen.fixture_text(tmp_path / name) == gen.fixture_text(FIXTURES / name), name
