"""D-074: recovery key — typo-tolerant parsing, deterministic per-archive passwords."""

from __future__ import annotations

import re

import pytest

from dpg.core.vault import archive
from dpg.core.vault.archive import ArchiveFormat
from dpg.core.vault.recovery import (
    InvalidRecoveryKey,
    derive_password,
    fingerprint,
    new_recovery_key,
    parse_recovery_key,
    tag_from_name,
)


def test_format_and_roundtrip() -> None:
    keys = {new_recovery_key() for _ in range(50)}
    assert len(keys) == 50
    for key in keys:
        assert re.fullmatch(r"([A-Z2-7]{5}-){6}[A-Z2-7]{5}", key)
        raw = parse_recovery_key(key)
        assert len(raw) == 20
        # forgiving input: lower case, spaces, no dashes, 0/1/8 look-alikes
        sloppy = key.lower().replace("-", " ").replace("o", "0").replace("i", "1")
        assert parse_recovery_key(sloppy) == raw


def test_typos_are_caught() -> None:
    key = new_recovery_key()
    swapped = key[:3] + ("A" if key[3] != "A" else "B") + key[4:]
    with pytest.raises(InvalidRecoveryKey):
        parse_recovery_key(swapped)
    with pytest.raises(InvalidRecoveryKey):
        parse_recovery_key(key[:-1])
    with pytest.raises(InvalidRecoveryKey):
        parse_recovery_key("hello")


def test_derived_password_is_stable_per_archive_and_opens_it() -> None:
    raw = parse_recovery_key(new_recovery_key())
    name = archive.archive_name(ArchiveFormat.SEVEN_ZIP)
    tag = tag_from_name(name)
    assert tag is not None
    pw = derive_password(raw, tag)
    assert pw == derive_password(raw, tag)  # the same key re-creates it
    assert pw != derive_password(raw, "00000000")  # each archive has its own
    assert pw != derive_password(parse_recovery_key(new_recovery_key()), tag)
    plain = pw.replace("-", "")
    assert len(plain) == 24
    assert re.search("[a-z]", plain)
    assert re.search("[A-Z]", plain)
    assert re.search("[0-9]", plain)
    blob = archive.create({"가상.txt": b"x"}, pw, ArchiveFormat.SEVEN_ZIP)
    assert archive.open_archive(blob, derive_password(raw, tag)) == {"가상.txt": b"x"}


def test_fingerprint_and_tags() -> None:
    raw = parse_recovery_key(new_recovery_key())
    assert re.fullmatch(r"[0-9A-F]{8}", fingerprint(raw))
    assert tag_from_name("보관_2026-09-26_7f3a9c2e.7z") == "7f3a9c2e"
    assert tag_from_name("보관_2026-09-26_7f3a.7z") is None  # made before recovery keys
    assert tag_from_name("사진.zip") is None
