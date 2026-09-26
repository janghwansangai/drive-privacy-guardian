"""Fixtures for the Chrome extension tests (extension/app/test/fixtures), from synthetic data.

- expected/*.json: what the desktop app's extractors read from each synthetic file (text
  segments and table grids) — the extension's parsers must read the same content.
- archives made by the desktop app code: 7z (AES-256 + header encryption) and AES-ZIP whose
  password is derived from a SYNTHETIC recovery key (not a real secret; see recovery.txt).

    uv run python tools/make_ext_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dpg.core.extract import formats, hwp
from dpg.core.vault import archive
from dpg.core.vault.recovery import derive_password, parse_recovery_key

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tests" / "fixtures" / "synthetic"
OUT = ROOT / "extension" / "app" / "test" / "fixtures"
# Fixed, synthetic recovery key used only by tests (checksum-valid, never used for real data).
SYNTHETIC_RECOVERY_CODE = "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z2345-67ABC"

FILES = {
    "상담기록_가상.hwp": hwp.extract_hwp,
    "학생명단_가상.hwpx": formats.extract_hwpx,
    "6-2_학생_연락처.xlsx": formats.extract_xlsx,
    "6-2_학생_연락처.csv": lambda d: formats.extract_csv(d),
}


def _valid_key() -> str:
    """Make SYNTHETIC_RECOVERY_CODE checksum-valid (the last 3 chars are the checksum)."""
    import base64
    import hashlib

    body = SYNTHETIC_RECOVERY_CODE.replace("-", "")[:32]
    raw = base64.b32decode(body)
    check = base64.b32encode(hashlib.sha256(b"dpg-rk" + raw).digest())[:3].decode()
    text = body + check
    return "-".join(text[i : i + 5] for i in range(0, 35, 5))


def main() -> None:
    (OUT / "expected").mkdir(parents=True, exist_ok=True)
    for name, fn in FILES.items():
        ex = fn((SRC / name).read_bytes())
        (OUT / "expected" / f"{name}.json").write_text(
            json.dumps(
                {"segments": [s.text for s in ex.segments], "tables": [t.rows for t in ex.tables]},
                ensure_ascii=False,
                indent=1,
            ),
            encoding="utf-8",
        )
    key = _valid_key()
    raw = parse_recovery_key(key)
    members = {n: (SRC / n).read_bytes() for n in FILES}
    tag7z, tagzip = "0a1b2c3d", "4e5f6a7b"
    (OUT / f"보관_2026-09-27_{tag7z}.7z").write_bytes(
        archive.create(members, derive_password(raw, tag7z), archive.ArchiveFormat.SEVEN_ZIP)
    )
    (OUT / f"보관_2026-09-27_{tagzip}.zip").write_bytes(
        archive.create(members, derive_password(raw, tagzip), archive.ArchiveFormat.AES_ZIP)
    )
    # Only fingerprints of the derived passwords are stored (no secret-looking strings in git).
    fps = [
        hashlib.sha256(derive_password(raw, t).encode()).hexdigest()[:16] for t in (tag7z, tagzip)
    ]
    (OUT / "recovery.txt").write_text(
        f"{key}\n# synthetic, tests only. derivation check values: {' '.join(fps)}\n",
        encoding="utf-8",
    )
    print("fixtures written to", OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
