"""Package the Chrome extension for GitHub Releases (unpacked-install zip, SPEC D-078).

    uv run python tools/build_extension.py   ->  dist/DrivePrivacyGuardian-Extension-<ver>.zip

Only the files the extension needs are included (no tests, harness, node_modules).
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "extension" / "app"
DIST = ROOT / "dist"
INCLUDE = [
    "manifest.json",
    "background.js",
    "drive_watch.js",
    "viewer.html",
    "viewer.css",
    "viewer.js",
    "guide.html",
    "guide.css",
    "NOTICE_KO.txt",
]
INCLUDE_DIRS = ["lib", "vendor", "guide"]


def main() -> int:
    version = json.loads((APP / "manifest.json").read_text(encoding="utf-8"))["version"]
    DIST.mkdir(exist_ok=True)
    out = DIST / f"DrivePrivacyGuardian-Extension-{version}.zip"
    files = [APP / f for f in INCLUDE] + sorted(
        p for d in INCLUDE_DIRS for p in (APP / d).rglob("*") if p.is_file()
    )
    root = "DrivePrivacyGuardian-Extension"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            info = zipfile.ZipInfo(f"{root}/{f.relative_to(APP).as_posix()}", (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, f.read_bytes())  # fixed timestamps: reproducible zip
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f"{out.relative_to(ROOT)}  {out.stat().st_size / 1024 / 1024:.1f} MB  sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
