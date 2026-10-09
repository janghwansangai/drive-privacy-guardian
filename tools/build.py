"""Build the desktop app and release files (SPEC 9).

    uv run --group build python tools/build.py

1. THIRD_PARTY_LICENSES.txt for the runtime dependencies (pip-licenses, offline)
2. PyInstaller onedir build (packaging/dpg.spec)
3. `--selftest` of the *built* app (fails the build if anything is missing)
4. macOS: .zip (+ .dmg) of the .app · Windows: .zip of the folder
5. SHA256SUMS.txt
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dpg import __version__  # noqa: E402

APP = "Drive Privacy Guardian"
DIST = ROOT / "dist"
BUILD = ROOT / "build"
BUILD_ONLY = {"pyinstaller", "pyinstaller-hooks-contrib", "pip-licenses", "setuptools"}


def run(cmd: list[str], **kw: object) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT, **kw)  # noqa: S603 — fixed argument lists


def runtime_packages() -> list[str]:
    uv = shutil.which("uv") or "uv"
    out = subprocess.run(  # noqa: S603
        [uv, "export", "--locked", "--no-dev", "--no-hashes", "--no-emit-project"],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
    names = []
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "-")):
            names.append(line.split("==")[0].split(";")[0].strip())
    return sorted(n for n in names if n.lower() not in BUILD_ONLY)


def third_party_licenses() -> Path:
    target = BUILD / "licenses" / "THIRD_PARTY_LICENSES.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            "-m",
            "piplicenses",
            "--packages",
            *runtime_packages(),
            "--with-license-file",
            "--no-license-path",
            "--with-urls",
            "--format=plain-vertical",
            f"--output-file={target}",
        ]
    )
    header = (
        "Drive Privacy Guardian — 포함된 오픈소스 구성요소와 라이선스\n"
        "Qt/PySide6/Shiboken6는 LGPL-3.0 조건으로 사용합니다 (NOTICE_KO.txt 참고).\n\n"
    )
    target.write_text(header + target.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def pyinstaller() -> None:
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            str(ROOT / "packaging" / "dpg.spec"),
            "--noconfirm",
            "--clean",
            f"--distpath={DIST}",
            f"--workpath={BUILD / 'pyi'}",
        ]
    )


def built_executable() -> Path:
    if sys.platform == "darwin":
        return DIST / f"{APP}.app" / "Contents" / "MacOS" / APP
    if sys.platform == "win32":
        return DIST / APP / f"{APP}.exe"
    return DIST / APP / APP


def codesign_app() -> None:
    """macOS: sign the bundle with the project's self-signed identity when CI provides one
    (D-100). The same certificate on every release lets the keychain recognise an update as
    the same app, so it stops asking for the login password after each update. Without it
    the app keeps PyInstaller's ad-hoc signature, as before."""
    import os

    identity = os.environ.get("DPG_CODESIGN_IDENTITY")
    if sys.platform != "darwin" or not identity:
        return
    app = DIST / f"{APP}.app"
    cmd = ["codesign", "--force", "--deep", "--sign", identity]
    keychain = os.environ.get("DPG_CODESIGN_KEYCHAIN")
    if keychain:
        cmd += ["--keychain", keychain]
    run([*cmd, str(app)])
    run(["codesign", "--verify", "--deep", "--strict", str(app)])
    run(["codesign", "-d", "-r-", str(app)])  # prints the designated requirement (for the log)


def selftest(skip_keychain: bool) -> None:
    report = BUILD / "selftest.txt"
    cmd = [str(built_executable()), "--selftest", f"--selftest-out={report}"]
    if skip_keychain:
        cmd.append("--no-keychain")
    result = subprocess.run(cmd, cwd=ROOT, env={**_env(), "QT_QPA_PLATFORM": "offscreen"})  # noqa: S603
    print(report.read_text(encoding="utf-8") if report.exists() else "(no self-test report)")
    if result.returncode != 0:
        raise SystemExit("built app failed its self-test")


def _env() -> dict[str, str]:
    import os

    return dict(os.environ)


def package() -> list[Path]:
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    base = f"DrivePrivacyGuardian-{__version__}"
    outputs: list[Path] = []
    if sys.platform == "darwin":
        app = DIST / f"{APP}.app"
        zip_path = DIST / f"{base}-macOS-{arch}.zip"
        run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(zip_path)])
        outputs.append(zip_path)
        dmg = DIST / f"{base}-macOS-{arch}.dmg"
        dmg.unlink(missing_ok=True)
        # The disk image shows the app next to an "Applications" shortcut: drag one onto the other.
        stage = BUILD / "dmg"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        run(["ditto", str(app), str(stage / app.name)])  # keeps the signature
        (stage / "Applications").symlink_to("/Applications")
        run(
            [
                "hdiutil", "create", "-volname", APP, "-srcfolder", str(stage),
                "-ov", "-format", "UDZO", str(dmg),
            ]
        )  # fmt: skip
        outputs.append(dmg)
    else:
        name = "Windows" if sys.platform == "win32" else "Linux"
        archive = shutil.make_archive(str(DIST / f"{base}-{name}-{arch}"), "zip", DIST, APP)
        outputs.append(Path(archive))
    return outputs


def checksums(files: list[Path]) -> Path:
    sums = DIST / "SHA256SUMS.txt"
    lines = []
    for f in files:
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        lines.append(f"{digest}  {f.name}")
    existing = sums.read_text(encoding="utf-8").splitlines() if sums.exists() else []
    keep = [ln for ln in existing if ln.split()[-1] not in {f.name for f in files}]
    sums.write_text("\n".join([*keep, *lines]) + "\n", encoding="utf-8")
    return sums


def main() -> int:
    # Windows CI consoles default to cp1252; the self-test report is Korean.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    skip_keychain = "--no-keychain" in sys.argv  # CI runners may lack an unlocked keychain
    third_party_licenses()
    pyinstaller()
    codesign_app()
    selftest(skip_keychain)
    files = package()
    sums = checksums(files)
    print("\n완료:")
    for f in [*files, sums]:
        print(f"  {f.relative_to(ROOT)}  ({f.stat().st_size / 1024 / 1024:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
