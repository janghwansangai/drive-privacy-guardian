# PyInstaller spec — onedir build (SPEC 9, V13: Qt stays as separate, replaceable libraries).
# Build with: uv run --group build python tools/build.py
# ruff: noqa
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
APP = "Drive Privacy Guardian"
sys.path.insert(0, str(ROOT / "src"))
from dpg import __version__ as VERSION  # noqa: E402

import googleapiclient  # noqa: E402

DISCOVERY = Path(googleapiclient.__file__).parent / "discovery_cache" / "documents"

datas = [
    # Only the Drive v3 discovery document (static discovery: no network fetch, ~0.3 MB
    # instead of the 100 MB of every Google API).
    (str(DISCOVERY / "drive.v3.json"), "googleapiclient/discovery_cache/documents"),
    (str(ROOT / "LICENSE"), "."),
    (str(ROOT / "build" / "licenses" / "THIRD_PARTY_LICENSES.txt"), "."),
    (str(ROOT / "packaging" / "NOTICE_KO.txt"), "."),
    # Qt / PySide6 are used under LGPL-3.0 (which incorporates GPL-3.0 terms): ship both texts.
    (str(ROOT / "packaging" / "licenses" / "LGPL-3.0.txt"), "licenses"),
    (str(ROOT / "packaging" / "licenses" / "GPL-3.0.txt"), "licenses"),
]

hiddenimports = [
    *collect_submodules("keyring.backends"),
    "PySide6.QtPrintSupport",
]

# Never ship Qt networking / web engines: they would bypass the network guard (CLAUDE.md).
excludes = [
    "PySide6.QtNetwork",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebSockets",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickWidgets",
    "PySide6.Qt3DCore",
    "PySide6.QtMultimedia",
    "PySide6.QtBluetooth",
    "PySide6.QtNfc",
    "PySide6.QtPositioning",
    "PySide6.QtLocation",
    "PySide6.QtHttpServer",
    "PySide6.QtDesigner",
    "PySide6.QtHelp",
    "tkinter",
    "pytest",
    "IPython",
]

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT / "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=excludes,
    noarchive=False,
)
# Qt network pieces: only the TUIO touch plugin (touch input over UDP) pulls in QtNetwork.
# Neither is needed; leaving them out keeps every network path under the net guard.
_DROP_BINARIES = ("QtNetwork", "uiotouch", "QtQml", "QtQuick", "QtWebEngine")


def _keep_binary(entry):
    return not any(token in entry[0] for token in _DROP_BINARIES)


def _keep_data(entry):
    dest = entry[0].replace("\\", "/")
    if "discovery_cache/documents/" in dest:
        return dest.endswith("drive.v3.json")  # the hook collects all ~600 Google APIs
    return not any(token in dest for token in _DROP_BINARIES)


a.binaries = [b for b in a.binaries if _keep_binary(b)]
a.datas = [d for d in a.datas if _keep_data(d)]

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP,
    console=False,
    disable_windowed_traceback=True,
    upx=False,
    argv_emulation=False,
    target_arch=None,
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name=APP)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name=f"{APP}.app",
        bundle_identifier="io.github.drive-privacy-guardian",
        version=VERSION,
        info_plist={
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "12.0",
            "NSHumanReadableCopyright": "MIT License · Qt/PySide6: LGPL-3.0",
        },
    )
