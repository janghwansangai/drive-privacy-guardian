"""새 버전 확인 (D-110, user decision 2026-11-02: "켤 때 자동 확인").

One GET of GitHub's latest-release record for this repository — the only request the app makes
to a host other than Google, through its own transport (`UPDATE_POLICY`: api.github.com only).
Nothing about the user is sent; the answer gives the version number, the release notes and the
download addresses. Downloading and installing are left to the user's browser and the user: the
app never downloads or runs code. Off with 「설정 → 켤 때 새 버전 확인」.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from typing import Any

from dpg import REPOSITORY_URL, __version__
from dpg.core.net_guard import UPDATE_POLICY
from dpg.core.net_guard.http import GuardedHttp

LATEST_URL = "https://api.github.com/repos/janghwansangai/drive-privacy-guardian/releases/latest"
RELEASES_PAGE = REPOSITORY_URL.rstrip("/") + "/releases/latest"
# Only addresses of this repository's own release files are ever handed to the browser.
DOWNLOAD_PREFIX = REPOSITORY_URL.rstrip("/") + "/releases/download/"
PAGE_PREFIX = REPOSITORY_URL.rstrip("/") + "/releases/"
CHECK_EVERY_SECONDS = 24 * 60 * 60
MAX_NOTES = 4000

# The file a user of this computer installs (release assets keep these names, D-097).
ASSETS = {
    "Darwin": "DrivePrivacyGuardian-macOS-arm64.dmg",
    "Windows": "DrivePrivacyGuardian-Windows-x64.zip",
}


class UpdateCheckFailed(Exception):
    """No answer (offline, GitHub busy, unexpected reply). Message is Korean and safe to show."""


@dataclass(frozen=True)
class Release:
    version: str  # "0.2.8"
    notes: str = ""  # release notes (Markdown), shown as text
    page: str = RELEASES_PAGE
    downloads: dict[str, str] = field(default_factory=dict)  # asset name -> address

    def download_for(self, system: str | None = None) -> str:
        """The installer for this computer, or the release page when there is none."""
        name = ASSETS.get(system or platform.system())
        return self.downloads.get(name, self.page) if name else self.page


def parse_version(text: str) -> tuple[int, ...] | None:
    parts = text.strip().lstrip("vV").split(".")
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def is_newer(latest: str, current: str = __version__) -> bool:
    new, now = parse_version(latest), parse_version(current)
    return new is not None and now is not None and new > now


def _release_from(data: Any) -> Release:
    if not isinstance(data, dict):
        raise UpdateCheckFailed("새 버전 정보를 읽지 못했습니다.")
    version = str(data.get("tag_name", "")).lstrip("vV")
    if parse_version(version) is None or data.get("draft") or data.get("prerelease"):
        raise UpdateCheckFailed("새 버전 정보를 읽지 못했습니다.")
    page = str(data.get("html_url", ""))
    downloads = {
        str(a.get("name")): str(a.get("browser_download_url"))
        for a in data.get("assets", [])
        if isinstance(a, dict)
        and str(a.get("browser_download_url", "")).startswith(DOWNLOAD_PREFIX)
    }
    return Release(
        version=version,
        notes=str(data.get("body") or "")[:MAX_NOTES],
        page=page if page.startswith(PAGE_PREFIX) else RELEASES_PAGE,
        downloads=downloads,
    )


def fetch_latest(http: Any = None) -> Release:
    """The latest published release. Raises UpdateCheckFailed (never anything else)."""
    http = http or GuardedHttp(UPDATE_POLICY, timeout=15)
    try:
        response, body = http.request(
            LATEST_URL,
            "GET",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"DrivePrivacyGuardian/{__version__}",
            },
        )
    except Exception as exc:
        raise UpdateCheckFailed("인터넷에 연결되지 않아 확인하지 못했습니다.") from exc
    if int(getattr(response, "status", 0)) != 200:
        raise UpdateCheckFailed("지금은 확인하지 못했습니다. 나중에 다시 해 보세요.")
    try:
        data = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    except ValueError as exc:
        raise UpdateCheckFailed("새 버전 정보를 읽지 못했습니다.") from exc
    return _release_from(data)


def due(last_checked: float, now: float) -> bool:
    return now - last_checked >= CHECK_EVERY_SECONDS or now < last_checked
