"""D-110: the update check reads only GitHub's latest-release record, and only this project's
release files are ever handed to the browser."""

from __future__ import annotations

import json
from typing import Any

import pytest

from dpg.core import update
from dpg.core.net_guard import DEFAULT_POLICY, SOCKET_POLICY, UPDATE_POLICY, BlockedConnectionError
from dpg.core.net_guard.http import GuardedHttp

OURS = "https://github.com/janghwansangai/drive-privacy-guardian/releases/download/v0.2.8/"


def _record(**over: Any) -> dict[str, Any]:
    data = {
        "tag_name": "v0.2.8",
        "draft": False,
        "prerelease": False,
        "body": "### v0.2.8\n- 고침",
        "html_url": "https://github.com/janghwansangai/drive-privacy-guardian/releases/tag/v0.2.8",
        "assets": [
            {
                "name": update.ASSETS["Darwin"],
                "browser_download_url": OURS + update.ASSETS["Darwin"],
            },
            {
                "name": update.ASSETS["Windows"],
                "browser_download_url": OURS + update.ASSETS["Windows"],
            },
            {"name": "evil.dmg", "browser_download_url": "https://evil.example/x.dmg"},
        ],
    }
    data.update(over)
    return data


class FakeHttp:
    def __init__(self, status: int = 200, body: Any = None, error: Exception | None = None) -> None:
        self.status, self.body, self.error = status, body, error
        self.calls: list[tuple[Any, ...]] = []

    def request(self, uri: str, method: str = "GET", body: Any = None, headers: Any = None) -> Any:
        self.calls.append((uri, method, body, headers))
        if self.error:
            raise self.error
        response = type("R", (), {"status": self.status})()
        return response, json.dumps(self.body).encode()


def test_versions() -> None:
    assert update.parse_version("v0.2.10") == (0, 2, 10)
    assert update.parse_version("0.2.x") is None
    assert update.is_newer("0.2.10", "0.2.9")
    assert not update.is_newer("0.2.7", "0.2.7")
    assert not update.is_newer("0.2.6", "0.2.7")
    assert not update.is_newer("nonsense", "0.2.7")


def test_reads_one_get_with_nothing_about_the_user() -> None:
    http = FakeHttp(body=_record())
    rel = update.fetch_latest(http)
    assert http.calls == [
        (
            update.LATEST_URL,
            "GET",
            None,
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": f"DrivePrivacyGuardian/{update.__version__}",
            },
        )
    ]
    assert rel.version == "0.2.8"
    assert "고침" in rel.notes
    assert rel.download_for("Darwin") == OURS + update.ASSETS["Darwin"]
    assert rel.download_for("Windows") == OURS + update.ASSETS["Windows"]
    assert rel.download_for("Linux") == rel.page  # no installer: the release page
    assert "evil.dmg" not in rel.downloads  # only this project's release files


def test_odd_answers_fall_back_safely() -> None:
    rel = update.fetch_latest(FakeHttp(body=_record(html_url="https://evil.example/")))
    assert rel.page == update.RELEASES_PAGE
    for bad in (
        FakeHttp(status=403, body={}),
        FakeHttp(body=_record(tag_name="latest")),
        FakeHttp(body=_record(draft=True)),
        FakeHttp(body=["not", "a", "record"]),
        FakeHttp(error=OSError("offline")),
        FakeHttp(error=BlockedConnectionError("blocked")),
    ):
        with pytest.raises(update.UpdateCheckFailed):
            update.fetch_latest(bad)


def test_due_once_a_day() -> None:
    assert update.due(0, 1_000_000)
    assert not update.due(1_000_000, 1_000_000 + 3600)
    assert update.due(1_000_000, 1_000_000 + 86_400)
    assert update.due(2_000_000, 1_000_000)  # clock went back


def test_the_update_transport_reaches_only_github_api() -> None:
    assert UPDATE_POLICY.is_allowed_host("api.github.com")
    for host in (
        "github.com",
        "www.googleapis.com",
        "objects.githubusercontent.com",
        "evil.example",
    ):
        assert not UPDATE_POLICY.is_allowed_host(host), host
    assert not DEFAULT_POLICY.is_allowed_host("api.github.com")  # Google traffic unchanged
    assert SOCKET_POLICY.is_allowed_host("api.github.com")
    assert SOCKET_POLICY.is_allowed_host("www.googleapis.com")
    assert not SOCKET_POLICY.is_allowed_host("evil.example")
    with pytest.raises(BlockedConnectionError):
        GuardedHttp(UPDATE_POLICY).request("https://www.googleapis.com/drive/v3/files")
    with pytest.raises(BlockedConnectionError):
        GuardedHttp().request(update.LATEST_URL)
