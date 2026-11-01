// 새 버전 확인 (D-110, user decision 2026-11-02 "켤 때 자동 확인"): once a day when a view opens,
// read GitHub's latest-release record — the version number and the address of the extension
// zip. Nothing about the user is sent (no cookies, no referrer). connect-src allows
// api.github.com for this read only; the zip is downloaded by the browser when the user asks.
export const LATEST_URL = "https://api.github.com/repos/janghwansangai/drive-privacy-guardian/releases/latest";
const DOWNLOAD_PREFIX = "https://github.com/janghwansangai/drive-privacy-guardian/releases/download/";
export const EXTENSION_ASSET = "DrivePrivacyGuardian-Extension.zip";
export const CHECK_EVERY_MS = 24 * 60 * 60 * 1000;

export class UpdateCheckFailed extends Error {} // message is Korean and safe to show

export function parseVersion(text) {
  const parts = String(text || "").trim().replace(/^v/i, "").split(".");
  if (parts.length < 1 || parts.length > 4 || !parts.every((p) => /^\d+$/.test(p))) return null;
  return parts.map(Number);
}

export function isNewer(latest, current) {
  const a = parseVersion(latest);
  const b = parseVersion(current);
  if (!a || !b) return false;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return d > 0;
  }
  return false;
}

/** { version, download } — download is this project's extension zip, or null. */
export async function fetchLatest(fetchFn = fetch) {
  let res;
  try {
    res = await fetchFn(LATEST_URL, {
      headers: { Accept: "application/vnd.github+json" },
      credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
    });
  } catch {
    throw new UpdateCheckFailed("인터넷에 연결되지 않아 확인하지 못했습니다.");
  }
  if (!res.ok) throw new UpdateCheckFailed("지금은 확인하지 못했습니다. 나중에 다시 해 보세요.");
  let data;
  try { data = await res.json(); } catch { throw new UpdateCheckFailed("새 버전 정보를 읽지 못했습니다."); }
  const version = String(data?.tag_name || "").replace(/^v/i, "");
  if (!parseVersion(version) || data.draft || data.prerelease) throw new UpdateCheckFailed("새 버전 정보를 읽지 못했습니다.");
  const asset = (Array.isArray(data.assets) ? data.assets : []).find((a) => a?.name === EXTENSION_ASSET);
  const url = String(asset?.browser_download_url || "");
  return { version, download: url.startsWith(DOWNLOAD_PREFIX) ? url : null };
}

/** The automatic check: at most once a day, unless turned off. Returns the latest seen or null. */
export async function checkDaily({ storage, now = Date.now(), fetchFn = fetch } = {}) {
  const { updateCheck: last = null, updateOff = false } = await storage.get(["updateCheck", "updateOff"]);
  if (updateOff) return null;
  if (last && now - last.at < CHECK_EVERY_MS && now >= last.at) return last;
  try {
    const latest = await fetchLatest(fetchFn);
    const updateCheck = { at: now, version: latest.version, download: latest.download };
    await storage.set({ updateCheck });
    return updateCheck;
  } catch {
    return last; // offline: try again next time, show what was known
  }
}
