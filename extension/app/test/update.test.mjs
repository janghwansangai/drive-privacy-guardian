// D-110: once a day, the version number only; this project's own zip address only.
import test from "node:test";
import assert from "node:assert/strict";
import { checkDaily, fetchLatest, isNewer, LATEST_URL, UpdateCheckFailed, CHECK_EVERY_MS } from "../lib/update.js";

const OURS = "https://github.com/janghwansangai/drive-privacy-guardian/releases/download/v0.2.8/DrivePrivacyGuardian-Extension.zip";
const record = (over = {}) => ({
  tag_name: "v0.2.8", draft: false, prerelease: false,
  assets: [{ name: "DrivePrivacyGuardian-Extension.zip", browser_download_url: OURS }],
  ...over,
});
const answer = (body, ok = true) => async (url, init) => {
  answer.calls.push([url, init]);
  return { ok, json: async () => body };
};
answer.calls = [];

function area() {
  const data = {};
  return { data, get: async (keys) => Object.fromEntries(keys.map((k) => [k, data[k]])), set: async (o) => Object.assign(data, o) };
}

test("versions compare as numbers", () => {
  assert.ok(isNewer("0.2.10", "0.2.9"));
  assert.ok(!isNewer("0.2.7", "0.2.7"));
  assert.ok(!isNewer("0.2.6", "0.2.7"));
  assert.ok(!isNewer("latest", "0.2.7"));
});

test("one GET without cookies or referrer; only our own zip address is kept", async () => {
  answer.calls = [];
  const got = await fetchLatest(answer(record()));
  assert.deepEqual(got, { version: "0.2.8", download: OURS });
  assert.equal(answer.calls[0][0], LATEST_URL);
  assert.equal(answer.calls[0][1].credentials, "omit");
  assert.equal(answer.calls[0][1].referrerPolicy, "no-referrer");
  assert.equal(answer.calls[0][1].method, undefined); // GET
  const foreign = await fetchLatest(answer(record({ assets: [{ name: "DrivePrivacyGuardian-Extension.zip", browser_download_url: "https://evil.example/x.zip" }] })));
  assert.equal(foreign.download, null);
  for (const bad of [answer({}, false), answer(record({ tag_name: "nightly" })), answer(record({ draft: true })), async () => { throw new TypeError("offline"); }]) {
    await assert.rejects(fetchLatest(bad), UpdateCheckFailed);
  }
});

test("daily: asks once a day, never when turned off, keeps the last answer when offline", async () => {
  const storage = area();
  let n = 0;
  const fetchFn = async () => { n += 1; return { ok: true, json: async () => record() }; };
  const now = 1_800_000_000_000;
  assert.equal((await checkDaily({ storage, now, fetchFn })).version, "0.2.8");
  await checkDaily({ storage, now: now + 3600_000, fetchFn });
  assert.equal(n, 1);
  const offline = async () => { throw new TypeError("offline"); };
  assert.equal((await checkDaily({ storage, now: now + CHECK_EVERY_MS, fetchFn: offline })).version, "0.2.8");
  storage.data.updateOff = true;
  assert.equal(await checkDaily({ storage, now: now + 3 * CHECK_EVERY_MS, fetchFn }), null);
  assert.equal(n, 1);
});
