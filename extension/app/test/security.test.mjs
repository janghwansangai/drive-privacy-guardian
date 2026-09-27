// Privacy rules for the shipped extension code (the same principles as the desktop app).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { HERE } from "./helpers.mjs";

const ROOT = path.resolve(HERE, "..");
const SHIPPED = ["viewer.js", "background.js", "drive_watch.js", ...fs.readdirSync(path.join(ROOT, "lib")).map((f) => `lib/${f}`)];
const src = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
const manifest = JSON.parse(src("manifest.json"));

test("network: only Google sign-in and the Drive API", () => {
  // drive.google.com is only there so the side panel can read the Drive tab's URL (which folder
  // is open); nothing is fetched from it and no code is injected into it.
  assert.deepEqual(manifest.host_permissions, ["https://www.googleapis.com/*", "https://drive.google.com/*"]);
  const csp = manifest.content_security_policy.extension_pages;
  assert.match(csp, /connect-src 'self' https:\/\/www\.googleapis\.com;/);
  assert.match(csp, /script-src 'self' 'wasm-unsafe-eval';/);
  // only Drive may frame the viewer (the large view, D-089)
  assert.match(csp, /frame-ancestors https:\/\/drive\.google\.com$/);
  assert.doesNotMatch(csp, /(?<!wasm-)unsafe-eval|unsafe-inline|http:/);
  // XML namespace names are identifiers, never fetched.
  const NAMESPACES = new Set(["http://schemas.openxmlformats.org/officeDocument/2006/relationships"]);
  for (const f of SHIPPED) {
    for (const url of (src(f).match(/https?:\/\/[^\s"'`)]+/g) || []).filter((u) => !NAMESPACES.has(u))) {
      // drive.google.com appears only as a sender check (startsWith) — never fetched (see connect-src).
      // (and as the postMessage target of the large view's close request)
      assert.match(url, /^https:\/\/(www\.googleapis\.com|accounts\.google\.com|drive\.google\.com)(\/|$)/, `${f}: ${url}`);
    }
  }
});

test("minimal permissions, no content scripts, no remote code", () => {
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "identity", "sidePanel", "storage"]);
  // One content script, on Drive only (D-086); what it may do is checked below.
  assert.deepEqual(manifest.content_scripts, [
    { matches: ["https://drive.google.com/*"], js: ["drive_watch.js"], run_at: "document_idle", all_frames: false },
  ]);
  assert.ok(!manifest.permissions.includes("scripting") && !manifest.permissions.includes("tabs"));
  assert.equal(manifest.side_panel.default_path, "viewer.html");
  for (const f of SHIPPED) assert.doesNotMatch(src(f), /chrome\.scripting|executeScript|insertCSS/, f);
  // only viewer.html, only for Drive (the large view's iframe, D-089)
  assert.deepEqual(manifest.web_accessible_resources, [{ resources: ["viewer.html"], matches: ["https://drive.google.com/*"] }]);
  for (const f of SHIPPED) {
    const s = src(f);
    assert.doesNotMatch(s, /\beval\(|new Function\(|importScripts\(/, f);
    assert.doesNotMatch(s, /\.innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write/, `${f}: DOM text only`);
  }
});

test("nothing decrypted is persisted; storage holds only what D-088 allows", () => {
  const allowed = {
    "lib/drive.js": ["clientId", "auth"], // auth → session storage (memory only)
    "lib/keyring.js": ["vaultWrap", "vaultKey", "lockMinutes"], // vaultWrap is AES-GCM encrypted
  };
  for (const f of SHIPPED) {
    const s = src(f);
    assert.doesNotMatch(s, /chrome\.storage\.sync|setAccessLevel|chrome\.downloads|localStorage|sessionStorage|indexedDB|caches\.open/, f);
    const keys = [...s.matchAll(/(?:storage\.\w+\??|local\(\)|session\(\))\.set\(\{\s*(\w+)/g)].map((m) => m[1]);
    for (const k of keys) assert.ok((allowed[f] || []).includes(k), `${f}: may not store "${k}"`);
  }
  const k = src("lib/keyring.js");
  assert.match(k, /local\(\)\.set\(\{ vaultWrap \}\)/);
  assert.match(k, /session\(\)\.set\(\{ vaultKey:/); // the unlocked key only in session memory
  assert.doesNotMatch(k, /local\(\)\.set\(\{ vaultKey/);
  assert.match(src("lib/drive.js"), /chrome\.storage\.session\?\.set\(\{ auth:/);
  assert.ok(!manifest.permissions.includes("downloads")); // saving uses a one-off <a download> link
});

test("saving happens only from the confirmed dialog button", () => {
  const s = src("viewer.js");
  const saves = [...s.matchAll(/download:/g)];
  assert.equal(saves.length, 1);
  const block = s.slice(s.indexOf('$("saveOk").onclick'), s.indexOf("URL.revokeObjectURL(url), 10_000"));
  assert.match(block, /download:/, "the only download link is built inside the dialog's confirm handler");
  assert.match(src("viewer.html"), /<dialog id="saveDialog">[\s\S]*다운로드 폴더/);
});

test("drive.file by default; the full drive scope only on the user's explicit request (D-086)", () => {
  const s = src("lib/drive.js");
  assert.match(s, /auth\/drive\.file"/);
  assert.doesNotMatch(s, /auth\/drive\.readonly|auth\/drive\.metadata/);
  assert.match(s, /let wantFull = false;/);
  assert.equal((s.match(/wantFull = true/g) || []).length, 1, "only requestFullAccess() turns it on");
  const req = s.slice(s.indexOf("export async function requestFullAccess"), s.indexOf("async function authed"));
  assert.match(req, /wantFull = true/);
  assert.match(src("viewer.js"), /requestFullAccess\(\)/);
});

test("HWP notice is kept (Hancom published format, D-048)", () => {
  assert.match(src("lib/hwp.js"), /한컴의 HWP 문서 파일\(\.hwp\) 공개 문서를 참고하여 개발하였습니다/);
  assert.match(src("viewer.html"), /한컴의 HWP 문서 파일\(\.hwp\) 공개 문서를 참고하여 개발하였습니다/);
});

test("vendored 7-Zip WASM is the verified build, with its licence files", async () => {
  const { createHash } = await import("node:crypto");
  const sha = (f) => createHash("sha256").update(fs.readFileSync(path.join(ROOT, "vendor/7z-wasm", f))).digest("hex");
  assert.equal(sha("7zz.es6.js"), "f2010cb8d734cac7290a2b27278b30f2bbcd0d354f900173b4cad6b7d46a767a");
  assert.equal(sha("7zz.wasm"), "e16c6997e2eaa89575c0dd1f305074be629c3f4d87246244d37fd19debc8a285");
  assert.ok(fs.existsSync(path.join(ROOT, "vendor/7z-wasm/License.txt")));
  assert.ok(fs.existsSync(path.join(ROOT, "vendor/7z-wasm/unRarLicense.txt")));
});

test("vendored pdf.js is the verified build; GPL fonts and the scripting engine are left out", async () => {
  const { createHash } = await import("node:crypto");
  const dir = path.join(ROOT, "vendor/pdfjs");
  const sha = (f) => createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("hex");
  assert.equal(sha("pdf.min.mjs"), "f80490490320511e5df18c580b9edd6b5db8058dceebaf6f161992e0a964b9e2");
  assert.equal(sha("pdf.worker.min.mjs"), "8ab0e5e30031b4a06ecfddd5ae9562f0227f830ee7ec9ed1a968b134243d2386");
  assert.ok(fs.existsSync(path.join(dir, "LICENSE")));
  const all = fs.readdirSync(dir, { recursive: true }).map(String);
  assert.ok(!all.some((f) => /Liberation|quickjs|sandbox|\.map$/i.test(f)), "no GPL fonts, no JS engine, no source maps");
  const pdf = src("lib/pdf.js");
  assert.match(pdf, /isEvalSupported: false/);
  assert.match(pdf, /enableXfa: false/);
});

test("E3 writes: upload and trash only — no permanent delete, trash only after both checks", () => {
  const d = src("lib/drive.js");
  assert.doesNotMatch(d, /method:\s*"DELETE"|emptyTrash/);
  assert.match(d, /JSON\.stringify\(\{ trashed: true \}\)/);
  const r = src("lib/reencrypt.js");
  assert.match(r, /if \(trashOld && trashIds\.length && uploadVerified\)/);
  assert.ok(r.indexOf("verifyArchive(") < r.indexOf("drive.upload("), "verify before upload");
  assert.match(src("lib/restore.js"), /if \(trashArchive && archiveId && allVerified\)/);
});

test("Drive page watcher: file IDs to this extension, and only the large-view iframe on the page (D-086, D-089)", () => {
  const w = src("drive_watch.js");
  // talks only to this extension, never to the network or storage
  assert.doesNotMatch(w, /fetch\(|XMLHttpRequest|WebSocket|sendBeacon|chrome\.storage|localStorage|indexedDB|chrome\.tabs/);
  assert.doesNotMatch(w, /\bpostMessage\(/, "it only listens for the iframe's close request");
  // the only page change: one iframe of this extension's viewer, added and removed
  assert.deepEqual([...w.matchAll(/createElement\("(\w+)"\)/g)].map((m) => m[1]), ["iframe"]);
  assert.match(w, /overlay\.src = chrome\.runtime\.getURL\(`viewer\.html\?mode=overlay&file=\$\{encodeURIComponent\(id\)\}`\)/);
  assert.doesNotMatch(w, /\.(innerHTML|outerHTML|textContent|innerText|value)\s*=|appendChild|prepend\(|insertAdjacent|setAttribute|document\.write/);
  assert.equal((w.match(/\.append\(/g) || []).length, 1);
  assert.match(w, /ev\.origin === ORIGIN && ev\.source === overlay\?\.contentWindow/);
  // the messages carry IDs / counts only
  const sends = [...w.matchAll(/send\(\{([^}]*)\}\)/g)].map((m) => m[1].trim());
  assert.deepEqual(sends, ['type: "driveStatus", items, selected: selected.length, found: ids.length', 'type: "driveSelection", ids']);
  // the receivers check who sent it
  assert.match(src("viewer.js"), /sender\.id !== chrome\.runtime\.id \|\| !sender\.tab \|\| !sender\.url\?\.startsWith\("https:\/\/drive\.google\.com\/"\)/);
  assert.match(w, /if \(sender\.id !== chrome\.runtime\.id \|\| sender\.tab\) return;/);
  assert.match(src("background.js"), /if \(sender\.id !== chrome\.runtime\.id \|\| sender\.tab/);
});
