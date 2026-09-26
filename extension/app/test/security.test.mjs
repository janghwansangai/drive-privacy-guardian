// Privacy rules for the shipped extension code (the same principles as the desktop app).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { HERE } from "./helpers.mjs";

const ROOT = path.resolve(HERE, "..");
const SHIPPED = ["viewer.js", "background.js", ...fs.readdirSync(path.join(ROOT, "lib")).map((f) => `lib/${f}`)];
const src = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
const manifest = JSON.parse(src("manifest.json"));

test("network: only Google sign-in and the Drive API", () => {
  assert.deepEqual(manifest.host_permissions, ["https://www.googleapis.com/*"]);
  const csp = manifest.content_security_policy.extension_pages;
  assert.match(csp, /connect-src 'self' https:\/\/www\.googleapis\.com;/);
  assert.match(csp, /script-src 'self' 'wasm-unsafe-eval';/);
  assert.doesNotMatch(csp, /(?<!wasm-)unsafe-eval|unsafe-inline|http:/);
  // XML namespace names are identifiers, never fetched.
  const NAMESPACES = new Set(["http://schemas.openxmlformats.org/officeDocument/2006/relationships"]);
  for (const f of SHIPPED) {
    for (const url of (src(f).match(/https?:\/\/[^\s"'`)]+/g) || []).filter((u) => !NAMESPACES.has(u))) {
      assert.match(url, /^https:\/\/(www\.googleapis\.com|accounts\.google\.com)\//, `${f}: ${url}`);
    }
  }
});

test("minimal permissions, no content scripts, no remote code", () => {
  assert.deepEqual(manifest.permissions.sort(), ["identity", "storage"]);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.web_accessible_resources, undefined);
  for (const f of SHIPPED) {
    const s = src(f);
    assert.doesNotMatch(s, /\beval\(|new Function\(|importScripts\(/, f);
    assert.doesNotMatch(s, /\.innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write/, `${f}: DOM text only`);
  }
});

test("nothing decrypted is persisted: storage holds only the client ID, no downloads API", () => {
  for (const f of SHIPPED) {
    const s = src(f);
    for (const m of s.matchAll(/chrome\.storage\.(\w+)\.set\(([^)]*)\)/g)) {
      assert.equal(m[1], "local", f);
      assert.match(m[2], /^\{ clientId: value \}$/, `${f}: only the client ID may be stored`);
    }
    assert.doesNotMatch(s, /chrome\.downloads|localStorage|sessionStorage|indexedDB|caches\.open/, f);
  }
  assert.ok(!manifest.permissions.includes("downloads")); // saving arrives in E2, on request only
});

test("drive.file scope only (no restricted Drive scopes)", () => {
  const s = src("lib/drive.js");
  assert.match(s, /auth\/drive\.file"/);
  assert.doesNotMatch(s, /auth\/drive\.readonly|auth\/drive\.metadata|auth\/drive"/);
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
