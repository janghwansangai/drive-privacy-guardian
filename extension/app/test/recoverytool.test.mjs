// D-106: the offline recovery tool (src/dpg/resources/recovery-tool.html) re-creates an archive's password
// from the paper recovery key without the app, a library or the network. It must give exactly
// the passwords the desktop app and the extension use.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { recoveryKey } from "./helpers.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TOOL = path.join(HERE, "..", "..", "..", "src", "dpg", "resources", "recovery-tool.html");
const html = fs.readFileSync(TOOL, "utf8");
const core = html.slice(html.indexOf("/* BEGIN CORE"), html.indexOf("/* END CORE */"));
const DPG = new Function(`${core}; return DPG;`)();

test("hash functions match the platform's", () => {
  for (const n of [0, 1, 55, 56, 64, 111, 112, 128, 300]) {
    const bytes = [...crypto.randomBytes(n)];
    assert.equal(Buffer.from(DPG.sha256(bytes)).toString("hex"), crypto.createHash("sha256").update(Buffer.from(bytes)).digest("hex"));
    assert.equal(Buffer.from(DPG.sha512(bytes)).toString("hex"), crypto.createHash("sha512").update(Buffer.from(bytes)).digest("hex"));
  }
});

test("same passwords as the app (pinned v0.2.5 values) and the same fingerprint", async () => {
  const k = DPG.parseKey(recoveryKey());
  assert.equal(k.error, undefined);
  assert.equal(DPG.fingerprint(k.raw), "525ADC3A");
  assert.equal(DPG.derivePassword(k.raw, "0a1b2c3d"), "KZaY-wJRt-lIAZ-LNoc-uQo3-ptSc");
  assert.equal(DPG.derivePassword(k.raw, "ffffffff"), "Biud-RZi9-qz2p-pqN5-HdM1-uL2i");
  const { parseRecoveryKey, derivePassword } = await import("../lib/vault.js");
  const raw = await parseRecoveryKey(recoveryKey());
  for (let i = 0; i < 20; i++) {
    const tag = crypto.randomBytes(4).toString("hex");
    assert.equal(DPG.derivePassword(k.raw, tag), await derivePassword(raw, tag));
  }
});

test("typos and names", () => {
  const key = recoveryKey();
  assert.ok(DPG.parseKey(key.toLowerCase().replace(/-/g, " ")).raw); // forgiving input
  const typo = key.slice(0, 3) + (key[3] === "A" ? "B" : "A") + key.slice(4);
  assert.ok(DPG.parseKey(typo).error);
  assert.equal(DPG.tagFrom("상담기록.hwp (암호화 7f3a9c2e).7z"), "7f3a9c2e");
  assert.equal(DPG.tagFrom("명단.xlsx 외 3개 (암호화 0A1B2C3D).zip"), "0a1b2c3d");
  assert.equal(DPG.tagFrom("보관_2026-09-26_7f3a9c2e.7z"), "7f3a9c2e");
  assert.equal(DPG.tagFrom("7f3a9c2e"), "7f3a9c2e");
  assert.equal(DPG.tagFrom("그냥 파일.7z"), null);
});

test("the tool is self-contained: no network, no external files, nothing stored", () => {
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+href=|https?:\/\/(?!www\.w3)/);
  assert.doesNotMatch(html, /fetch\(|XMLHttpRequest|localStorage|sessionStorage|indexedDB|document\.cookie/);
  assert.match(html, /default-src 'none'/);
});

test("the website copy is the same file", () => {
  const site = fs.readFileSync(path.join(HERE, "..", "..", "..", "site", "public", "recover.html"), "utf8");
  assert.equal(site, html, "copy src/dpg/resources/recovery-tool.html to site/public/recover.html");
});
