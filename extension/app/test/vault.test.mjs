// Interop with archives made by the desktop app + the recovery key, all in memory.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { FIX, SYN, read, recoveryKey } from "./helpers.mjs";
import { openArchive, passwordFor, parseRecoveryKey, derivePassword, tagFromName, create7z, WrongPassword } from "../lib/vault.js";

const ARCHIVES = fs.readdirSync(FIX).filter((n) => /^보관_.*\.(7z|zip)$/.test(n));

test("fixtures exist (7z and AES-ZIP from the desktop app)", () => {
  assert.equal(ARCHIVES.length, 2);
});

for (const name of ARCHIVES) {
  test(`opens ${name.slice(-6)} with the recovery key, rejects a wrong password`, async () => {
    const bytes = read(path.join(FIX, name));
    const pw = await passwordFor(name, recoveryKey().toLowerCase().replaceAll("-", " "));
    const files = await openArchive(bytes, pw);
    assert.deepEqual([...files.keys()].sort(), ["6-2_학생_연락처.csv", "6-2_학생_연락처.xlsx", "상담기록_가상.hwp", "학생명단_가상.hwpx"].sort());
    for (const [n, data] of files) assert.deepEqual(data, read(path.join(SYN, n)), n);
    await assert.rejects(openArchive(bytes, "Wrong-Pass-0000"), WrongPassword);
    await assert.rejects(openArchive(bytes, ""), WrongPassword);
  });
}

test("recovery key: same derivation as the desktop app, typo detection", async () => {
  const key = recoveryKey();
  const raw = await parseRecoveryKey(key);
  assert.ok(raw);
  const pwLine = fs.readFileSync(path.join(FIX, "recovery.txt"), "utf8").split("\n")[1];
  const pythonFingerprints = pwLine.replace(/^.*check values: /, "").trim().split(" ");
  const { createHash } = await import("node:crypto");
  const fp = (s) => createHash("sha256").update(s).digest("hex").slice(0, 16);
  assert.equal(fp(await derivePassword(raw, "0a1b2c3d")), pythonFingerprints[0]);
  assert.equal(fp(await derivePassword(raw, "4e5f6a7b")), pythonFingerprints[1]);
  const typo = key.slice(0, 3) + (key[3] === "A" ? "B" : "A") + key.slice(4);
  assert.equal(await parseRecoveryKey(typo), null);
  assert.equal(await passwordFor("보관_2026-09-27_0a1b2c3d.7z", "plain-password"), "plain-password");
  assert.equal(tagFromName("보관_2026-09-27_7f3a.7z"), null); // made before recovery keys
  assert.equal(tagFromName("상담기록.hwp (암호화 7f3a9c2e).7z"), "7f3a9c2e"); // D-087, same as the desktop app
  assert.equal(tagFromName("상담기록.hwp 외 2개 (암호화 0a1b2c3d).zip"), "0a1b2c3d");
});

test("extension-made 7z round trip (header encrypted, names hidden)", async () => {
  const files = new Map([["가상_메모.txt", new TextEncoder().encode("hello")]]);
  const blob = await create7z(files, "Aa1-roundtrip");
  assert.ok(!Buffer.from(blob).includes(Buffer.from("가상_메모")));
  const back = await openArchive(blob, "Aa1-roundtrip");
  assert.equal(new TextDecoder().decode(back.get("가상_메모.txt")), "hello");
});

test("extension archives are stored without compression (user request) but still encrypted", async () => {
  const zeros = new Uint8Array(200000); // would shrink to almost nothing if compressed
  const blob = await create7z(new Map([["폴더/하위/빈칸.bin", zeros]]), "Aa1-store-test");
  assert.ok(blob.length > 200000, `stored, not compressed (${blob.length} bytes)`);
  const back = await openArchive(blob, "Aa1-store-test");
  assert.deepEqual([...back.keys()], ["폴더/하위/빈칸.bin"]);
  await assert.rejects(openArchive(blob, "wrong-password"), WrongPassword);
});
