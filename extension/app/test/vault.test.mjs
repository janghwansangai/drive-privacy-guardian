// Interop with archives made by the desktop app + the recovery key, all in memory.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { COMMON_TEST_TAG, FIX, SYN, read, recoveryKey } from "./helpers.mjs";
import { openArchive, passwordFor, parseRecoveryKey, derivePassword, tagFromName, create7z, createArchive, newArchiveName, WrongPassword } from "../lib/vault.js";

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

// D-107: the default archive is a standard ZIP that Windows Explorer / macOS open with the password alone.
const COMMON = await derivePassword(await parseRecoveryKey(recoveryKey()), COMMON_TEST_TAG);
const STD = "상담기록_가상.hwp 외 3개 (암호화 6c7d8e9f).zip";

test("D-107: a desktop-made standard ZIP opens here with the common password alone", async () => {
  const back = await openArchive(read(path.join(FIX, STD)), COMMON);
  assert.deepEqual([...back.keys()].sort(), ["6-2_학생_연락처.csv", "6-2_학생_연락처.xlsx", "상담기록_가상.hwp", "학생명단_가상.hwpx"]);
  for (const [n, d] of back) assert.deepEqual(d, read(path.join(SYN, n)), n);
  await assert.rejects(openArchive(read(path.join(FIX, STD)), `${COMMON}x`), WrongPassword);
});

test("D-107: extension-made ZIP is classic ZipCrypto with UTF-8 names (opens without any program)", async () => {
  const files = new Map([["가상_메모.txt", new TextEncoder().encode("hello")], ["폴더/표.csv", new TextEncoder().encode("a,b")]]);
  const blob = await createArchive(files, COMMON, "zip");
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  assert.equal(dv.getUint32(0, true), 0x04034b50); // local file header
  const flags = dv.getUint16(6, true);
  assert.ok(flags & 0x0001, "encrypted");
  assert.ok(flags & 0x0800, "UTF-8 names (Korean names stay readable)");
  assert.notEqual(dv.getUint16(8, true), 99, "not WinZip AES (Explorer cannot open that)");
  assert.ok(Buffer.from(blob).includes(Buffer.from("가상_메모.txt")), "names are visible in a standard ZIP (UI says so)");
  assert.ok(!Buffer.from(blob).includes(Buffer.from("hello")), "contents are not");
  const back = await openArchive(blob, COMMON);
  assert.deepEqual([...back.keys()].sort(), ["가상_메모.txt", "폴더/표.csv"]);
  await assert.rejects(openArchive(blob, "wrong-password"), WrongPassword);
  await assert.rejects(createArchive(files, COMMON, "rar"));
});

test("new archive names end in .zip by default, .7z for high security", () => {
  assert.match(newArchiveName(["상담기록.hwp"]), /^상담기록\.hwp \(암호화 [0-9a-f]{8}\)\.zip$/);
  assert.match(newArchiveName(["a.txt", "b.txt"], new Date(), "7z"), /^a\.txt 외 1개 \(암호화 [0-9a-f]{8}\)\.7z$/);
  assert.match(newArchiveName([], new Date(2026, 9, 25)), /^보관_2026-10-25_[0-9a-f]{8}\.zip$/);
});

test("D-104: password derivation is pinned (same values as the desktop app, v0.2.5)", async () => {
  const { parseRecoveryKey, derivePassword } = await import("../lib/vault.js");
  const raw = await parseRecoveryKey(recoveryKey());
  // If this fails, archives already on people's drives would stop opening: fix the code, not the values.
  assert.equal(await derivePassword(raw, "0a1b2c3d"), "KZaY-wJRt-lIAZ-LNoc-uQo3-ptSc");
  assert.equal(await derivePassword(raw, "ffffffff"), "Biud-RZi9-qz2p-pqN5-HdM1-uL2i");
});
