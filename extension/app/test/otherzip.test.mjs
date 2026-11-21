// D-112: a ZIP made by the extension opens with other programs and the password alone — Info-ZIP
// unzip, libarchive (bsdtar: macOS / Windows tar.exe) and Python's zipfile — byte for byte, with
// Korean names and folders. Each tool is skipped only when it is not installed.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import "./helpers.mjs";
import { createArchive } from "../lib/vault.js";

const PW = "Other-Zip-Test_2026!"; // synthetic; printable ASCII like the common-password rule
const enc = (s) => new TextEncoder().encode(s);
const big = new Uint8Array(300000).map((_, i) => (i * 7919) % 251);
const FILES = new Map([
  ["상담기록_가상.txt", enc("가상 상담 기록\n")],
  ["학급자료/6-2 학생 연락처.csv", enc("이름,번호\n가상,010-0000-0000\n")],
  ["학급자료/하위/표.bin", big],
  ["빈파일.txt", new Uint8Array(0)],
]);
const has = (cmd, args) => spawnSync(cmd, args, { encoding: "utf8" }).status !== null && !spawnSync(cmd, args).error;

function walk(dir, prefix = "") {
  const out = new Map();
  for (const n of fs.readdirSync(dir)) {
    const p = path.join(dir, n);
    if (fs.statSync(p).isDirectory()) for (const [k, v] of walk(p, `${prefix}${n}/`)) out.set(k, v);
    else out.set((prefix + n).normalize("NFC"), new Uint8Array(fs.readFileSync(p)));
  }
  return out;
}
function same(got) {
  assert.deepEqual([...got.keys()].sort(), [...FILES.keys()].sort());
  for (const [k, v] of FILES) assert.ok(Buffer.from(got.get(k)).equals(Buffer.from(v)), k);
}

const zip = await createArchive(FILES, PW, "zip");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dpg-zip-"));
const file = path.join(dir, "보관.zip");
fs.writeFileSync(file, zip);
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test("Info-ZIP unzip opens it with the password", { skip: !has("unzip", ["-v"]) }, () => {
  const out = path.join(dir, "unzip");
  const r = spawnSync("unzip", ["-q", "-P", PW, file, "-d", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  same(walk(out));
  const wrong = spawnSync("unzip", ["-q", "-o", "-P", "wrong-password", file, "-d", path.join(dir, "w")], { encoding: "utf8" });
  assert.notEqual(wrong.status, 0, "a wrong password is refused");
});

test("libarchive (bsdtar — macOS, Windows tar.exe) opens it with the password", { skip: !has("bsdtar", ["--version"]) }, () => {
  const out = path.join(dir, "bsdtar");
  fs.mkdirSync(out);
  const r = spawnSync("bsdtar", ["-x", "--passphrase", PW, "-f", file, "-C", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  same(walk(out));
});

test("Python zipfile opens it with the password (names flagged UTF-8, ZipCrypto, no Zip64)", { skip: !has("python3", ["--version"]) }, () => {
  const code = `
import sys, zipfile, json, hashlib
z = zipfile.ZipFile(sys.argv[1])
out = {}
for i in z.infolist():
    if i.is_dir(): continue  # folder entries hold no data
    assert i.flag_bits & 0x1, "encrypted: " + i.filename
    assert i.flag_bits & 0x800, "UTF-8 name flag"
    assert i.compress_type == 0, "stored"
    out[i.filename] = hashlib.sha256(z.read(i, pwd=sys.argv[2].encode())).hexdigest()
print(json.dumps(out))`;
  const r = spawnSync("python3", ["-I", "-c", code, file, PW], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout);
  const { createHash } = globalThis.process.getBuiltinModule("node:crypto");
  const want = Object.fromEntries([...FILES].map(([k, v]) => [k, createHash("sha256").update(v).digest("hex")]));
  assert.deepEqual(got, want);
});
