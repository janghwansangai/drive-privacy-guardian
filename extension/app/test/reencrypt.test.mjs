// E3: re-encrypt → verify → upload → re-check → trash old, against a fake Drive (synthetic data).
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { FIX, read, recoveryKey } from "./helpers.mjs";
import { openArchive, passwordFor, parseRecoveryKey, tagFromName } from "../lib/vault.js";
import { planMembers, reencrypt, ReencryptFailed } from "../lib/reencrypt.js";

const enc = (s) => new TextEncoder().encode(s);
const existing = () => new Map([["메모.txt", enc("old")], ["폴더/표.csv", enc("a,b")], ["사진.png", enc("png")]]);

function fakeDrive({ corruptUpload = false, denyParent = false } = {}) {
  const store = new Map();
  const calls = [];
  return {
    store, calls,
    async upload(name, parent, bytes) {
      calls.push(["upload", name, parent]);
      if (denyParent && parent) { const e = new Error("403"); e.status = 403; throw e; }
      const id = `id${store.size}`;
      const kept = bytes.slice();
      if (corruptUpload) kept[kept.length - 1] ^= 1;
      store.set(id, { name, parent, bytes: kept });
      return { id, name };
    },
    async download({ id }) { calls.push(["download", id]); return store.get(id).bytes.slice(); },
    async trash(id) { calls.push(["trash", id]); },
  };
}

test("plan: same base name replaces (keeps the folder), new names are added, removed ones dropped", () => {
  const { files, rows } = planMembers(existing(), [{ name: "표.csv", bytes: enc("NEW") }, { name: "추가.hwp", bytes: enc("h") }], new Set(["사진.png"]));
  assert.deepEqual(rows, [
    { name: "메모.txt", state: "그대로" }, { name: "폴더/표.csv", state: "바꿈" },
    { name: "사진.png", state: "뺌" }, { name: "추가.hwp", state: "추가" },
  ]);
  assert.equal(new TextDecoder().decode(files.get("폴더/표.csv")), "NEW");
  assert.ok(!files.has("사진.png"));
});

test("recovery key: new archive gets its own tag and opens with the same key; old one trashed after checks", async () => {
  const raw = await parseRecoveryKey(recoveryKey());
  const drive = fakeDrive();
  const { files } = planMembers(existing(), [{ name: "메모.txt", bytes: enc("edited") }]);
  const steps = [];
  const r = await reencrypt({ files, secret: { raw }, parent: "folderA", trashIds: ["OLD"], trashOld: true, drive, onStep: (s) => steps.push(s) });
  assert.match(r.name, /^보관_\d{4}-\d{2}-\d{2}_[0-9a-f]{8}\.7z$/);
  assert.ok(r.verified && r.uploadVerified && r.trashedOld && !r.parentFallback);
  assert.deepEqual(drive.calls.map((c) => c[0]), ["upload", "download", "trash"]);
  assert.equal(drive.calls[0][2], "folderA");
  assert.equal(steps.length, 5);
  const up = drive.store.get(r.id);
  const back = await openArchive(up.bytes, await passwordFor(r.name, recoveryKey()));
  assert.equal(new TextDecoder().decode(back.get("메모.txt")), "edited");
  assert.equal(new TextDecoder().decode(back.get("폴더/표.csv")), "a,b");
  assert.notEqual(tagFromName(r.name), "0a1b2c3d");
});

test("upload check fails → the old archive is NOT trashed", async () => {
  const drive = fakeDrive({ corruptUpload: true });
  const r = await reencrypt({ files: existing(), secret: { password: "Typed-pass-99" }, parent: "p", trashIds: ["OLD"], trashOld: true, drive });
  assert.equal(r.uploadVerified, false);
  assert.equal(r.trashedOld, false);
  assert.ok(!drive.calls.some((c) => c[0] === "trash"));
});

test("typed password is reused; trash only when asked; folder refused → top of My Drive", async () => {
  const drive = fakeDrive({ denyParent: true });
  const r = await reencrypt({ files: existing(), secret: { password: "Typed-pass-99" }, parent: "p", trashIds: ["OLD"], trashOld: false, drive });
  assert.ok(r.parentFallback);
  assert.deepEqual(drive.calls.map((c) => c[0]), ["upload", "upload", "download"]);
  assert.deepEqual([drive.calls[0][2], drive.calls[1][2]], ["p", null]);
  assert.ok((await openArchive(drive.store.get(r.id).bytes, "Typed-pass-99")).has("메모.txt"));
});

test("nothing to archive / other upload errors stop before touching the old archive", async () => {
  await assert.rejects(reencrypt({ files: new Map(), secret: { password: "x" }, drive: fakeDrive() }), ReencryptFailed);
  const drive = fakeDrive();
  drive.upload = async () => { const e = new Error("구글 드라이브 오류 (500)"); e.status = 500; throw e; };
  await assert.rejects(reencrypt({ files: existing(), secret: { password: "Typed-pass-99" }, parent: "p", trashIds: ["OLD"], trashOld: true, drive }), /예전 보관 파일은 그대로/);
});

test("desktop-made archive → re-encrypted by the extension keeps every file byte-identical", async () => {
  const name = "보관_2026-09-27_0a1b2c3d.7z";
  const members = await openArchive(read(path.join(FIX, name)), await passwordFor(name, recoveryKey()));
  const raw = await parseRecoveryKey(recoveryKey());
  const drive = fakeDrive();
  const r = await reencrypt({ files: members, secret: { raw }, parent: null, drive });
  const back = await openArchive(drive.store.get(r.id).bytes, await passwordFor(r.name, recoveryKey()));
  assert.deepEqual([...back.keys()].sort(), [...members.keys()].sort());
  for (const [n, d] of members) assert.deepEqual(back.get(n), d, n);
});

test("several Drive originals are trashed only after both checks; partial failures are reported", async () => {
  const drive = fakeDrive();
  const failing = new Set(["B"]);
  drive.trash = async (id) => { drive.calls.push(["trash", id]); if (failing.has(id)) throw new Error("403"); };
  const r = await reencrypt({ files: existing(), secret: { password: "Typed-pass-99" }, parent: "p", trashIds: ["A", "B", "C"], trashOld: true, drive });
  assert.deepEqual(drive.calls.filter((c) => c[0] === "trash").map((c) => c[1]), ["A", "B", "C"]);
  assert.equal(r.trashedOld, false);
  assert.equal(r.trashFailed, 1);
  await assert.rejects(reencrypt({ files: existing(), secret: { password: "x-12345678" }, trashIds: ["bad id"], trashOld: true, drive }), ReencryptFailed);
});
