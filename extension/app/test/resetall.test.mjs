// D-112: 「모두 풀기 (초기화)」 — every archive back to normal files, all-or-nothing per archive.
import test from "node:test";
import assert from "node:assert/strict";
import { recoveryKey } from "./helpers.mjs";
import { createArchive, derivePassword, parseRecoveryKey } from "../lib/vault.js";
import { resetAll, candidates } from "../lib/resetall.js";

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const PW = "Reset-test-2026"; // synthetic

function fakeDrive(archives) {
  const store = new Map(archives.map((a) => [a.id, a.bytes]));
  const calls = [];
  let n = 0;
  return {
    store, calls,
    async download({ id }) { calls.push(["download", id]); return store.get(id).slice(); },
    async upload(name, parent, bytes) { const id = `up${n++}`; calls.push(["upload", name, parent]); store.set(id, bytes.slice()); return { id }; },
    async createFolder(name, parent) { const id = `dir${n++}`; calls.push(["folder", name, parent]); return { id }; },
    async trash(id) { calls.push(["trash", id]); },
  };
}

test("each archive opens with a typed password or the recovery key, is restored, checked, then trashed", async () => {
  const raw = await parseRecoveryKey(recoveryKey());
  const zip = await createArchive(new Map([["학급자료/명단.csv", enc("이름,번호")], ["학급자료/메모.txt", enc("메모")]]), PW, "zip");
  const tag = "a1b2c3d4";
  const sevenZ = await createArchive(new Map([["상담.txt", enc("상담")]]), await derivePassword(raw, tag), "7z");
  const other = await createArchive(new Map([["x.txt", enc("x")]]), "Other-pass-1", "zip");
  const archives = [
    { id: "Z1", name: "학급자료 (암호화 0badf00d).zip", parents: ["F"], bytes: zip },
    { id: "S1", name: `상담.txt (암호화 ${tag}).7z`, parents: ["G"], bytes: sevenZ },
    { id: "O1", name: "x.txt (암호화 12345678).zip", parents: ["F"], bytes: other },
  ];
  const drive = fakeDrive(archives);
  const r = await resetAll({ archives, typed: [PW], raw, drive });
  assert.deepEqual(r.map((x) => [x.name, x.ok]), [[archives[0].name, true], [archives[1].name, true], [archives[2].name, false]]);
  assert.match(r[2].reason, /비밀번호가 맞지 않음/);
  const trashed = drive.calls.filter((c) => c[0] === "trash").map((c) => c[1]);
  assert.deepEqual(trashed, ["Z1", "S1"]); // the one that did not open is untouched
  assert.deepEqual(drive.calls.filter((c) => c[0] === "folder"), [["folder", "학급자료", "F"]]);
  const ups = drive.calls.filter((c) => c[0] === "upload").map((c) => c[1]);
  assert.deepEqual(ups.slice().sort(), ["메모.txt", "명단.csv", "상담.txt"]);
  const contents = [...drive.store.entries()].filter(([id]) => id.startsWith("up")).map(([, b]) => dec(b)).sort();
  assert.deepEqual(contents, ["메모", "상담", "이름,번호"]);
});

test("a typed recovery key works as a password; a failed check leaves the archive", async () => {
  const raw = await parseRecoveryKey(recoveryKey());
  const tag = "0a0b0c0d";
  assert.deepEqual(await candidates(`a (암호화 ${tag}).zip`, [recoveryKey()], null), [await derivePassword(raw, tag)]);
  const zip = await createArchive(new Map([["a.txt", enc("a")]]), PW, "zip");
  const archives = [{ id: "Z", name: "a.txt (암호화 11112222).zip", parents: ["F"], bytes: zip }];
  const drive = fakeDrive(archives);
  drive.download = async ({ id }) => { const b = drive.store.get(id).slice(); if (id.startsWith("up")) b[0] ^= 1; return b; };
  const r = await resetAll({ archives, typed: [PW], drive });
  assert.equal(r[0].ok, false);
  assert.match(r[0].reason, /되돌림/);
  assert.ok(!drive.calls.some((c) => c[0] === "trash" && c[1] === "Z"));
});
