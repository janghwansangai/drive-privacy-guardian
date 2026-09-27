import test from "node:test";
import assert from "node:assert/strict";
import { restoreToDrive, restorePlan, mimeOf, RestoreFailed } from "../lib/restore.js";

const enc = (s) => new TextEncoder().encode(s);
function fakeDrive({ corrupt = false } = {}) {
  const store = new Map();
  const calls = [];
  return {
    store, calls,
    async upload(name, parent, bytes, mime) { calls.push(["upload", name, parent, mime]); const id = `id${store.size}`; const b = bytes.slice(); if (corrupt) b[0] ^= 1; store.set(id, b); return { id }; },
    async download({ id }) { calls.push(["download", id]); return store.get(id).slice(); },
    async trash(id) { calls.push(["trash", id]); },
    async createFolder(name, parent) { calls.push(["folder", name, parent]); return { id: `dir-${name}` }; },
  };
}

test("plan: folders kept, duplicates numbered per folder; MIME by extension", () => {
  assert.deepEqual(restorePlan(["a.hwp", "폴더/a.hwp", "b", "b"]), [
    { dir: "", name: "a.hwp" }, { dir: "폴더", name: "a.hwp" }, { dir: "", name: "b" }, { dir: "", name: "b (2)" },
  ]);
  assert.equal(mimeOf("표.XLSX"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  assert.equal(mimeOf("x.unknown"), "application/octet-stream");
});

test("every file uploaded to the archive's folder and checked, then the archive is trashed", async () => {
  const drive = fakeDrive();
  const members = new Map([["상담기록.hwp", enc("h")], ["폴더/명단.xlsx", enc("x")]]);
  const r = await restoreToDrive({ members, parent: "F", archiveId: "ARC", trashArchive: true, drive });
  assert.ok(r.allVerified && r.trashedArchive);
  assert.deepEqual(drive.calls.filter((c) => c[0] === "upload").map((c) => [c[1], c[2]]), [["상담기록.hwp", "F"], ["명단.xlsx", "dir-폴더"]]);
  assert.deepEqual(drive.calls.filter((c) => c[0] === "folder"), [["folder", "폴더", "F"]]);
  assert.deepEqual(drive.calls.at(-1), ["trash", "ARC"]);
});

test("a failed check keeps the archive; trash only when asked; upload errors stop", async () => {
  const bad = fakeDrive({ corrupt: true });
  const r = await restoreToDrive({ members: new Map([["a.txt", enc("a")]]), parent: "F", archiveId: "ARC", trashArchive: true, drive: bad });
  assert.equal(r.allVerified, false);
  assert.ok(!bad.calls.some((c) => c[0] === "trash"));
  const keep = fakeDrive();
  await restoreToDrive({ members: new Map([["a.txt", enc("a")]]), parent: "F", archiveId: "ARC", trashArchive: false, drive: keep });
  assert.ok(!keep.calls.some((c) => c[0] === "trash"));
  const failing = fakeDrive();
  failing.upload = async () => { throw new Error("구글 드라이브 오류 (500)"); };
  await assert.rejects(restoreToDrive({ members: new Map([["a.txt", enc("a")]]), parent: "F", archiveId: "ARC", trashArchive: true, drive: failing }), RestoreFailed);
});

test("a folder archive comes back as the same folder tree", async () => {
  const drive = fakeDrive();
  const members = new Map([["학급자료/명단.csv", enc("c")], ["학급자료/하위/메모.txt", enc("m")], ["학급자료/하위/표.xlsx", enc("x")]]);
  const r = await restoreToDrive({ members, parent: "F", archiveId: "ARC", trashArchive: true, drive });
  assert.deepEqual(drive.calls.filter((c) => c[0] === "folder"), [["folder", "학급자료", "F"], ["folder", "하위", "dir-학급자료"]]);
  assert.deepEqual(r.files.map((f) => f.name), ["학급자료/명단.csv", "학급자료/하위/메모.txt", "학급자료/하위/표.xlsx"]);
});
