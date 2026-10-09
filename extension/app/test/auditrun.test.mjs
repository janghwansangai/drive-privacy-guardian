// D-101: the sharing audit goes page by page and can always go on from where it stopped.
import test from "node:test";
import assert from "node:assert/strict";
import { newRun, step, where, SPLIT_SEEN } from "../lib/auditrun.js";

const FOLDER = "application/vnd.google-apps.folder";
const NOW = new Date("2026-10-09T12:00:00Z");

/** A tiny fake of files.list: understands the queries auditrun.js sends. */
function fakeDrive(files, pageSize = 3) {
  const calls = [];
  const listPage = async ({ q, pageToken }) => {
    calls.push({ q, pageToken });
    if (pageToken === "expired") { const e = new Error("bad token"); e.status = 400; throw e; }
    let hits;
    const parent = /^'([\w-]+)' in parents/.exec(q);
    if (parent) hits = files.filter((f) => f.parents?.[0] === parent[1]);
    else {
      const lo = /createdTime >= '([^']+)'/.exec(q)?.[1];
      const hi = /createdTime < '([^']+)'/.exec(q)?.[1];
      hits = files.filter((f) => f.mine !== false && (!lo || f.createdTime >= lo) && (!hi || f.createdTime < hi));
    }
    const start = Number(pageToken || 0);
    const next = start + pageSize < hits.length ? String(start + pageSize) : undefined;
    return { files: hits.slice(start, start + pageSize), nextPageToken: next };
  };
  return { listPage, calls };
}

const file = (id, extra = {}) => ({ id: `${id}`.padEnd(12, "0"), name: id, mimeType: "text/plain", shared: false, createdTime: "2026-01-02T00:00:00Z", ...extra });

async function runAll(run, listPage, max = 1000) {
  for (let i = 0; i < max && run.status !== "done"; i++) await step(run, listPage, NOW);
  return run;
}

test("whole drive: keeps only shared files, ends done", async () => {
  const files = [file("a", { shared: true }), file("b"), file("c", { shared: true }), file("d"), file("e")];
  const { listPage } = fakeDrive(files);
  const run = await runAll(newRun({ kind: "drive" }, NOW), listPage);
  assert.equal(run.status, "done");
  assert.equal(run.seen, 5);
  assert.deepEqual(run.files.map((f) => f.name), ["a", "c"]);
  assert.equal(where(run), "내 드라이브 전체");
});

test("stopped after a page, then continued from the saved state (as JSON)", async () => {
  const files = Array.from({ length: 10 }, (_, i) => file(`f${i}`, { shared: i % 2 === 0 }));
  const { listPage, calls } = fakeDrive(files);
  const run = newRun({ kind: "drive" }, NOW);
  await step(run, listPage, NOW); // one page, then the panel closes
  const saved = JSON.parse(JSON.stringify(run)); // what chrome.storage.session keeps
  assert.equal(saved.status, "running");
  assert.equal(saved.files.length, 2); // partial results are already there
  calls.length = 0;
  await runAll(saved, listPage);
  assert.equal(calls[0].pageToken, "3"); // went on, did not start over
  assert.equal(saved.files.length, 5);
});

test("big drive: switches to createdTime windows and says where it is", async () => {
  const files = Array.from({ length: 40 }, (_, i) => file(`g${i}`, { shared: i % 4 === 0, createdTime: `${2010 + (i % 17)}-0${1 + (i % 9)}-15T00:00:00Z` }));
  const { listPage, calls } = fakeDrive(files, 5);
  const run = newRun({ kind: "drive" }, NOW);
  run.seen = SPLIT_SEEN; // pretend a lot was already counted
  await step(run, listPage, NOW);
  assert.ok(run.windows, "windows started");
  assert.match(where(run), /^내 드라이브 전체 · 2012년 이전에 만든 파일 \(1\/\d+\)$/);
  await runAll(run, listPage);
  assert.equal(run.status, "done");
  assert.equal(run.files.length, 10); // every shared file found once (the first page re-read, no duplicates)
  assert.ok(calls.some((c) => c.q.includes("createdTime >= '2026-07-01T00:00:00'")));
});

test("an expired page token re-reads that part only", async () => {
  const files = Array.from({ length: 6 }, (_, i) => file(`h${i}`, { shared: true }));
  const { listPage } = fakeDrive(files);
  const run = newRun({ kind: "drive" }, NOW);
  await step(run, listPage, NOW);
  run.token = "expired";
  await runAll(run, listPage);
  assert.equal(run.files.length, 6);
});

test("folder scope: folder by folder, with the folder being read", async () => {
  const top = "top000000000";
  const sub = "sub000000000";
  const files = [
    file("명단.xlsx", { parents: [top], shared: true }),
    { id: sub, name: "하위", mimeType: FOLDER, parents: [top], shared: true },
    file("메모.txt", { parents: [sub], shared: true }),
    file("outside", { shared: true }),
  ];
  const { listPage } = fakeDrive(files);
  const run = newRun({ kind: "folder", id: top, name: "학급자료" }, NOW);
  assert.equal(where(run), "폴더 학급자료/");
  await step(run, listPage, NOW);
  assert.equal(where(run), "폴더 학급자료/하위/");
  await runAll(run, listPage);
  assert.equal(run.status, "done");
  assert.deepEqual(run.files.map((f) => f.name).sort(), ["메모.txt", "명단.xlsx", "하위"]);
  assert.equal(where(run), "폴더 「학급자료」 전체");
});

test("the saved state keeps only what the audit needs, with the same verdicts", async () => {
  const { buildAudit } = await import("../lib/audit.js");
  const { internalDomains } = await import("../lib/sharing.js");
  const me = "teacher@school.example";
  const full = {
    id: "share0000001", name: "명단.xlsx", mimeType: "x", shared: true, parents: ["p000000000001"], modifiedTime: "2026-01-01", webViewLink: "https://…", size: "1234",
    permissions: [
      { id: "o", type: "user", role: "owner", emailAddress: me, displayName: "선생님", photoLink: "https://…" },
      { id: "x", type: "user", role: "writer", emailAddress: "parent@gmail.com", displayName: "학부모", permissionDetails: [{ inherited: true, permissionType: "file" }] },
      { id: "a", type: "anyone", role: "reader", allowFileDiscovery: false },
    ],
  };
  const { compact } = await import("../lib/auditrun.js");
  const c = compact(full);
  assert.ok(JSON.stringify(c).length < JSON.stringify(full).length * 0.75);
  assert.equal(c.photoLink, undefined);
  const internal = internalDomains(me);
  const strip = (items) => items.map((it) => ({ e: it.exposure, v: it.views.map((v) => [v.id, v.type, v.role, v.email, v.inherited, v.external]) }));
  assert.deepEqual(strip(buildAudit([c], me, internal)), strip(buildAudit([full], me, internal)));
});
