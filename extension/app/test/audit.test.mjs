// D-092: whole-Drive sharing audit (metadata only).
import test from "node:test";
import assert from "node:assert/strict";
import { buildAudit, summary, peopleLine } from "../lib/audit.js";
import { internalDomains, plan } from "../lib/sharing.js";

const me = "teacher@school.example";
const internal = internalDomains(me);
const own = { id: "o", type: "user", role: "owner", emailAddress: me };
const files = [
  { id: "F", name: "학급자료", mimeType: "application/vnd.google-apps.folder", shared: true, parents: ["root"], permissions: [own, { id: "a", type: "anyone", role: "reader" }] },
  { id: "c", name: "명단.xlsx", shared: true, parents: ["F"], permissions: [own, { id: "a", type: "anyone", role: "reader" }, { id: "x", type: "user", role: "writer", emailAddress: "parent@gmail.com" }] },
  { id: "p", name: "개인.hwp", shared: false, parents: ["root"], permissions: [own] },
  { id: "i", name: "동료만.docx", shared: true, parents: ["root"], permissions: [own, { id: "k", type: "user", role: "writer", emailAddress: "colleague@school.example" }] },
];

test("only shared-and-exposed items, folders first, paths from shared parents", () => {
  const items = buildAudit(files, me, internal);
  assert.deepEqual(items.map((it) => it.file.id), ["F", "c"]); // colleague-only = restricted, not listed
  assert.equal(items[1].path, "학급자료/");
  assert.deepEqual(summary(items), { total: 2, counts: [0, 0, 0, 2, 0] });
  assert.equal(peopleLine(items[1].views), "링크(보기) · parent@gmail.com");
});

test("a permission the parent folder also has is treated as inherited (change it on the folder)", () => {
  const items = buildAudit(files, me, internal);
  const child = items.find((it) => it.file.id === "c");
  const p = plan(child.views, "restrict_all");
  assert.deepEqual(p.changes.map((c) => c.perm.id), ["x"]); // the external user was added directly
  assert.deepEqual(p.skips.map((s) => s.perm.id), ["a"]); // the link comes from 학급자료
  const folder = plan(items[0].views, "restrict_all");
  assert.deepEqual(folder.changes.map((c) => c.perm.id), ["a"]);
});
