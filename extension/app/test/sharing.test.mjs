// D-091: sharing audit/changes use the desktop app's rules.
import test from "node:test";
import assert from "node:assert/strict";
import { internalDomains, view, exposureOf, plan, apply, undo, EXPOSURE } from "../lib/sharing.js";

const me = "teacher@school.example";
const internal = internalDomains(me);
const perms = [
  { id: "own", type: "user", role: "owner", emailAddress: me },
  { id: "col", type: "user", role: "writer", emailAddress: "colleague@school.example" },
  { id: "ext", type: "user", role: "writer", emailAddress: "parent@gmail.com" },
  { id: "inh", type: "user", role: "reader", emailAddress: "other@gmail.com", permissionDetails: [{ inherited: true }] },
  { id: "any", type: "anyone", role: "writer" },
  { id: "dom", type: "domain", role: "reader", domain: "school.example" },
];
const views = perms.map((p) => view(p, me, internal));

test("internal = own domain, but never gmail.com", () => {
  assert.deepEqual([...internalDomains(me)], ["school.example"]);
  assert.deepEqual([...internalDomains("someone@gmail.com")], []);
});

test("exposure levels like the desktop app", () => {
  assert.equal(exposureOf(views), EXPOSURE.LINK_EDIT);
  assert.equal(exposureOf(views.filter((v) => v.type !== "anyone")), EXPOSURE.EXTERNAL);
  assert.equal(exposureOf(views.filter((v) => ["own", "col", "dom"].includes(v.id))), EXPOSURE.DOMAIN);
  assert.equal(exposureOf(views.filter((v) => ["own", "col"].includes(v.id))), EXPOSURE.RESTRICTED);
});

test("plans change only direct permissions; owner, me and inherited are skipped", () => {
  const all = plan(views, "restrict_all");
  assert.deepEqual(all.changes.map((c) => c.perm.id), ["ext", "any", "dom"]);
  assert.deepEqual(all.skips.map((s) => [s.perm.id, s.reason.slice(0, 7)]), [["inh", "상위 폴더에서"]]);
  assert.deepEqual(plan(views, "link_to_view").changes.map((c) => [c.perm.id, c.op, c.role]), [["any", "role", "reader"]]);
  assert.deepEqual(plan(views, "editors_to_viewers").changes.map((c) => c.perm.id), ["col", "ext"]);
  assert.deepEqual(plan(views, "remove_external").changes.map((c) => c.perm.id), ["ext"]);
});

test("apply records what it did; undo re-creates without e-mail and restores roles", async () => {
  const calls = [];
  const drive = {
    deletePermission: async (f, p) => { calls.push(["del", f, p]); if (p === "dom") throw new Error("403"); },
    updatePermission: async (f, p, r) => { calls.push(["role", f, p, r]); },
    createPermission: async (f, p) => { calls.push(["create", f, p]); },
  };
  const items = [{ fileId: "F1", name: "a", changes: [...plan(views, "restrict_all").changes, ...plan(views, "link_to_view").changes] }];
  const r = await apply(items, drive);
  assert.equal(r.failed.length, 1);
  assert.equal(r.done.length, 3);
  await undo(r.done, drive);
  const undone = calls.slice(4);
  assert.deepEqual(undone[0], ["role", "F1", "any", "writer"]);
  assert.deepEqual(undone.at(-1), ["create", "F1", { type: "user", role: "writer", emailAddress: "parent@gmail.com", domain: undefined, allowFileDiscovery: undefined }]);
});
