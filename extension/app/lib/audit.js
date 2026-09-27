// Whole-Drive sharing audit (D-092), like the desktop app's scan: every file I own is listed with
// its permissions (metadata only — no file contents are downloaded), shared ones are classified
// with lib/sharing.js, and permissions that a parent folder already gives are marked as probably
// inherited (My Drive does not say so; the desktop app infers it the same way, D-054).

import { view, exposureOf } from "./sharing.js";

export const FOLDER = "application/vnd.google-apps.folder";
const key = (v) => `${v.type}|${v.role}|${v.email || ""}|${v.domain || ""}`;

/**
 * files: [{ id, name, mimeType, shared, parents, permissions }] (only shared ones matter)
 * Returns items sorted folders-first then by risk: [{ file, views, exposure, path }]
 */
export function buildAudit(files, me, internal) {
  const shared = files.filter((f) => f.shared && Array.isArray(f.permissions));
  const byId = new Map(shared.map((f) => [f.id, f]));
  const views = new Map(shared.map((f) => [f.id, f.permissions.map((p) => view(p, me, internal))]));
  const pathOf = (f, depth = 0) => {
    const up = byId.get(f.parents?.[0]);
    return up && depth < 30 ? `${pathOf(up, depth + 1)}${up.name}/` : "";
  };
  const items = shared.map((f) => {
    const own = views.get(f.id);
    // the same permission on the (shared) parent folder → it probably comes from there
    const parentKeys = new Set((views.get(f.parents?.[0]) || []).filter((v) => !v.owner).map(key));
    const vs = own.map((v) => (!v.owner && !v.inherited && parentKeys.has(key(v)) ? { ...v, inherited: true, likely: true } : v));
    return { file: f, views: vs, exposure: exposureOf(vs), path: pathOf(f) };
  });
  return items
    .filter((it) => it.exposure > 0)
    .sort((a, b) => (b.file.mimeType === FOLDER) - (a.file.mimeType === FOLDER) || b.exposure - a.exposure || a.file.name.localeCompare(b.file.name, "ko"));
}

/** Counts per exposure level (for the summary cards). */
export function summary(items) {
  const counts = [0, 0, 0, 0, 0];
  for (const it of items) counts[it.exposure] += 1;
  return { total: items.length, counts };
}

/** Short "who" line: 링크(편집) · parent@gmail.com 외 2명 */
export function peopleLine(views) {
  const parts = [];
  const link = views.find((v) => v.type === "anyone");
  if (link) parts.push(`링크(${link.role === "reader" ? "보기" : link.role === "commenter" ? "댓글" : "편집"})`);
  const dom = views.find((v) => v.type === "domain");
  if (dom) parts.push(`${dom.domain} 전체`);
  const people = views.filter((v) => (v.type === "user" || v.type === "group") && !v.owner && !v.me);
  if (people.length) parts.push(people.length === 1 ? people[0].email : `${people[0].email} 외 ${people.length - 1}명`);
  return parts.join(" · ");
}
