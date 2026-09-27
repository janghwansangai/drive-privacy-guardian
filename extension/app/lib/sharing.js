// Sharing audit and changes for files / folders chosen in Drive — the desktop app's rules
// (dpg/core/audit/analyze.py, dpg/core/actions): exposure levels, internal = the account's own
// domain except consumer domains (gmail.com), and only permissions given directly on the item
// are changed (inherited ones come from a parent folder, D-054). Pure functions + an executor
// that records how to undo each change.

export const CONSUMER_DOMAINS = new Set(["gmail.com", "googlemail.com"]);
export const EXPOSURE = { RESTRICTED: 0, DOMAIN: 1, EXTERNAL: 2, LINK_VIEW: 3, LINK_EDIT: 4 };
export const EXPOSURE_LABEL = ["제한됨", "도메인 공개", "외부 계정 공유", "링크 공개(보기)", "링크 공개(편집)"];
const EDIT_ROLES = new Set(["writer", "fileOrganizer", "organizer"]);

// Same wording as the desktop app (Google's share dialog: 일반 액세스 / 사용자).
export const ACTIONS = {
  restrict_all: "모두 '제한됨'으로 (링크·도메인 공개 해제 + 외부 사용자 액세스 권한 삭제)",
  remove_link: "일반 액세스: '링크가 있는 모든 사용자' → '제한됨'",
  link_to_view: "일반 액세스: 링크 사용자의 역할 '편집자' → '뷰어'",
  restrict_domain: "일반 액세스: 학교(도메인) 전체 공개 → '제한됨'",
  remove_external: "외부 사용자(학교 밖 계정) '액세스 권한 삭제'",
  editors_to_viewers: "'편집자' 역할을 '뷰어'로 변경",
};

const domainOf = (email) => (email && email.includes("@") ? email.split("@").pop().toLowerCase() : null);

export function internalDomains(myEmail, extra = []) {
  const set = new Set(extra.map((d) => d.toLowerCase().trim()).filter(Boolean));
  const own = domainOf(myEmail);
  if (own && !CONSUMER_DOMAINS.has(own)) set.add(own);
  return set;
}

/** One permission, as the UI and the planner see it. */
export function view(p, myEmail, internal) {
  const email = p.emailAddress ? p.emailAddress.toLowerCase() : null;
  const inherited = (p.permissionDetails || []).length > 0 && p.permissionDetails.every((d) => d.inherited);
  const external = (p.type === "user" || p.type === "group") && !internal.has(domainOf(email)) && email !== (myEmail || "").toLowerCase();
  return {
    id: p.id, type: p.type, role: p.role, email, domain: p.domain ? p.domain.toLowerCase() : null,
    discoverable: !!p.allowFileDiscovery, inherited, owner: p.role === "owner",
    me: !!email && email === (myEmail || "").toLowerCase(),
    external: external || (p.type === "domain" && !internal.has((p.domain || "").toLowerCase())),
  };
}

export function exposureOf(views) {
  let e = EXPOSURE.RESTRICTED;
  for (const v of views) {
    if (v.type === "anyone") e = Math.max(e, EDIT_ROLES.has(v.role) ? EXPOSURE.LINK_EDIT : EXPOSURE.LINK_VIEW);
    else if (v.type === "domain") e = Math.max(e, v.external ? EXPOSURE.EXTERNAL : EXPOSURE.DOMAIN);
    else if (v.external && !v.owner) e = Math.max(e, EXPOSURE.EXTERNAL);
  }
  return e;
}

/** Changes for one action on one item: { changes: [{ op: "delete"|"role", perm, role? }], skips: [{ perm, reason }] } */
export function plan(views, action) {
  const changes = [];
  const skips = [];
  const want = (v) => {
    switch (action) {
      case "remove_link": return v.type === "anyone" ? { op: "delete" } : null;
      case "link_to_view": return v.type === "anyone" && EDIT_ROLES.has(v.role) ? { op: "role", role: "reader" } : null;
      case "restrict_domain": return v.type === "domain" ? { op: "delete" } : null;
      case "remove_external": return v.external && v.type !== "domain" ? { op: "delete" } : null;
      case "editors_to_viewers": return (v.type === "user" || v.type === "group") && v.role === "writer" ? { op: "role", role: "reader" } : null;
      case "restrict_all": return v.type === "anyone" || v.type === "domain" || v.external ? { op: "delete" } : null;
      default: return null;
    }
  };
  for (const v of views) {
    const w = want(v);
    if (!w) continue;
    if (v.owner) skips.push({ perm: v, reason: "소유자 권한은 바꿀 수 없음" });
    else if (v.me) skips.push({ perm: v, reason: "내 권한은 바꾸지 않음" });
    else if (v.inherited) skips.push({ perm: v, reason: "상위 폴더에서 온 권한 — 그 폴더에서 바꾸세요" });
    else changes.push({ ...w, perm: v });
  }
  return { changes, skips };
}

export const whoOf = (v) => (v.type === "anyone" ? "링크가 있는 모든 사용자" : v.type === "domain" ? `${v.domain} 전체` : v.email || "(알 수 없음)");
export const ROLE_KO = { owner: "소유자", organizer: "관리자", fileOrganizer: "콘텐츠 관리자", writer: "편집자", commenter: "댓글 작성자", reader: "뷰어" };

/**
 * Apply planned changes. drive: { deletePermission(fileId, permId), updatePermission(fileId, permId, role) }
 * Returns { done: [{ fileId, change, undo }], failed: [{ fileId, change, error }] }
 */
export async function apply(items, drive, onStep = () => {}) {
  const done = [];
  const failed = [];
  const total = items.reduce((n, it) => n + it.changes.length, 0);
  let i = 0;
  for (const it of items) {
    for (const c of it.changes) {
      onStep(`바꾸는 중… ${++i}/${total}`);
      try {
        if (c.op === "delete") await drive.deletePermission(it.fileId, c.perm.id);
        else await drive.updatePermission(it.fileId, c.perm.id, c.role);
        done.push({ fileId: it.fileId, name: it.name, change: c });
      } catch (e) {
        failed.push({ fileId: it.fileId, name: it.name, change: c, error: e.message });
      }
    }
  }
  return { done, failed };
}

/** Undo what apply() did: re-create removed permissions (no e-mail), restore old roles. */
export async function undo(done, drive, onStep = () => {}) {
  const failed = [];
  for (const [i, d] of [...done].reverse().entries()) {
    onStep(`되돌리는 중… ${i + 1}/${done.length}`);
    const p = d.change.perm;
    try {
      if (d.change.op === "role") await drive.updatePermission(d.fileId, p.id, p.role);
      else await drive.createPermission(d.fileId, { type: p.type, role: p.role, emailAddress: p.email || undefined, domain: p.domain || undefined, allowFileDiscovery: p.type === "anyone" || p.type === "domain" ? p.discoverable : undefined });
    } catch (e) { failed.push({ ...d, error: e.message }); }
  }
  return { failed };
}
