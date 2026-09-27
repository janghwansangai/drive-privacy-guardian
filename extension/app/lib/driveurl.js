// What the Drive tab is showing, from its URL only (no code is injected into Drive).
//   /drive/folders/<id>, /drive/u/1/folders/<id>  → { folder: id }
//   /drive/my-drive, /drive/u/0/my-drive, /drive/ → { folder: "root" }
//   /file/d/<id>/view, /open?id=<id>              → { file: id }
//   anything else (search, recent, shared, other sites) → null

const ID = /^[\w-]{10,}$/;

export function parseDriveUrl(text) {
  let u;
  try { u = new URL(text); } catch { return null; }
  if (u.protocol !== "https:" || u.hostname !== "drive.google.com") return null;
  const path = u.pathname.replace(/^\/drive\/u\/\d+\//, "/drive/");
  let m = /^\/(?:drive\/)?file\/d\/([^/]+)/.exec(path.replace(/^\/drive\/u\/\d+/, ""));
  if (m && ID.test(m[1])) return { file: m[1] };
  if (/^\/open$/.test(u.pathname) && ID.test(u.searchParams.get("id") || "")) return { file: u.searchParams.get("id") };
  m = /^\/drive\/folders\/([^/?#]+)/.exec(path);
  if (m && ID.test(m[1])) return { folder: m[1] };
  if (/^\/drive\/(my-drive|home)?\/?$/.test(path)) return { folder: "root" };
  return null;
}
