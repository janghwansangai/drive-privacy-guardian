// Google sign-in (launchWebAuthFlow + the user's own web client), Drive reads, and the E3 writes:
// upload a new encrypted archive, move a replaced archive to the trash (never a permanent delete).
// Scope: drive.file for viewing (E0: the desktop app's archives are visible with it). The full
// `drive` scope is requested only when the user encrypts files chosen in Drive (D-086).
// The access token lives in memory and in chrome.storage.session (memory only, cleared when the
// browser closes, not readable by content scripts) so the side panel, the large view and the tab
// share one sign-in (D-088).

export const SCOPE_FILE = "https://www.googleapis.com/auth/drive.file";
export const SCOPE_FULL = "https://www.googleapis.com/auth/drive";
const API = "https://www.googleapis.com/drive/v3/files";
const UPLOAD = "https://www.googleapis.com/upload/drive/v3/files";
// `상담기록.hwp (암호화 7f3a9c2e).7z` (D-087) or `보관_2026-09-26_7f3a9c2e.7z` (before)
const VAULT_NAME = /^(?:보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})|.+ \(암호화 [0-9a-f]{8}\))\.(7z|zip)$/;
const MAX_DOWNLOAD = 1024 * 1024 * 1024;

let token = null;
let tokenExpiry = 0;
let wantFull = false; // once the user agreed to the full scope, later silent refreshes keep it
let granted = new Set();

export async function clientId() {
  return (await chrome.storage.local.get("clientId")).clientId || "";
}
export async function setClientId(value) {
  if (!/^[\w-]+\.apps\.googleusercontent\.com$/.test(value)) throw new Error("클라이언트 ID 형식이 아닙니다");
  await chrome.storage.local.set({ clientId: value }); // an identifier, not a secret
}

export function signOut() {
  token = null; tokenExpiry = 0; granted = new Set(); wantFull = false;
  chrome.storage.session?.remove("auth").catch?.(() => {});
}

/** Pick up a sign-in made in another view of this extension (same browser session). */
export async function restore() {
  if (signedIn()) return true;
  const a = (await chrome.storage.session?.get("auth"))?.auth;
  if (!a || Date.now() >= a.expiry) return false;
  token = a.token; tokenExpiry = a.expiry; granted = new Set(a.granted || []);
  wantFull = granted.has(SCOPE_FULL);
  return true;
}
export function hasFullAccess() { return signedIn() && granted.has(SCOPE_FULL); }
export function signedIn() { return !!token && Date.now() < tokenExpiry; }

export async function signIn({ interactive = true, prompt = "select_account" } = {}) {
  const id = await clientId();
  if (!id) throw new Error("먼저 설정에서 클라이언트 ID를 저장해 주세요");
  const state = crypto.randomUUID();
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: id, response_type: "token", redirect_uri: chrome.identity.getRedirectURL(),
    scope: wantFull ? `${SCOPE_FILE} ${SCOPE_FULL}` : SCOPE_FILE, state, prompt, include_granted_scopes: "false",
  }).toString();
  const redirected = await chrome.identity.launchWebAuthFlow({ url: url.toString(), interactive });
  const p = new URLSearchParams(new URL(redirected).hash.slice(1));
  if (p.get("state") !== state) throw new Error("로그인 응답이 일치하지 않습니다");
  if (p.get("error")) throw new Error(`구글 로그인 거부: ${p.get("error")}`);
  if (!(p.get("scope") || "").split(" ").includes(SCOPE_FILE)) throw new Error("권한 체크박스를 선택해 주세요");
  granted = new Set((p.get("scope") || "").split(" "));
  token = p.get("access_token");
  tokenExpiry = Date.now() + (Number(p.get("expires_in") || 3600) - 60) * 1000;
  await chrome.storage.session?.set({ auth: { token, expiry: tokenExpiry, granted: [...granted] } });
}

/** Ask for the full Drive scope (only when encrypting files chosen in Drive). */
export async function requestFullAccess() {
  if (hasFullAccess()) return;
  wantFull = true;
  try {
    await signIn({ interactive: true, prompt: "consent" });
  } catch (e) { wantFull = false; throw e; }
  if (!granted.has(SCOPE_FULL)) {
    wantFull = false;
    throw new Error("드라이브 파일을 암호화하려면 권한 화면에서 '드라이브의 모든 파일 보기·수정…' 항목도 체크해 주세요");
  }
}

async function authed(url, init = {}) {
  if (!signedIn() && !(await restore())) await signIn({ interactive: true, prompt: "" });
  let res = await fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } });
  if (res.status === 401) {
    signOut();
    await signIn({ interactive: true, prompt: "" });
    res = await fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } });
  }
  if (!res.ok) {
    const err = new Error(`구글 드라이브 오류 (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return res;
}

export const isVaultName = (name) => VAULT_NAME.test(name || "");

/** Encrypted archives visible to this app; `parent` limits it to one folder ("root" = My Drive). */
export async function listVaultFiles({ parent } = {}) {
  if (parent && !/^[\w-]+$/.test(parent)) throw new Error("폴더 ID 형식이 아닙니다");
  const q = "trashed = false and (mimeType = 'application/x-7z-compressed' or mimeType = 'application/zip')" +
    (parent ? ` and '${parent}' in parents` : "");
  const found = [];
  let pageToken = "";
  do {
    const url = new URL(API);
    url.search = new URLSearchParams({
      q, pageSize: "1000", fields: "nextPageToken,files(id,name,size,createdTime,parents)",
      supportsAllDrives: "true", includeItemsFromAllDrives: "true", corpora: "allDrives",
      ...(pageToken ? { pageToken } : {}),
    }).toString();
    const body = await (await authed(url)).json();
    found.push(...body.files.filter((f) => VAULT_NAME.test(f.name)));
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return found.sort((a, b) => (b.createdTime || "").localeCompare(a.createdTime || ""));
}

/** One file's metadata, or null if this app cannot see it (drive.file). */
export async function getFile(id) {
  if (!/^[\w-]+$/.test(id)) return null;
  const url = `${API}/${encodeURIComponent(id)}?supportsAllDrives=true&fields=id,name,size,createdTime,parents,trashed,mimeType`;
  try {
    const f = await (await authed(url)).json();
    return f.trashed ? null : f;
  } catch (e) {
    if (e.status === 404 || e.status === 403) return null;
    throw e;
  }
}

/** Download into memory; `onProgress(done, total)` is called while it streams. */
export async function download(file, onProgress) {
  if (Number(file.size || 0) > MAX_DOWNLOAD) throw new Error("파일이 너무 큽니다 (1GB 초과)");
  const url = `${API}/${encodeURIComponent(file.id)}?alt=media&supportsAllDrives=true`;
  const res = await authed(url);
  const total = Number(res.headers.get("Content-Length") || file.size || 0);
  if (!onProgress || !res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const parts = [];
  let done = 0;
  for (;;) {
    const { value, done: end } = await reader.read();
    if (end) break;
    parts.push(value);
    done += value.length;
    if (done > MAX_DOWNLOAD) throw new Error("파일이 너무 큽니다 (1GB 초과)");
    onProgress(done, total);
  }
  const out = new Uint8Array(done);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Upload a new file (resumable session, one PUT). `parent` may be null = the top of My Drive. */
export async function upload(name, parent, bytes, mimeType = "application/x-7z-compressed") {
  const url = `${UPLOAD}?uploadType=resumable&supportsAllDrives=true&fields=id,name,size,parents`;
  const start = await authed(url, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": mimeType, "X-Upload-Content-Length": String(bytes.length) },
    body: JSON.stringify({ name, mimeType, ...(parent ? { parents: [parent] } : {}) }),
  });
  const session = start.headers.get("Location");
  if (!session || !session.startsWith(UPLOAD)) throw new Error("업로드를 시작하지 못했습니다");
  return (await authed(session, { method: "PUT", headers: { "Content-Type": mimeType }, body: bytes })).json();
}

/** Move to the Drive trash (restorable for 30 days). There is no permanent delete. */
export async function trash(id) {
  const url = `${API}/${encodeURIComponent(id)}?supportsAllDrives=true&fields=id,trashed`;
  return (await authed(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ trashed: true }) })).json();
}

/** Google Docs/Sheets/Slides → an Office file (Drive export limit 10MB). */
export const EXPORTS = {
  "application/vnd.google-apps.document": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"],
  "application/vnd.google-apps.spreadsheet": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"],
  "application/vnd.google-apps.presentation": ["application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"],
};

/** Bytes of a Drive file (exported if it is a Google document). Returns { name, bytes }. */
export async function fetchContent(file) {
  const exp = EXPORTS[file.mimeType];
  if (exp) {
    const url = `${API}/${encodeURIComponent(file.id)}/export?mimeType=${encodeURIComponent(exp[0])}`;
    const bytes = new Uint8Array(await (await authed(url)).arrayBuffer());
    return { name: file.name.endsWith(exp[1]) ? file.name : file.name + exp[1], bytes };
  }
  if ((file.mimeType || "").startsWith("application/vnd.google-apps.")) throw new Error(`「${file.name}」은(는) 암호화할 수 없는 형식입니다 (폴더·양식 등)`);
  return { name: file.name, bytes: await download(file) };
}

export const FOLDER_MIME = "application/vnd.google-apps.folder";
export const TREE_LIMITS = { files: 3000, bytes: 700 * 1024 * 1024 };

/** Every file under a folder, with its path inside it (`하위폴더/파일.hwp`). Shortcuts and forms
 *  are skipped (reported); stops with a clear message past TREE_LIMITS (memory-only work). */
export async function listFolderTree(folder, limits = TREE_LIMITS) {
  const files = [];
  const skipped = [];
  let bytes = 0;
  const queue = [{ id: folder.id, path: "" }];
  while (queue.length) {
    const { id, path } = queue.shift();
    if (!/^[\w-]+$/.test(id)) continue;
    let pageToken = "";
    do {
      const url = new URL(API);
      url.search = new URLSearchParams({
        q: `'${id}' in parents and trashed = false`, pageSize: "1000",
        fields: "nextPageToken,files(id,name,mimeType,size,parents)",
        supportsAllDrives: "true", includeItemsFromAllDrives: "true", ...(pageToken ? { pageToken } : {}),
      }).toString();
      const body = await (await authed(url)).json();
      for (const f of body.files) {
        const name = f.name.replace(/[\\/]/g, "_");
        if (f.mimeType === FOLDER_MIME) { queue.push({ id: f.id, path: `${path}${name}/` }); continue; }
        if (f.mimeType.startsWith("application/vnd.google-apps.") && !EXPORTS[f.mimeType]) { skipped.push(`${path}${name}`); continue; }
        bytes += Number(f.size || 0);
        files.push({ ...f, path: `${path}${name}` });
        if (files.length > limits.files) throw new Error(`폴더 안 파일이 너무 많습니다 (${limits.files}개 초과) — 데스크톱 앱을 쓰거나 폴더를 나눠 주세요`);
        if (bytes > limits.bytes) throw new Error(`폴더가 너무 큽니다 (${Math.round(limits.bytes / 1048576)}MB 초과, 브라우저 메모리에서 작업) — 폴더를 나눠 주세요`);
      }
      pageToken = body.nextPageToken || "";
    } while (pageToken);
  }
  return { files, skipped };
}

/** A new folder (for decrypting a folder archive back into Drive). */
export async function createFolder(name, parent) {
  const clean = String(name).replace(/[\\/]/g, "_").trim().slice(0, 255) || "폴더";
  const url = `${API}?supportsAllDrives=true&fields=id,name,parents`;
  return (await authed(url, {
    method: "POST", headers: { "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify({ name: clean, mimeType: FOLDER_MIME, ...(parent ? { parents: [parent] } : {}) }),
  })).json();
}

// -- sharing (D-091/D-092): the whole-Drive audit reads permissions and changes them ------------
const PERM_FIELDS = "id,type,role,emailAddress,domain,allowFileDiscovery,permissionDetails(inherited,permissionType)";
const idOk = (id) => /^[\w-]+$/.test(id);

export async function myEmail() {
  const url = "https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)";
  return (await (await authed(url)).json()).user?.emailAddress || "";
}

/** Remove one person's / the link's access to a file (not the file itself). */
export async function deletePermission(fileId, permId) {
  if (!idOk(fileId) || !idOk(permId)) throw new Error("ID 형식이 아닙니다");
  await authed(`${API}/${encodeURIComponent(fileId)}/permissions/${encodeURIComponent(permId)}?supportsAllDrives=true`, { method: "DELETE" });
}

export async function updatePermission(fileId, permId, role) {
  if (!idOk(fileId) || !idOk(permId)) throw new Error("ID 형식이 아닙니다");
  await authed(`${API}/${encodeURIComponent(fileId)}/permissions/${encodeURIComponent(permId)}?supportsAllDrives=true&fields=id`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role }),
  });
}

/** Re-create a permission when undoing (no notification e-mail). */
export async function createPermission(fileId, perm) {
  if (!idOk(fileId)) throw new Error("파일 ID 형식이 아닙니다");
  const person = perm.type === "user" || perm.type === "group";
  const url = `${API}/${encodeURIComponent(fileId)}/permissions?supportsAllDrives=true&fields=id${person ? "&sendNotificationEmail=false" : ""}`;
  await authed(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(perm) });
}

/** Whole-Drive audit (D-092): every file I own, metadata + permissions only (no contents).
 *  onProgress(seen, shared); stop() → true ends early. Returns { files, seen, stopped }. */
export async function scanMyFiles({ onProgress = () => {}, stop = () => false } = {}) {
  const files = [];
  let seen = 0;
  let pageToken = "";
  do {
    if (stop()) return { files, seen, stopped: true };
    const url = new URL(API);
    url.search = new URLSearchParams({
      q: "'me' in owners and trashed = false", corpora: "user", pageSize: "1000",
      fields: `nextPageToken,files(id,name,mimeType,shared,parents,modifiedTime,permissions(${PERM_FIELDS}))`,
      ...(pageToken ? { pageToken } : {}),
    }).toString();
    const body = await (await authed(url)).json();
    seen += body.files.length;
    for (const f of body.files) if (f.shared) files.push(f); // not shared → nothing to check
    onProgress(seen, files.length);
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return { files, seen, stopped: false };
}

/** One file again after a change (to refresh the audit list). */
export async function refreshShared(id) {
  if (!idOk(id)) return null;
  const url = `${API}/${encodeURIComponent(id)}?supportsAllDrives=true&fields=id,name,mimeType,shared,parents,modifiedTime,permissions(${PERM_FIELDS})`;
  return (await authed(url)).json();
}
