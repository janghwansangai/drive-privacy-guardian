// Google sign-in (launchWebAuthFlow + the user's own web client) and Drive reads.
// Scope: drive.file only (E0: the desktop app's archives are visible with it).
// The access token lives only in this module's memory.

export const SCOPE_FILE = "https://www.googleapis.com/auth/drive.file";
const API = "https://www.googleapis.com/drive/v3/files";
const VAULT_NAME = /^보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})\.(7z|zip)$/;
const MAX_DOWNLOAD = 1024 * 1024 * 1024;

let token = null;
let tokenExpiry = 0;

export async function clientId() {
  return (await chrome.storage.local.get("clientId")).clientId || "";
}
export async function setClientId(value) {
  if (!/^[\w-]+\.apps\.googleusercontent\.com$/.test(value)) throw new Error("클라이언트 ID 형식이 아닙니다");
  await chrome.storage.local.set({ clientId: value }); // an identifier, not a secret
}

export function signOut() { token = null; tokenExpiry = 0; }
export function signedIn() { return !!token && Date.now() < tokenExpiry; }

export async function signIn({ interactive = true, prompt = "select_account" } = {}) {
  const id = await clientId();
  if (!id) throw new Error("먼저 설정에서 클라이언트 ID를 저장해 주세요");
  const state = crypto.randomUUID();
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: id, response_type: "token", redirect_uri: chrome.identity.getRedirectURL(),
    scope: SCOPE_FILE, state, prompt, include_granted_scopes: "false",
  }).toString();
  const redirected = await chrome.identity.launchWebAuthFlow({ url: url.toString(), interactive });
  const p = new URLSearchParams(new URL(redirected).hash.slice(1));
  if (p.get("state") !== state) throw new Error("로그인 응답이 일치하지 않습니다");
  if (p.get("error")) throw new Error(`구글 로그인 거부: ${p.get("error")}`);
  if (!(p.get("scope") || "").split(" ").includes(SCOPE_FILE)) throw new Error("권한 체크박스를 선택해 주세요");
  token = p.get("access_token");
  tokenExpiry = Date.now() + (Number(p.get("expires_in") || 3600) - 60) * 1000;
}

async function authed(url, init = {}) {
  if (!signedIn()) await signIn({ interactive: true, prompt: "" });
  let res = await fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } });
  if (res.status === 401) {
    signOut();
    await signIn({ interactive: true, prompt: "" });
    res = await fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } });
  }
  if (!res.ok) throw new Error(`구글 드라이브 오류 (${res.status})`);
  return res;
}

export async function listVaultFiles() {
  const q = "trashed = false and (mimeType = 'application/x-7z-compressed' or mimeType = 'application/zip')";
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

export async function download(file) {
  if (Number(file.size || 0) > MAX_DOWNLOAD) throw new Error("파일이 너무 큽니다 (1GB 초과)");
  const url = `${API}/${encodeURIComponent(file.id)}?alt=media&supportsAllDrives=true`;
  return new Uint8Array(await (await authed(url)).arrayBuffer());
}
