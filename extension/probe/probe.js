// E0 probe: sign-in with the user's own OAuth client (launchWebAuthFlow, implicit token),
// Drive listing with drive.file vs drive.readonly, and 7-Zip WASM under the extension CSP.
// Tokens live only in this module's memory; nothing is written except the client ID.

const DRIVE = "https://www.googleapis.com/drive/v3/files";
const VAULT_NAME = /^보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})\.(7z|zip)$/;
const SCOPES = {
  narrow: "https://www.googleapis.com/auth/drive.file",
  wide: "https://www.googleapis.com/auth/drive.readonly",
};
const $ = (id) => document.getElementById(id);

$("redirect").textContent = chrome.identity.getRedirectURL();
$("copy").onclick = () => navigator.clipboard.writeText(chrome.identity.getRedirectURL());
chrome.storage.local.get("clientId").then(({ clientId }) => { if (clientId) $("client").value = clientId; });
$("save").onclick = async () => {
  const value = $("client").value.trim();
  if (!/^[\w-]+\.apps\.googleusercontent\.com$/.test(value)) {
    $("saved").textContent = "형식이 올바르지 않습니다";
    return;
  }
  await chrome.storage.local.set({ clientId: value }); // an ID, not a secret
  $("saved").textContent = "저장됨";
};

async function signIn(scope) {
  const { clientId } = await chrome.storage.local.get("clientId");
  if (!clientId) throw new Error("먼저 ①에서 클라이언트 ID를 저장하세요");
  const state = crypto.randomUUID();
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: clientId,
    response_type: "token",
    redirect_uri: chrome.identity.getRedirectURL(),
    scope,
    state,
    prompt: "select_account consent",
    include_granted_scopes: "false",
  }).toString();
  const redirected = await chrome.identity.launchWebAuthFlow({ url: url.toString(), interactive: true });
  const params = new URLSearchParams(new URL(redirected).hash.slice(1));
  if (params.get("state") !== state) throw new Error("로그인 응답이 일치하지 않습니다 (state)");
  if (params.get("error")) throw new Error(`구글이 거부함: ${params.get("error")}`);
  const granted = (params.get("scope") || "").split(" ");
  if (!granted.includes(scope)) throw new Error("요청한 권한이 부여되지 않았습니다 (체크박스 확인)");
  return params.get("access_token");
}

async function findArchives(token) {
  const q = "trashed = false and (mimeType = 'application/x-7z-compressed' or mimeType = 'application/zip')";
  let pageToken = "";
  const found = [];
  do {
    const url = new URL(DRIVE);
    url.search = new URLSearchParams({
      q, pageSize: "1000", fields: "nextPageToken,files(id,name)",
      supportsAllDrives: "true", includeItemsFromAllDrives: "true", corpora: "allDrives",
      ...(pageToken ? { pageToken } : {}),
    }).toString();
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Drive API ${res.status}`);
    const body = await res.json();
    found.push(...body.files.filter((f) => VAULT_NAME.test(f.name)));
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return found.length;
}

async function probe(kind) {
  const out = $(`${kind}Result`);
  out.className = "result";
  out.textContent = "브라우저 창에서 로그인해 주세요…";
  let token = null;
  try {
    token = await signIn(SCOPES[kind]);
    const n = await findArchives(token);
    out.className = "result ok";
    out.textContent = `✓ 로그인 성공 · 찾은 암호화 파일 ${n}개 (${kind === "narrow" ? "drive.file" : "drive.readonly"})`;
  } catch (e) {
    out.className = "result bad";
    out.textContent = `✗ ${e.message}`;
  } finally {
    token = null; // dropped: nothing kept after the check
  }
}
$("narrow").onclick = () => probe("narrow");
$("wide").onclick = () => probe("wide");

$("wasm").onclick = async () => {
  const out = $("wasmResult");
  try {
    const { default: SevenZip } = await import("./vendor/7z-wasm/7zz.es6.js");
    const lines = [];
    const sz = await SevenZip({ print: (s) => lines.push(s) });
    // Make and open a tiny AES-256 + header-encrypted archive entirely in memory.
    const put = (name, text) => {
      const bytes = new TextEncoder().encode(text);
      const s = sz.FS.open(name, "w+"); sz.FS.write(s, bytes, 0, bytes.length); sz.FS.close(s);
    };
    put("/t.txt", "가상 시험");
    sz.callMain(["a", "/t.7z", "/t.txt", "-pAa1-e0", "-mhe=on"]);
    sz.FS.mkdir("/o");
    sz.callMain(["x", "/t.7z", "-pAa1-e0", "-o/o", "-y"]);
    const back = new TextDecoder().decode(sz.FS.readFile("/o/t.txt"));
    out.className = back === "가상 시험" ? "ok" : "bad";
    out.textContent = back === "가상 시험" ? "✓ 7-Zip WASM 동작 (암호화·해제, 메모리)" : "✗ 결과가 다름";
  } catch (e) {
    out.className = "bad";
    out.textContent = `✗ ${e && e.message ? e.message : e}`;
  }
};
