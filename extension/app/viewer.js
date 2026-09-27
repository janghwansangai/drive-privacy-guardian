// Viewer page: sign in → list encrypted files → unlock in memory → view HWP/HWPX/XLSX/DOCX/
// PDF/images/CSV/TXT → save a copy only when the user asks (with a warning).
// Decrypted bytes and parsed content live only in variables of this page and are dropped on
// close, after 10 idle minutes, and when the tab goes away.

import * as drive from "./lib/drive.js";
import { openArchive, passwordFor, parseRecoveryKey, tagFromName, WrongPassword, ArchiveError } from "./lib/vault.js";
import { viewModel } from "./lib/view.js";
import { renderModel } from "./lib/render.js";
import { planMembers, reencrypt, ReencryptFailed } from "./lib/reencrypt.js";
import { parseDriveUrl } from "./lib/driveurl.js";

const $ = (id) => document.getElementById(id);
const IDLE_MS = 10 * 60 * 1000;

let current = null; // { file, members: Map<name, Uint8Array> }
let rememberedKey = null; // raw recovery key bytes, memory only, if the user asked
let idleTimer = null;
let shown = null; // name of the member on screen
let handles = []; // things to release on close (object URLs, PDF documents)

function release() {
  for (const h of handles) { try { h.destroy(); } catch { /* already gone */ } }
  handles = [];
}

const parseXml = (text) => {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) throw new Error("XML 오류");
  return doc;
};

function message(text, ok = false) { $("message").textContent = text || ""; $("message").classList.toggle("ok", ok); }

function forget() {
  encrypted = null;
  if (current) {
    for (const data of current.members.values()) data.fill(0); // best effort wipe
    current.members.clear();
  }
  current = null;
  release();
  closeReenc();
  $("view").replaceChildren();
  $("members").replaceChildren();
  $("notice").textContent = "";
  $("opened").hidden = true;
  $("save").hidden = true;
  shown = null;
}

function touch() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    forget();
    rememberedKey = null;
    message("10분 동안 쓰지 않아 풀린 내용을 메모리에서 지웠습니다.");
  }, IDLE_MS);
}
["click", "keydown", "scroll"].forEach((t) => document.addEventListener(t, touch, { passive: true }));
window.addEventListener("pagehide", () => { forget(); rememberedKey = null; drive.signOut(); });

// -- settings --------------------------------------------------------------------------------
$("redirect").textContent = chrome.identity.getRedirectURL();
$("settingsBtn").onclick = () => { $("settings").hidden = !$("settings").hidden; };
$("helpBtn").onclick = () => { $("help").hidden = !$("help").hidden; };
drive.clientId().then((id) => {
  $("client").value = id;
  if (!id) { $("settings").hidden = false; message("처음 한 번 설정에서 클라이언트 ID를 저장해 주세요."); }
});
$("saveClient").onclick = async () => {
  try { await drive.setClientId($("client").value.trim()); $("clientSaved").textContent = "저장됨"; message(""); }
  catch (e) { $("clientSaved").textContent = e.message; }
};

// -- account & list --------------------------------------------------------------------------
function setSignedIn(on) {
  $("status").textContent = on ? "로그인됨" : "로그인 전";
  $("login").hidden = on;
  $("logout").hidden = !on;
}

// -- which files to list: the folder open in the Drive tab next to this panel, or all ------------
let scope = "folder";
let driveLoc = null; // parseDriveUrl() of the active Drive tab (side panel only)

function fileItem(f) {
  const li = document.createElement("li");
  li.dataset.id = f.id;
  li.append(document.createTextNode(f.name));
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${(f.createdTime || "").slice(0, 10)} · ${(Number(f.size || 0) / 1024).toFixed(0)} KB`;
  li.append(meta);
  li.onclick = () => select(f, li);
  if (selected && selected.id === f.id) li.classList.add("on");
  return li;
}

async function refresh() {
  message("");
  const list = $("files");
  list.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: "불러오는 중…" }));
  const folder = scope === "folder" ? driveLoc?.folder : null;
  $("scopeFolder").classList.toggle("on", scope === "folder");
  $("scopeAll").classList.toggle("on", scope === "all");
  $("scopeInfo").textContent = scope === "all" ? "이 확장 프로그램이 볼 수 있는 모든 암호화 파일"
    : folder === "root" ? "드라이브에서 열어 둔 폴더: 내 드라이브"
    : folder ? "드라이브에서 열어 둔 폴더의 암호화 파일"
    : "드라이브에서 폴더를 열면 그 폴더의 파일만 보입니다 (지금은 전체)";
  try {
    const files = await drive.listVaultFiles(folder ? { parent: folder } : {});
    setSignedIn(true);
    list.replaceChildren();
    if (!files.length) list.append(Object.assign(document.createElement("li"), { className: "muted", textContent: folder ? "이 폴더에는 암호화된 파일이 없습니다" : "암호화된 파일이 없습니다" }));
    for (const f of files) list.append(fileItem(f));
  } catch (e) {
    list.replaceChildren();
    message(e.message);
  }
}

$("scopeFolder").onclick = () => { scope = "folder"; if (drive.signedIn()) refresh(); };
$("scopeAll").onclick = () => { scope = "all"; if (drive.signedIn()) refresh(); };

/** Follow the Drive tab: list its folder; a previewed encrypted file is selected right away. */
async function followDrive(url) { return followLoc(parseDriveUrl(url || "")); }

async function followLoc(loc) {
  const same = JSON.stringify(loc) === JSON.stringify(driveLoc);
  if (same) return;
  driveLoc = loc;
  if (!drive.signedIn()) { $("scopeInfo").textContent = loc ? "로그인하면 드라이브에서 열어 둔 폴더의 암호화 파일이 보입니다" : ""; return; }
  if (loc?.file) {
    if (reenc || (selected && selected.id === loc.file)) return;
    const f = await drive.getFile(loc.file);
    if (f && drive.isVaultName(f.name)) {
      const li = fileItem(f);
      $("files").prepend(li);
      await select(f, li);
      return;
    }
  }
  if (scope === "folder") await refresh();
}

async function watchDriveTab() {
  const me = await chrome.tabs.getCurrent?.();
  if (me) { // full-tab mode: no Drive tab to follow
    document.body.classList.add("inTab");
    $("openTab").hidden = true;
    scope = "all";
    document.querySelector(".seg").hidden = true;
    return;
  }
  const win = await chrome.windows?.getCurrent?.().catch(() => null);
  listenToDrive(win).catch(() => {});
  const check = async () => {
    const [tab] = await chrome.tabs.query({ active: true, ...(win ? { windowId: win.id } : { currentWindow: true }) });
    try { await followDrive(tab?.url); } catch (e) { message(e.message); }
  };
  let timer = null;
  const soon = () => { clearTimeout(timer); timer = setTimeout(check, 300); };
  chrome.tabs.onActivated.addListener((info) => { if (!win || info.windowId === win.id) soon(); });
  chrome.tabs.onUpdated.addListener((_id, change, tab) => { if (change.url && tab.active && (!win || tab.windowId === win.id)) soon(); });
  check();
}

$("login").onclick = async () => {
  try {
    await drive.signIn({ interactive: true });
    setSignedIn(true);
    const loc = driveLoc;
    driveLoc = undefined; // re-apply the Drive tab's folder / file now that we can list
    if (loc?.file) await followLoc(loc);
    else { driveLoc = loc; await refresh(); }
  }
  catch (e) { message(e.message); }
};
$("logout").onclick = () => { forget(); rememberedKey = null; drive.signOut(); setSignedIn(false); $("files").replaceChildren(); $("unlock").hidden = true; };
$("refresh").onclick = refresh;

// -- unlock ----------------------------------------------------------------------------------
let selected = null;
let encrypted = null; // { id, bytes } — the still-encrypted download, reused on a retry
async function select(file, li) {
  forget();
  document.querySelectorAll("#files li").forEach((x) => x.classList.remove("on"));
  li?.classList.add("on");
  selected = file;
  $("unlockName").textContent = file.name;
  $("unlock").hidden = false;
  $("password").value = "";
  message("");
  if (rememberedKey && tagFromName(file.name)) {
    await unlock(null); // the remembered recovery key opens it directly
  } else {
    $("password").focus();
  }
}

$("unlockForm").onsubmit = async (ev) => {
  ev.preventDefault();
  await unlock($("password").value);
};

async function unlock(typed) {
  if (!selected) return;
  const file = selected;
  message("받는 중… (메모리에만)");
  try {
    let password;
    let secret; // kept while the archive is open, for re-encryption (E3)
    if (typed === null) {
      const { derivePassword } = await import("./lib/vault.js");
      password = await derivePassword(rememberedKey, tagFromName(file.name));
      secret = { raw: rememberedKey };
    } else {
      password = await passwordFor(file.name, typed);
      const raw = tagFromName(file.name) ? await parseRecoveryKey(typed) : null;
      secret = raw ? { raw } : { password: typed };
      if ($("remember").checked && raw) rememberedKey = raw;
    }
    $("password").value = "";
    const mb = (n) => (n / 1024 / 1024).toFixed(1);
    if (Number(file.size || 0) > 300 * 1024 * 1024) message("큰 파일입니다. 받고 푸는 데 시간이 걸리고 메모리를 많이 씁니다…");
    if (!encrypted || encrypted.id !== file.id) {
      encrypted = { id: file.id, bytes: await drive.download(file, (done, total) => {
        message(total ? `받는 중… ${mb(done)} / ${mb(total)} MB (메모리에만)` : `받는 중… ${mb(done)} MB (메모리에만)`);
      }) };
    }
    message("푸는 중…");
    const members = await openArchive(encrypted.bytes, password);
    current = { file, members, secret };
    showOpened();
    message("");
  } catch (e) {
    if (e instanceof WrongPassword) message("비밀번호(또는 복구 키)가 맞지 않거나 파일이 손상되었습니다.");
    else if (e instanceof ArchiveError) message(e.message);
    else message(e.message || "열지 못했습니다.");
  }
}

function showOpened() {
  $("unlock").hidden = true;
  $("opened").hidden = false;
  $("openedName").textContent = current.file.name;
  const ul = $("members");
  ul.replaceChildren();
  const names = [...current.members.keys()].sort();
  names.forEach((name, i) => {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = name;
    btn.onclick = () => show(name, btn);
    li.append(btn);
    ul.append(li);
    if (i === 0) show(name, btn);
  });
}

async function show(name, btn) {
  document.querySelectorAll("#members button").forEach((b) => b.classList.remove("on"));
  btn.classList.add("on");
  $("notice").textContent = "";
  release();
  shown = name;
  $("save").hidden = false;
  $("view").replaceChildren(Object.assign(document.createElement("p"), { className: "muted", textContent: "여는 중…" }));
  const model = await viewModel(name, current.members.get(name), parseXml);
  if (!current || shown !== name) return; // closed or switched meanwhile
  const track = (h) => { if (current && shown === name) handles.push(h); else h.destroy(); };
  $("view").replaceChildren(renderModel(model, (t) => { $("notice").textContent = t; }, track));
}

// -- save (only when asked) -------------------------------------------------------------------
$("save").onclick = () => $("saveDialog").showModal();
$("saveCancel").onclick = () => $("saveDialog").close();
$("saveOk").onclick = () => {
  $("saveDialog").close();
  if (!current || !shown) return;
  const url = URL.createObjectURL(new Blob([current.members.get(shown)], { type: "application/octet-stream" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: shown.split("/").pop() });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  message(`「${a.download}」을(를) 다운로드 폴더에 저장했습니다. 다 쓰면 휴지통에 버리고 휴지통도 비우세요.`);
};

$("close").onclick = () => { forget(); $("unlock").hidden = !selected; };
$("back").onclick = () => {
  forget();
  closeReenc();
  selected = null;
  $("unlock").hidden = true;
  document.querySelectorAll("#files li").forEach((x) => x.classList.remove("on"));
};
$("openTab").onclick = () => chrome.runtime.sendMessage({ type: "openTab" });

// Narrow side panel: show either the list or the open file (body.focus), with "← 목록" to go back.
const focusTargets = ["unlock", "opened", "reenc"].map($);
const updateFocus = () => {
  const on = focusTargets.some((e) => !e.hidden);
  if (document.body.classList.contains("focus") === on) return; // setting `hidden` again would re-trigger
  document.body.classList.toggle("focus", on);
  $("back").hidden = !on;
};
const focusWatch = new MutationObserver(updateFocus);
for (const e of focusTargets) focusWatch.observe(e, { attributes: true, attributeFilter: ["hidden"] });
$("back").hidden = true;
watchDriveTab().catch(() => {});
touch();

// -- files selected / double-clicked in the Drive tab (drive_watch.js sends their IDs) ------------
let driveSel = []; // Drive IDs selected in the Drive tab
let selFiles = []; // their metadata, when this app may see them

const li = (text, cls) => Object.assign(document.createElement("li"), { textContent: text, className: cls || "" });

async function showSelection(ids) {
  driveSel = ids;
  const card = $("selCard");
  if (!ids.length) { card.hidden = true; selFiles = []; return; }
  card.hidden = false;
  $("selTitle").textContent = `드라이브에서 선택: ${ids.length}개`;
  const list = $("selList");
  if (!drive.signedIn()) {
    list.replaceChildren(li("로그인하면 선택한 파일이 보입니다", "muted"));
    $("selEncrypt").hidden = true;
    return;
  }
  const metas = await Promise.all(ids.slice(0, 20).map((id) => drive.getFile(id).catch(() => null)));
  if (driveSel !== ids) return; // selection changed meanwhile
  selFiles = metas.filter(Boolean);
  list.replaceChildren();
  let plain = ids.length - selFiles.length; // unknown ones (no permission yet) count as plain files
  for (const f of selFiles) {
    const row = li("");
    row.append(document.createTextNode(f.name));
    if (drive.isVaultName(f.name)) {
      const b = Object.assign(document.createElement("button"), { className: "tonal", textContent: "열기" });
      b.onclick = () => select(f, null);
      row.append(b);
    } else if (f.mimeType === "application/vnd.google-apps.folder") {
      row.append(Object.assign(document.createElement("span"), { className: "muted", textContent: "폴더" }));
    } else plain += 1;
    list.append(row);
  }
  if (ids.length > selFiles.length) list.append(li(`이름을 모르는 파일 ${ids.length - selFiles.length}개 — 「암호화」를 누르면 권한을 받은 뒤 보입니다`, "muted"));
  $("selEncrypt").hidden = plain === 0;
  $("selEncrypt").textContent = `🔒 선택한 파일 암호화 (${plain}개)`;
  $("selInfo").textContent = plain ? "드라이브에서 바로 암호화해 같은 폴더에 올립니다. 처음 한 번 드라이브 파일 읽기·쓰기 권한을 묻습니다." : "";
}

async function openDriveFile(id) {
  if (!drive.signedIn()) { message("로그인하면 더블클릭한 암호화 파일이 바로 열립니다."); return; }
  const f = await drive.getFile(id);
  if (f && drive.isVaultName(f.name) && !(selected && selected.id === f.id)) await select(f, null);
}

$("selEncrypt").onclick = async () => {
  try {
    await drive.requestFullAccess();
    const metas = (await Promise.all(driveSel.map((id) => drive.getFile(id).catch(() => null)))).filter(Boolean);
    const files = metas.filter((f) => !drive.isVaultName(f.name) && f.mimeType !== "application/vnd.google-apps.folder");
    if (!files.length) { message("암호화할 수 있는 파일이 없습니다 (폴더·보관 파일은 제외)."); return; }
    forget();
    $("unlock").hidden = true;
    openReenc("drive", files);
  } catch (e) { message(e.message); }
};

async function listenToDrive(win) {
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url?.startsWith("https://drive.google.com/")) return;
    if (win && sender.tab.windowId !== win.id) return; // another window's Drive tab
    const ok = (id) => typeof id === "string" && /^[\w-]{20,}$/.test(id);
    if (msg?.type === "driveSelection" && Array.isArray(msg.ids)) showSelection(msg.ids.filter(ok).slice(0, 50)).catch((e) => message(e.message));
    if (msg?.type === "driveOpen" && ok(msg.id)) {
      chrome.runtime.sendMessage({ type: "takePendingOpen", windowId: win?.id }).catch(() => {}); // handled here
      openDriveFile(msg.id).catch((e) => message(e.message));
    }
  });
  // The panel may have been opened by that very double-click: ask for it.
  const pending = await chrome.runtime.sendMessage({ type: "takePendingOpen", windowId: win?.id }).catch(() => null);
  if (pending?.id) openDriveFile(pending.id).catch(() => {});
}

// -- E3: re-encrypt and upload -----------------------------------------------------------------
let reenc = null; // { mode: "edit"|"new"|"drive", existing: Map, picked: [{name, bytes}], removed: Set, driveFiles? }

function closeReenc() {
  if (reenc) for (const p of reenc.picked) p.bytes.fill(0);
  reenc = null;
  $("reenc").hidden = true;
  $("pick").value = "";
  $("newSecret").value = "";
  $("newSecret2").value = "";
  $("reencStatus").textContent = "";
}

function openReenc(mode, driveFiles = []) {
  closeReenc();
  message("");
  reenc = { mode, existing: mode === "edit" ? current.members : new Map(), picked: [], removed: new Set(), driveFiles };
  $("reenc").hidden = false;
  $("reencGo").disabled = false;
  $("reencTitle").textContent = mode === "edit" ? `다시 암호화: ${current.file.name}`
    : mode === "drive" ? `드라이브 파일 암호화: ${driveFiles.length}개` : "새 파일 암호화해 올리기";
  $("pickStep").hidden = mode === "drive";
  $("secretStep").hidden = mode === "edit";
  $("trashStep").hidden = mode === "new";
  $("trashLabel").textContent = mode === "drive" ? "원래 파일을 휴지통으로" : "예전 보관 파일을 휴지통으로";
  $("secretInfo").hidden = mode !== "edit";
  if (mode === "drive") {
    $("whereInfo").textContent = "보관 파일은 원래 파일과 같은 폴더에 올립니다. 구글 문서·시트·프레젠테이션은 Office 파일(docx·xlsx·pptx)로 바꿔 암호화합니다.";
  } else if (mode === "edit") {
    $("secretInfo").textContent = current.secret.raw
      ? "비밀번호: 복구 키로 새 파일의 비밀번호를 만듭니다 (데스크톱 앱에서도 복구 키로 열림)."
      : "비밀번호: 이 파일을 열 때 넣은 비밀번호를 그대로 씁니다.";
    $("whereInfo").textContent = "새 보관 파일은 예전 파일과 같은 폴더에 올립니다 (안 되면 내 드라이브 맨 위).";
  } else {
    $("whereInfo").textContent = "새 보관 파일은 내 드라이브 맨 위에 올립니다. 데스크톱 앱의 「폴더로 옮기기」로 옮길 수 있습니다.";
  }
  drawRows();
  $("reenc").scrollIntoView({ behavior: "smooth" });
}

function drawRows() {
  const rows = reenc.mode === "drive"
    ? reenc.driveFiles.map((f) => ({ name: f.name, id: f.id, state: reenc.removed.has(f.id) ? "뺌" : "암호화" }))
    : planMembers(reenc.existing, reenc.picked, reenc.removed).rows;
  const t = $("reencRows");
  t.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = Object.assign(document.createElement("td"), { className: "muted", textContent: "파일을 골라 주세요" });
    tr.append(td); t.append(tr);
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    const tdName = Object.assign(document.createElement("td"), { textContent: r.name });
    const tdState = Object.assign(document.createElement("td"), { className: `state ${r.state}`, textContent: r.state });
    const tdX = document.createElement("td");
    if (r.state === "그대로" || r.state === "뺌" || r.state === "암호화") {
      const key = r.id || r.name;
      const cb = Object.assign(document.createElement("input"), { type: "checkbox", checked: r.state === "뺌", title: "빼기" });
      cb.onchange = () => { cb.checked ? reenc.removed.add(key) : reenc.removed.delete(key); drawRows(); };
      tdX.append(cb);
    }
    tr.append(tdName, tdState, tdX);
    t.append(tr);
  }
}

$("reencBtn").onclick = () => current && openReenc("edit");
$("newArchive").onclick = () => {
  if (!drive.signedIn()) { message("먼저 구글 로그인을 해 주세요."); return; }
  forget();
  $("unlock").hidden = true;
  openReenc("new");
};
$("reencCancel").onclick = closeReenc;
$("pick").onchange = async () => {
  if (!reenc) return;
  for (const f of $("pick").files) {
    const bytes = new Uint8Array(await f.arrayBuffer());
    reenc.picked = reenc.picked.filter((p) => p.name !== f.name).concat([{ name: f.name, bytes }]);
  }
  $("pick").value = "";
  try { drawRows(); } catch (e) { $("reencStatus").textContent = e.message; }
};

async function newSecret() {
  const typed = $("newSecret").value;
  if (!typed && rememberedKey) return { raw: rememberedKey }; // the recovery key remembered in this panel
  const raw = await parseRecoveryKey(typed);
  if (raw) return { raw };
  if (typed.length < 8) throw new ReencryptFailed("복구 키가 아니면 8자 이상 비밀번호를 넣어 주세요 (복구 키는 35자, 오타 확인)");
  if (typed !== $("newSecret2").value) throw new ReencryptFailed("비밀번호 확인이 다릅니다");
  return { password: typed };
}

$("reencGo").onclick = async () => {
  if (!reenc) return;
  const status = (t) => { $("reencStatus").textContent = t; };
  $("reencGo").disabled = true;
  let fetched = [];
  try {
    const secret = reenc.mode === "edit" ? current.secret : await newSecret();
    const old = reenc.mode === "edit" ? current.file : null;
    let files;
    let parent = old?.parents?.[0] || null;
    let trashIds = old ? [old.id] : [];
    if (reenc.mode === "drive") {
      const chosen = reenc.driveFiles.filter((f) => !reenc.removed.has(f.id));
      if (!chosen.length) throw new ReencryptFailed("암호화할 파일을 하나 이상 남겨 주세요");
      files = new Map();
      for (const [i, f] of chosen.entries()) {
        status(`드라이브에서 받는 중… ${i + 1}/${chosen.length} (메모리에만)`);
        const got = await drive.fetchContent(f);
        fetched.push(got.bytes);
        let name = got.name.replace(/[\\/]/g, "_");
        for (let n = 2; files.has(name); n++) name = got.name.replace(/(\.[^.]*)?$/, ` (${n})$1`);
        files.set(name, got.bytes);
      }
      parent = chosen[0].parents?.[0] || null;
      trashIds = chosen.map((f) => f.id);
    } else {
      files = planMembers(reenc.existing, reenc.picked, reenc.removed).files;
    }
    const result = await reencrypt({
      files, secret, parent, trashIds,
      trashOld: reenc.mode !== "new" && $("trashOld").checked,
      drive, onStep: status,
    });
    const lines = [`✓ 완료: ${result.name} (풀어서 비교 확인됨)`];
    lines.push(result.uploadVerified ? "✓ 올린 파일을 다시 받아 확인했습니다." : "⚠ 올린 파일 확인에 실패했습니다 — 예전 보관 파일은 지우지 않았습니다. 새 파일을 열어 확인해 보세요.");
    if (result.parentFallback) lines.push("ℹ 원래 폴더에 올릴 권한이 없어 내 드라이브 맨 위에 올렸습니다.");
    if (old && $("trashOld").checked && result.trashedOld) lines.push("🗑 예전 보관 파일을 휴지통으로 옮겼습니다 (30일 안에 복원 가능).");
    if (reenc.mode === "drive" && $("trashOld").checked && result.uploadVerified) {
      lines.push(result.trashFailed
        ? `⚠ 원래 파일 ${result.trashFailed}개는 휴지통으로 옮기지 못했습니다 (소유자가 아니거나 권한 없음). 드라이브에서 확인하세요.`
        : `🗑 원래 파일 ${trashIds.length}개를 휴지통으로 옮겼습니다 (30일 안에 복원 가능).`);
    }
    if (secret.password && reenc.mode === "new") lines.push("⚠ 직접 정한 비밀번호는 저장되지 않습니다. 잊으면 열 수 없습니다.");
    if (reenc.picked.length) lines.push("🧹 이 컴퓨터에서 고른 파일(암호 없음)은 다 썼으면 휴지통에 버리고 비우세요.");
    const keep = lines.join("\n");
    closeReenc();
    forget();
    selected = null;
    await refresh();
    message(keep, true);
  } catch (e) {
    status(e instanceof ReencryptFailed ? e.message : `실패: ${e.message || "알 수 없는 오류"} — 드라이브의 원래 파일은 그대로입니다.`);
    $("reencGo").disabled = false;
  } finally {
    for (const b of fetched) b.fill(0); // downloaded originals: best-effort wipe
  }
};
