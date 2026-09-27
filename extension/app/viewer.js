// Viewer page: sign in → unlock the master key once (personal password; D-088) → encrypted files
// open directly in memory → view HWP/HWPX/XLSX/DOCX/PDF/images/CSV/TXT → save / decrypt to Drive
// only when the user asks.
// Decrypted bytes and parsed content live only in variables of this page and are dropped on
// close, after 10 idle minutes, and when the tab goes away.

import * as drive from "./lib/drive.js";
import { openArchive, derivePassword, passwordFor, parseRecoveryKey, tagFromName, WrongPassword, ArchiveError } from "./lib/vault.js";
import * as keyring from "./lib/keyring.js";
import { viewModel } from "./lib/view.js";
import { renderModel } from "./lib/render.js";
import { planMembers, reencrypt, ReencryptFailed } from "./lib/reencrypt.js";
import { parseDriveUrl } from "./lib/driveurl.js";
import { restoreToDrive, RestoreFailed } from "./lib/restore.js";

const $ = (id) => document.getElementById(id);
const IDLE_MS = 10 * 60 * 1000;

let current = null; // { file, members: Map<name, Uint8Array> }
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
    message("10분 동안 쓰지 않아 풀린 내용을 메모리에서 지웠습니다.");
  }, IDLE_MS);
}
["click", "keydown", "scroll"].forEach((t) => document.addEventListener(t, touch, { passive: true }));
// Closing this view drops what it decrypted; the sign-in and the unlocked key stay in session
// memory for the other views until the browser closes or the auto-lock time passes.
window.addEventListener("pagehide", () => { forget(); });

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
    const wasDrive = driveTabActive;
    driveTabActive = !!tab?.url?.startsWith("https://drive.google.com/");
    if (driveTabActive && (driveTabActive !== wasDrive || !watcherSeen)) {
      watcherSeen = 0;
      chrome.tabs.sendMessage(tab.id, { type: "ping" }).catch(() => showDriveLink(null)); // no watcher there
      setTimeout(() => showDriveLink(null), 2500);
    }
    if (!driveTabActive) showDriveLink(null);
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
$("logout").onclick = async () => {
  forget(); drive.signOut(); await keyring.lock();
  setSignedIn(false); $("files").replaceChildren(); $("unlock").hidden = true;
};
$("refresh").onclick = refresh;

// -- unlock ----------------------------------------------------------------------------------
let selected = null;
let encrypted = null; // { id, bytes } — the still-encrypted download, reused on a retry
let pendingOpen = null; // a file chosen while locked: opened right after unlocking

async function select(file, li) {
  forget();
  document.querySelectorAll("#files li").forEach((x) => x.classList.remove("on"));
  li?.classList.add("on");
  selected = file;
  $("unlockName").textContent = file.name;
  $("unlock").hidden = true;
  $("password").value = "";
  message("");
  const tag = tagFromName(file.name);
  const raw = tag ? await keyring.currentKey() : null;
  if (raw) {
    pendingOpen = null;
    await openWith({ raw }, await derivePassword(raw, tag), { fallback: true });
  } else if (tag) {
    pendingOpen = file; // locked: ask for the personal password once, then open
    message("🔒 잠겨 있습니다 — 위쪽 🔒 칸에 개인 비밀번호를 넣으면 바로 열립니다.");
    $("vaultPw")?.focus();
  } else {
    showFilePassword(); // an old archive with its own password
  }
}

function showFilePassword(hint) {
  $("unlock").hidden = false;
  $("unlockHint").textContent = hint || "복구 키(만능키)로 잠그지 않은 예전 파일입니다. 이 파일을 잠글 때 정한 비밀번호를 넣으세요.";
  $("password").focus();
}

$("unlockForm").onsubmit = async (ev) => {
  ev.preventDefault();
  if (!selected) return;
  const typed = $("password").value;
  $("password").value = "";
  const raw = tagFromName(selected.name) ? await parseRecoveryKey(typed) : null;
  await openWith(raw ? { raw } : { password: typed }, await passwordFor(selected.name, typed));
};

/** Download (memory only) and decrypt the selected archive. */
async function openWith(secret, password, { fallback = false } = {}) {
  if (!selected) return;
  const file = selected;
  message("받는 중… (메모리에만)");
  try {
    const mb = (n) => (n / 1024 / 1024).toFixed(1);
    if (Number(file.size || 0) > 300 * 1024 * 1024) message("큰 파일입니다. 받고 푸는 데 시간이 걸리고 메모리를 많이 씁니다…");
    if (!encrypted || encrypted.id !== file.id) {
      encrypted = { id: file.id, bytes: await drive.download(file, (done, total) => {
        message(total ? `받는 중… ${mb(done)} / ${mb(total)} MB (메모리에만)` : `받는 중… ${mb(done)} MB (메모리에만)`);
      }) };
    }
    if (selected !== file) return;
    message("푸는 중…");
    const members = await openArchive(encrypted.bytes, password);
    current = { file, members, secret };
    showOpened();
    message("");
  } catch (e) {
    if (e instanceof WrongPassword && fallback) {
      message("");
      showFilePassword("이 컴퓨터의 복구 키로는 열리지 않습니다 — 다른 복구 키로 만들었거나 따로 정한 비밀번호가 있는 파일입니다. 그 비밀번호(또는 그때의 복구 키)를 넣으세요.");
    } else if (e instanceof WrongPassword) message("비밀번호가 맞지 않거나 파일이 손상되었습니다.");
    else if (e instanceof ArchiveError) message(e.message);
    else message(e.message || "열지 못했습니다.");
  }
}

// -- master key: set up once, unlock once, auto-lock (D-088) -----------------------------------
const vaultMsg = (t) => { $("vaultMsg").textContent = t || ""; };
const showVault = (id) => ["vaultSetup", "vaultUnlock", "vaultForgot", "vaultOpen"].forEach((x) => { $(x).hidden = x !== id; });

async function refreshVault() {
  if (!(await keyring.isSetUp())) { showVault("vaultSetup"); return; }
  if (await keyring.currentKey({ touch: false })) {
    showVault("vaultOpen");
    $("lockInfo").textContent = `· ${await keyring.lockMinutes()}분 동안 안 쓰면 잠김`;
    if (pendingOpen) { const f = pendingOpen; pendingOpen = null; if (selected?.id === f.id) await select(f, document.querySelector(`#files li[data-id="${CSS.escape(f.id)}"]`)); }
  } else if ($("vaultForgot").hidden) {
    showVault("vaultUnlock");
  }
}

let newKey = null; // a recovery key made here, shown once until setup completes
document.querySelectorAll('input[name="setupMode"]').forEach((r) => {
  r.onchange = async () => {
    const make = r.value === "new" && r.checked;
    $("setupKey").hidden = make;
    $("newKeyBox").hidden = !make;
    if (make && !newKey) { newKey = await keyring.newRecoveryKey(); $("newKeyText").textContent = newKey.text; }
  };
});

$("setupGo").onclick = async () => {
  vaultMsg("");
  const making = document.querySelector('input[name="setupMode"]:checked').value === "new";
  let raw;
  if (making) {
    if (!$("newKeySaved").checked) { vaultMsg("새 복구 키를 종이에 적은 뒤 「종이에 적었습니다」를 체크해 주세요."); return; }
    raw = newKey.raw;
  } else {
    raw = await parseRecoveryKey($("setupKey").value);
    if (!raw) { vaultMsg("복구 키가 맞지 않습니다. 35자를 오타 없이 넣어 주세요 (0/O, 1/I, 8/B는 자동 처리)."); return; }
  }
  const bad = keyring.checkNewPassword($("setupPw").value, $("setupPw2").value);
  if (bad) { vaultMsg(bad); return; }
  $("setupGo").disabled = true;
  try {
    await keyring.setPassword(raw, $("setupPw").value);
    ["setupKey", "setupPw", "setupPw2"].forEach((x) => { $(x).value = ""; });
    newKey = null; $("newKeyText").textContent = "";
    await refreshVault();
  } catch (e) { vaultMsg(e.message); } finally { $("setupGo").disabled = false; }
};

$("vaultUnlock").onsubmit = async (ev) => {
  ev.preventDefault();
  vaultMsg("여는 중…");
  try { await keyring.unlock($("vaultPw").value); $("vaultPw").value = ""; vaultMsg(""); await refreshVault(); }
  catch (e) { vaultMsg(e.message); }
};
$("forgotBtn").onclick = () => { vaultMsg(""); showVault("vaultForgot"); $("forgotKey").focus(); };
$("forgotCancel").onclick = () => { vaultMsg(""); showVault("vaultUnlock"); };
$("vaultForgot").onsubmit = async (ev) => {
  ev.preventDefault();
  vaultMsg("");
  const raw = await parseRecoveryKey($("forgotKey").value);
  if (!raw) { vaultMsg("복구 키가 맞지 않습니다. 35자를 오타 없이 넣어 주세요."); return; }
  const bad = keyring.checkNewPassword($("forgotPw").value, $("forgotPw2").value);
  if (bad) { vaultMsg(bad); return; }
  try {
    await keyring.checkRecoveryKey(raw);
    await keyring.setPassword(raw, $("forgotPw").value);
    ["forgotKey", "forgotPw", "forgotPw2"].forEach((x) => { $(x).value = ""; });
    showVault("vaultOpen");
    await refreshVault();
  } catch (e) { vaultMsg(e.message); }
};
$("lockNow").onclick = async () => { forget(); await keyring.lock(); };

// Locked elsewhere (another view, the auto-lock alarm) → drop what this view decrypted.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && "vaultKey" in changes) {
    if (!changes.vaultKey.newValue && current?.secret?.raw) { forget(); message("잠겼습니다. 개인 비밀번호를 넣으면 다시 열립니다."); }
    refreshVault();
  }
  if (area === "local" && "vaultWrap" in changes) refreshVault();
});
// Using this view counts as activity for the auto-lock.
["click", "keydown"].forEach((t) => document.addEventListener(t, () => { keyring.currentKey().catch(() => {}); }, { passive: true }));

// settings: lock time, change password, forget the key on this computer
keyring.lockMinutes().then((m) => { $("lockMinutes").value = String(m); });
$("lockMinutes").onchange = async () => { await keyring.setLockMinutes(Number($("lockMinutes").value)); refreshVault(); };
$("changePw").onclick = async () => {
  const raw = await keyring.currentKey();
  if (!raw) { $("changePwMsg").textContent = "먼저 잠금을 풀어 주세요"; return; }
  const bad = keyring.checkNewPassword($("newPw").value, $("newPw2").value);
  if (bad) { $("changePwMsg").textContent = bad; return; }
  await keyring.setPassword(raw, $("newPw").value);
  $("newPw").value = ""; $("newPw2").value = "";
  $("changePwMsg").textContent = "바꿨습니다";
};
$("forgetKey").onclick = async () => {
  if (!confirm("이 컴퓨터에 잠가 둔 복구 키를 지울까요? 종이의 복구 키로 다시 설정할 수 있습니다.")) return;
  forget(); await keyring.forget();
};
refreshVault();

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

// -- decrypt back into Drive (only when asked) ----------------------------------------------------
$("restoreBtn").onclick = () => { $("restoreStatus").textContent = ""; $("restoreOk").disabled = false; $("restoreDialog").showModal(); };
$("restoreCancel").onclick = () => $("restoreDialog").close();
$("restoreOk").onclick = async () => {
  if (!current) return;
  const file = current.file;
  $("restoreOk").disabled = true;
  try {
    const r = await restoreToDrive({
      members: current.members, parent: file.parents?.[0] || null, archiveId: file.id,
      trashArchive: $("restoreTrash").checked, drive, onStep: (t) => { $("restoreStatus").textContent = t; },
    });
    $("restoreDialog").close();
    const lines = [`✓ ${r.files.length}개 파일을 드라이브의 같은 폴더에 풀었습니다: ${r.files.map((f) => f.name).join(", ")}`];
    if (!r.allVerified) lines.push("⚠ 올린 파일 중 다시 받아 비교가 맞지 않는 것이 있어 암호화 파일은 지우지 않았습니다.");
    else if (r.trashedArchive) lines.push("🗑 암호화 파일을 휴지통으로 옮겼습니다 (30일 안에 복원 가능).");
    forget();
    selected = null;
    await refresh();
    message(lines.join("\n"), r.allVerified);
  } catch (e) {
    $("restoreStatus").textContent = e instanceof RestoreFailed ? e.message : `실패: ${e.message}`;
    $("restoreOk").disabled = false;
  }
};

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

// Status line: is the Drive page watcher running in the active Drive tab, and does it find files?
let driveTabActive = false;
let watcherSeen = 0; // time of the last message from drive_watch.js
function showDriveLink(status) {
  const p = $("driveLink");
  if (!driveTabActive) { p.hidden = true; return; }
  p.hidden = false;
  if (status) {
    watcherSeen = Date.now();
    p.classList.remove("off");
    p.textContent = `🔗 드라이브와 연결됨 · 화면의 파일 ${status.items}개 인식`
      + (status.selected && !status.found ? ` · 선택한 ${status.selected}개를 알아보지 못함` : "");
  } else if (!watcherSeen) {
    p.classList.add("off");
    p.textContent = "🔌 드라이브와 연결 안 됨 — 드라이브 탭을 새로고침(F5, Mac은 ⌘R)해 주세요";
  }
}

async function listenToDrive(win) {
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url?.startsWith("https://drive.google.com/")) return;
    if (win && sender.tab.windowId !== win.id) return; // another window's Drive tab
    const ok = (id) => typeof id === "string" && /^[\w-]{20,}$/.test(id);
    const n = (v) => (Number.isInteger(v) && v >= 0 && v < 1e6 ? v : 0);
    if (msg?.type === "driveStatus") showDriveLink({ items: n(msg.items), selected: n(msg.selected), found: n(msg.found) });
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
  $("trashStep").hidden = mode === "new";
  $("trashLabel").textContent = mode === "drive" ? "원래 파일을 휴지통으로" : "예전 보관 파일을 휴지통으로";
  $("secretInfo").hidden = false;
  $("secretInfo").textContent = "비밀번호: 복구 키(만능키)로 만듭니다 — 이 컴퓨터(개인 비밀번호), 데스크톱 앱, 종이의 복구 키로 모두 열립니다.";
  if (mode === "drive") {
    $("whereInfo").textContent = "보관 파일은 원래 파일과 같은 폴더에 올립니다. 구글 문서·시트·프레젠테이션은 Office 파일(docx·xlsx·pptx)로 바꿔 암호화합니다.";
  } else if (mode === "edit") {
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

/** New archives are always locked with the master key (D-088). */
async function newSecret() {
  const raw = await keyring.currentKey();
  if (!raw) throw new ReencryptFailed("먼저 위쪽 🔒 칸에서 잠금을 풀어 주세요 (개인 비밀번호)");
  return { raw };
}

$("reencGo").onclick = async () => {
  if (!reenc) return;
  const status = (t) => { $("reencStatus").textContent = t; };
  $("reencGo").disabled = true;
  let fetched = [];
  try {
    const secret = await newSecret();
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
