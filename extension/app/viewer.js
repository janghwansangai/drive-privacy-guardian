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
import * as sharing from "./lib/sharing.js";
import { buildAudit, summary as auditSummary } from "./lib/audit.js";
import { scanFile } from "./lib/scan.js";
import { KIND_LABEL, CONFIDENCE_LABEL } from "./lib/detect.js";

const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";
/** A line icon from the sprite in viewer.html. */
function icon(name) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("class", "ic");
  const use = document.createElementNS(SVGNS, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}
/** Button text with a line icon in front. */
function label(el, iconName, text) { el.replaceChildren(icon(iconName), document.createTextNode(text)); return el; }
const VIEW_EXT = /\.(hwp|hwpx|docx|xlsx|pdf|csv|txt|png|jpe?g|gif|webp|bmp)$/i;
const params = new URLSearchParams(location.search);
// Large view over Drive (D-089): this page inside drive_watch.js's full-screen iframe.
const OVERLAY = params.get("mode") === "overlay" && window.parent !== window;
if (OVERLAY) document.body.classList.add("overlay");
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
function toggle(btn, show) {
  btn.setAttribute("aria-pressed", String(show));
}
// One view at a time (user request): 암호화 파일 / 공유 점검 / 개인정보 검사 / 설정 / 도움말.
const VIEW_BUTTONS = { vault: "tabVault", audit: "auditBtn", pii: "piiBtn", settings: "settingsBtn", help: "helpBtn" };
const VIEW_TITLES = { vault: "암호화 관리", audit: "공유 점검", pii: "개인정보 점검", settings: "설정", help: "도움말" };
function setView(name) {
  document.body.dataset.view = name;
  $("pageTitle").textContent = VIEW_TITLES[name] || "";
  for (const [v, id] of Object.entries(VIEW_BUTTONS)) toggle($(id), v === name);
  if (name === "pii") updatePiiHint();
}
$("tabVault").onclick = () => setView("vault");
label($("selScan"), "idscan", "개인정보 점검");
label($("restoreBtn"), "unlock", "풀기 (드라이브에)");
label($("reencBtn"), "lock", "고친 파일로 다시 암호화");
/** ⛶: this view over the Drive tab, full screen (like the file preview). */
async function showBig(opts) {
  const status = $(opts.view === "pii" ? "piiProgress" : "auditStatus"); // visible in that view
  if (driveTabId !== null) {
    try { await chrome.tabs.sendMessage(driveTabId, { type: "showOverlay", ...opts }); status.textContent = ""; return; }
    catch { /* the Drive tab still has the watcher of an earlier version: open a tab instead */ }
  }
  const q = new URLSearchParams({ view: opts.view });
  if (opts.ids?.length) q.set("ids", opts.ids.join(","));
  await chrome.tabs.create({ url: chrome.runtime.getURL(`viewer.html?${q}`) });
  status.textContent = driveTabId !== null
    ? "새 탭으로 크게 열었습니다. 드라이브 탭을 새로고침(F5, Mac은 ⌘R)하면 다음부터 드라이브 위에 열립니다."
    : "새 탭으로 크게 열었습니다.";
}
$("settingsBtn").onclick = () => setView("settings");
$("helpBtn").onclick = () => setView("help");
$("guideBtn").onclick = () => window.open(chrome.runtime.getURL("guide.html"), "_blank", "noopener");
drive.clientId().then((id) => {
  $("client").value = id;
  if (!id) { $("settings").hidden = false; message("처음 한 번 설정에서 클라이언트 ID를 저장해 주세요."); }
});
$("saveClient").onclick = async () => {
  try { await drive.setClientId($("client").value.trim()); $("clientSaved").textContent = "저장됨"; message(""); }
  catch (e) { $("clientSaved").textContent = e.message; }
};

// -- account & list --------------------------------------------------------------------------
let acctEmail = "";
function setSignedIn(on) {
  $("login").hidden = on;
  $("acctBtn").hidden = !on;
  if (!on) { $("acctMenu").hidden = true; acctEmail = ""; return; }
  (acctEmail ? Promise.resolve(acctEmail) : drive.myEmail()).then((email) => {
    acctEmail = email;
    $("acctEmail").textContent = email || "로그인됨";
    $("avatar").textContent = (email || "?").slice(0, 1).toUpperCase();
    $("acctName").textContent = document.body.classList.contains("inTab") && email ? email : "로그인됨";
  }).catch(() => {});
}
$("acctBtn").onclick = (ev) => {
  ev.stopPropagation();
  const open = $("acctMenu").hidden;
  $("acctMenu").hidden = !open;
  $("acctBtn").setAttribute("aria-expanded", String(open));
};
document.addEventListener("click", (ev) => {
  if (!$("acctMenu").hidden && !$("acctMenu").contains(ev.target)) { $("acctMenu").hidden = true; $("acctBtn").setAttribute("aria-expanded", "false"); }
});

// -- which files to list: the folder open in the Drive tab next to this panel, or all ------------
let scope = "folder";
let driveLoc = null; // parseDriveUrl() of the active Drive tab (side panel only)

const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
function sq(iconName, color) { const s = el("span", `sq ${color || ""}`); s.append(icon(iconName)); return s; }
function iconBtn(iconName, tip, onclick, cls = "") {
  const b = el("button", `icon ${cls}`);
  b.dataset.tip = tip;
  b.setAttribute("aria-label", tip);
  b.append(icon(iconName));
  b.onclick = (ev) => { ev.stopPropagation(); onclick(); };
  return b;
}
/** One list row: [icon] name / sub-line [actions] */
function rowOf(iconEl, name, sub, actions = []) {
  const li = document.createElement("li");
  const body = el("div", "body");
  body.append(el("span", "nm", name));
  if (sub) { const sl = el("span", "sub"); typeof sub === "string" ? (sl.textContent = sub) : sl.append(...sub); body.append(sl); }
  li.append(iconEl, body);
  if (actions.length) { const a = el("span", "acts"); a.append(...actions); li.append(a); }
  return li;
}
const displayName = (name) => name.replace(/ \(암호화 [0-9a-f]{8}\)\.(7z|zip)$/, "");

function fileItem(f) {
  const li = rowOf(sq("lock", "green"), displayName(f.name), (f.createdTime || "").slice(0, 10), [
    iconBtn("eye", "열기", () => openLarge(f)),
    iconBtn("unlock", "풀기 (드라이브에)", () => quickRestore(f), "green"),
  ]);
  li.dataset.id = f.id;
  li.title = f.name;
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
  // only the unusual case needs words (less text): no Drive folder open while "이 폴더" is chosen
  $("scopeInfo").textContent = scope === "folder" && !folder ? "드라이브에서 폴더를 열면 그 폴더만 보입니다" : "";
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

let driveTabId = null;
async function watchDriveTab() {
  if (OVERLAY) return;
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
    driveTabId = driveTabActive ? tab.id : null;
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
    if (OVERLAY) { await openOverlayFile(); return; }
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
  const unlocked = (await keyring.isSetUp()) && !!(await keyring.currentKey({ touch: false }));
  document.body.classList.toggle("unlocked", unlocked);
  if (!(await keyring.isSetUp())) { showVault("vaultSetup"); return; }
  if (unlocked) {
    showVault("vaultOpen");
    $("lockInfo").textContent = `· ${await keyring.lockMinutes()}분 후 자동 잠금`;
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

/** Preview a file that is not encrypted (e.g. HWP, which Drive cannot show). Needs the full scope. */
async function previewPlain(f) {
  forget();
  selected = f;
  $("unlock").hidden = true;
  try {
    if (!drive.hasFullAccess()) await drive.requestFullAccess();
    message("받는 중… (메모리에만)");
    const got = await drive.fetchContent(f);
    if (selected !== f) return;
    current = { file: f, members: new Map([[got.name, got.bytes]]), secret: null, plain: true };
    showOpened();
    message("");
  } catch (e) { message(e.message); }
}

async function openOverlayFile() {
  const id = params.get("file") || "";
  if (!/^[\w-]{20,}$/.test(id)) { message("열 파일을 알 수 없습니다."); return; }
  if (!(await drive.restore())) { message("위쪽 「로그인」을 눌러 구글 로그인을 해 주세요. 로그인하면 바로 열립니다."); return; }
  setSignedIn(true);
  let f = await drive.getFile(id).catch(() => null);
  if (!f && !drive.hasFullAccess()) {
    // not one of this app's files: previewing it needs the Drive permission (asked once)
    message("이 파일을 보려면 드라이브 파일 보기 권한이 필요합니다.");
    $("grantBtn").hidden = false;
    $("grantBtn").onclick = async () => {
      try { await drive.requestFullAccess(); $("grantBtn").hidden = true; message(""); await openOverlayFile(); } catch (e) { message(e.message); }
    };
    return;
  }
  if (!f) { message("이 파일을 볼 권한이 없습니다."); return; }
  if (drive.isVaultName(f.name)) await select(f, null);
  else await previewPlain(f);
}
async function openOverlayView(view) {
  setView(view);
  if (!(await drive.restore())) { $(view === "audit" ? "auditStatus" : "piiProgress").textContent = "먼저 오른쪽 패널에서 구글 로그인을 해 주세요."; return; }
  setSignedIn(true);
  if (view === "pii") {
    driveSel = (params.get("ids") || "").split(",").filter((x) => /^[\w-]{20,}$/.test(x)).slice(0, 50);
    updatePiiHint();
    if (driveSel.length) runPii();
  }
}
const START_VIEW = ["audit", "pii"].includes(params.get("view")) ? params.get("view") : null; // overlay or a new tab
if (START_VIEW) openOverlayView(START_VIEW).catch((e) => message(e.message));
else if (OVERLAY) openOverlayFile().catch((e) => message(e.message));
// A sign-in from another view of this extension (same browser session) is used right away.
else drive.restore().then((ok) => { if (ok) { setSignedIn(true); refresh(); } }).catch(() => {});

function showOpened() {
  $("unlock").hidden = true;
  $("bigBtn").hidden = OVERLAY || driveTabId === null;
  $("restoreBtn").hidden = !!current.plain;
  $("reencBtn").hidden = !!current.plain;
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
// Decrypt in place right away (user request: no second confirmation). The archive goes to the
// trash only when every file was uploaded and re-checked.
async function restoreNow() {
  if (!current || current.plain) return;
  const file = current.file;
  $("restoreBtn").disabled = true;
  busy = true;
  try {
    const r = await restoreToDrive({
      members: current.members, parent: file.parents?.[0] || null, archiveId: file.id,
      trashArchive: true, drive, onStep: (t) => message(t, true),
    });
    const shownNames = r.files.slice(0, 5).map((f) => f.name).join(", ") + (r.files.length > 5 ? " …" : "");
    const lines = [`✓ 풀었습니다: ${shownNames}`];
    if (!r.allVerified) lines.push("⚠ 확인이 맞지 않는 파일이 있어 암호화 파일은 그대로 두었습니다.");
    else if (r.trashedArchive) lines.push("🗑 암호화 파일은 휴지통으로 (30일 안에 복원 가능)");
    forget();
    selected = null;
    if (OVERLAY) { $("view").replaceChildren(); }
    await refresh();
    message(lines.join("\n"), r.allVerified);
  } catch (e) {
    message(e instanceof RestoreFailed ? e.message : `실패: ${e.message}`);
  } finally {
    busy = false;
    $("restoreBtn").disabled = false;
  }
}
$("restoreBtn").onclick = restoreNow;

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

const closeOverlay = () => { forget(); window.parent.postMessage({ type: "dpgOverlayClose" }, "https://drive.google.com"); };
$("close").onclick = () => { if (OVERLAY) { closeOverlay(); return; } forget(); $("unlock").hidden = !selected; };
$("overlayClose").onclick = closeOverlay;
if (OVERLAY) document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !document.querySelector("dialog[open]")) closeOverlay(); });
$("back").onclick = () => {
  forget();
  closeReenc();
  selected = null;
  $("unlock").hidden = true;
  document.querySelectorAll("#files li").forEach((x) => x.classList.remove("on"));
};
$("openTab").onclick = () => chrome.runtime.sendMessage({ type: "openTab" });
// From the side panel: show the open archive large, over the Drive tab.
$("bigBtn").onclick = async () => {
  if (!current || driveTabId === null) return;
  try { await chrome.tabs.sendMessage(driveTabId, { type: "showOverlay", id: current.file.id }); forget(); $("unlock").hidden = true; selected = null; }
  catch { message("드라이브 탭을 새로고침(F5, Mac은 ⌘R)한 뒤 다시 눌러 주세요."); }
};

// Narrow side panel: show either the list or the open file (body.focus), with "← 목록" to go back.
const focusTargets = ["unlock", "opened", "reenc"].map($);
setView(START_VIEW || "vault");
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

let busy = false; // an encryption / decryption is running: do not switch screens under it

/** A new selection in Drive replaces whatever this panel was preparing (user request). */
function leaveForSelection() {
  if (busy || OVERLAY) return;
  if (!$("reenc").hidden || !$("unlock").hidden || !$("opened").hidden) {
    forget();
    closeReenc();
    selected = null;
    $("unlock").hidden = true;
    document.querySelectorAll("#files li").forEach((x) => x.classList.remove("on"));
  }
}

const FOLDER = "application/vnd.google-apps.folder";
const btn = (text, cls, onclick) => Object.assign(document.createElement("button"), { className: cls, textContent: text, onclick });

async function showSelection(ids) {
  driveSel = ids;
  const card = $("selCard");
  if (!ids.length) { card.hidden = true; selFiles = []; return; }
  leaveForSelection();
  card.hidden = false;
  $("selTitle").textContent = `${ids.length}개`;
  if (document.body.dataset.view === "pii") updatePiiHint();
  const list = $("selList");
  if (!drive.signedIn()) {
    list.replaceChildren(li("로그인하면 선택한 파일이 보입니다", "muted"));
    $("selEncrypt").hidden = true;
    $("selScan").hidden = true;
    return;
  }
  const metas = await Promise.all(ids.slice(0, 20).map((id) => drive.getFile(id).catch(() => null)));
  if (driveSel !== ids) return; // selection changed meanwhile
  selFiles = metas.filter(Boolean);
  if (document.body.dataset.view === "pii") updatePiiHint();
  list.replaceChildren();
  let plain = ids.length - selFiles.length; // unknown ones (no permission yet) count as plain files
  for (const f of selFiles) {
    const folder = f.mimeType === FOLDER;
    let row;
    if (drive.isVaultName(f.name)) {
      row = rowOf(sq("lock", "green"), displayName(f.name), "암호화됨", [
        iconBtn("eye", "열기", () => openLarge(f)),
        iconBtn("unlock", "풀기 (드라이브에)", () => quickRestore(f), "green"),
      ]);
    } else {
      plain += 1; // files and folders can be encrypted
      const acts = !folder && VIEW_EXT.test(f.name) ? [iconBtn("eye", "미리보기", () => openLarge(f))] : [];
      row = rowOf(sq(folder ? "folder" : "file"), f.name, folder ? "폴더" : "", acts);
    }
    list.append(row);
  }
  if (ids.length > selFiles.length) list.append(li(`이름을 모르는 항목 ${ids.length - selFiles.length}개 — 「암호화하기」를 누르면 보입니다`, "muted"));
  $("selScan").hidden = true; // 개인정보 점검 has its own tab (design A)
  $("selEncrypt").hidden = plain === 0;
  label($("selEncrypt"), "lock", plain === 1 ? "암호화하기" : `암호화하기 (${plain}개를 한 파일로)`);
}

/** "열기": large view over Drive when the Drive tab is next to us, else in this panel. */
async function openLarge(f) {
  if (driveTabId !== null) {
    try { await chrome.tabs.sendMessage(driveTabId, { type: "showOverlay", id: f.id }); return; } catch { /* no watcher: open here */ }
  }
  if (drive.isVaultName(f.name)) await select(f, null);
  else await previewPlain(f);
}

/** "풀기": decrypt in memory, then the decrypt-to-Drive confirmation right away. */
async function quickRestore(f) {
  await select(f, null);
  if (current?.file.id === f.id) await restoreNow();
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
    const files = metas.filter((f) => !drive.isVaultName(f.name));
    if (!files.length) { message("암호화할 수 있는 항목이 없습니다 (이미 암호화된 파일은 제외)."); return; }
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
  if (status) {
    watcherSeen = Date.now();
    // only problems are shown (less text): connected and working → nothing
    p.hidden = !(status.selected && !status.found);
    p.textContent = `드라이브에서 고른 ${status.selected}개를 알아보지 못했습니다 — 드라이브 탭을 새로고침해 주세요`;
  } else if (!watcherSeen) {
    p.hidden = false;
    p.textContent = "드라이브와 연결 안 됨 — 드라이브 탭을 새로고침(F5, Mac은 ⌘R)해 주세요";
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
  });
}

// -- personal-data check of the Drive selection (D-093) -------------------------------------------
const PII_MAX_FILES = 500;
let pii = null; // { results: [], stopping, running }

function closePii() {
  pii = null;
  $("piiList").replaceChildren();
  $("piiListCard").hidden = true;
  $("piiStats").hidden = true;
  $("piiProgressBar").hidden = true;
  $("piiEncrypt").hidden = true;
  $("piiProgress").textContent = "";
}
$("piiStop").onclick = () => { if (pii) pii.stopping = true; };
function updatePiiHint() {
  const n = driveSel.length;
  const first = selFiles.find((f) => driveSel.includes(f.id));
  const folder = first?.mimeType === drive.FOLDER_MIME;
  $("piiIcon").replaceChildren(icon(n === 1 && !folder ? "file" : "folder"));
  $("piiTarget").textContent = !n ? "드라이브에서 파일·폴더를 고르세요" : n === 1 && first ? first.name : `${n}개 선택`;
  if (!pii?.results?.length) $("piiHint").textContent = n ? "종류·건수만 보여 줍니다" : "";
  $("piiStart").disabled = !n || !!pii?.running;
}
$("piiBtn").onclick = () => setView("pii");
$("piiBig").onclick = () => showBig({ view: "pii", ids: driveSel });

const SHORT_KIND = { rrn: "주민번호", rrn_suspect: "주민번호 의심", passport: "여권", driver_license: "운전면허", mobile: "휴대전화", landline: "전화", account: "계좌", card: "카드", email: "이메일", address: "주소", student_roster: "명단", sensitive_suspect: "민감정보 의심", filename_hint: "파일명" };
function drawPiiRow(r) {
  const chips = [];
  const entries = Object.entries(r.kinds).filter(([k]) => r.status === "found" && k !== "filename_hint")
    .sort((a, b) => b[1].confidence - a[1].confidence);
  for (const [k, v] of entries) {
    const c = el("span", `chip ${v.confidence >= 3 ? "red" : "amber"}`, `${SHORT_KIND[k] || KIND_LABEL[k] || k} ${v.count}`);
    c.title = `${KIND_LABEL[k] || k} · ${CONFIDENCE_LABEL[v.confidence]} · ${v.locations.join(", ")}`;
    chips.push(c);
  }
  if (r.status === "none") chips.push(el("span", "chip green", "없음"));
  if (r.status === "unscannable") chips.push(el("span", "chip", `검사 불가 · ${r.reason}`));
  const li = document.createElement("li");
  li.style.alignItems = "flex-start";
  const body = el("div", "body");
  body.append(el("span", "nm", r.file.path || r.file.name));
  const k = el("span", "kinds"); k.append(...chips); body.append(k);
  li.append(sq("file", r.status === "found" ? "amber" : ""), body);
  return li;
}
function piiStats(results) {
  const found = results.filter((r) => r.status === "found").length;
  const none = results.filter((r) => r.status === "none").length;
  const skip = results.filter((r) => r.status === "unscannable").length;
  const s = $("piiStats");
  s.hidden = false;
  s.replaceChildren(...[[found, "개인정보 있음", "red"], [none, "없음", "green"], [skip, "검사 불가", "gray"]].map(([n, t, c]) => {
    const d = el("div", `stat ${c}`); d.append(el("b", "", String(n)), el("span", "", t)); return d;
  }));
}

$("selScan").onclick = () => { setView("pii"); runPii(); };
$("piiStart").onclick = () => runPii();
async function runPii() {
  if (!driveSel.length || pii?.running) return;
  try {
    await drive.requestFullAccess();
    closePii();
    const chosen = (await Promise.all(driveSel.map((id) => drive.getFile(id).catch(() => null)))).filter((f) => f && !drive.isVaultName(f.name));
    pii = { results: [], stopping: false, running: true };
    $("piiStop").hidden = false;
    $("piiStart").disabled = true;
    $("piiProgressBar").hidden = false;
    $("piiBar").style.width = "0%";
    // folders → every file inside (with its path)
    const files = [];
    for (const f of chosen) {
      if (f.mimeType === drive.FOLDER_MIME) {
        $("piiProgress").textContent = `「${f.name}」 폴더 안을 살펴보는 중…`;
        const tree = await drive.listFolderTree(f, { files: PII_MAX_FILES, bytes: Infinity });
        files.push(...tree.files.map((t) => ({ ...t, path: `${f.name}/${t.path}` })));
      } else files.push(f);
    }
    const { pdfTextPages } = await import("./lib/pdf.js");
    for (const [i, f] of files.slice(0, PII_MAX_FILES).entries()) {
      if (!pii || pii.stopping) break;
      $("piiProgress").textContent = `검사 중… ${i + 1}/${files.length}`;
      $("piiBar").style.width = `${Math.round(((i + 1) / Math.min(files.length, PII_MAX_FILES)) * 100)}%`;
      const r = await scanFile(f, { fetch: drive.fetchContent, parseXml, pdfText: pdfTextPages });
      if (!pii) return;
      pii.results.push(r);
      $("piiListCard").hidden = false;
      $("piiList").append(drawPiiRow(r));
      piiStats(pii.results);
    }
    const found = pii.results.filter((r) => r.status === "found");
    const skipped = pii.results.filter((r) => r.status === "unscannable").length;
    $("piiProgress").textContent = "";
    $("piiHint").textContent = `${pii.stopping ? "중지함 · " : ""}${pii.results.length}개 검사 완료${skipped ? ` · 검사 불가 ${skipped}개는 안전하다는 뜻이 아님` : ""}`;
    label($("piiStart"), "refresh", "다시 검사");
    $("piiEncrypt").hidden = !found.length;
    label($("piiEncrypt"), "lock", `개인정보 파일 ${found.length}개 암호화`);
  } catch (e) { $("piiProgress").textContent = e.message; } finally {
    if (pii) pii.running = false;
    $("piiStop").hidden = true;
    updatePiiHint();
  }
}
$("piiEncrypt").onclick = () => {
  const files = pii.results.filter((r) => r.status === "found").map((r) => r.file);
  closePii();
  setView("vault");
  forget();
  $("unlock").hidden = true;
  openReenc("drive", files);
};

// -- whole-Drive sharing audit (D-092) ------------------------------------------------------------
const PAGE = 200;
let audit = null; // { me, internal, items, filter, picked: Set, shown, lastDone, stopping }

// filter: null = all, "link" = link-shared (edit or view), 2 = external accounts, 1 = domain
const matches = (it, f) => f === null || (f === "link" ? it.exposure >= 3 : it.exposure === f);
function auditVisible() {
  return audit.items.filter((it) => matches(it, audit.filter));
}
const ACTION_SHORT = { restrict_all: "모두 '제한됨'으로", remove_link: "링크 공개 끄기", link_to_view: "링크: 편집 → 보기", restrict_domain: "도메인 공개 끄기", remove_external: "외부 사용자 빼기", editors_to_viewers: "편집자 → 뷰어" };
/** Who else can see it, without repeating the link state shown in the chip. */
function whoLine(views) {
  const people = views.filter((v) => (v.type === "user" || v.type === "group") && !v.owner && !v.me);
  const dom = views.find((v) => v.type === "domain");
  const parts = [];
  if (dom) parts.push(`${dom.domain} 전체`);
  if (people.length) parts.push(people.length === 1 ? people[0].email : `${people[0].email} 외 ${people.length - 1}명`);
  return parts.join(" · ") || (views.some((v) => v.type === "anyone") ? "링크가 있는 누구나" : "");
}
const EXP_CHIP = { 4: ["링크 · 편집", "red"], 3: ["링크 · 보기", "red"], 2: ["외부 계정", "amber"], 1: ["도메인", ""] };

function drawAudit() {
  const sum = auditSummary(audit.items);
  $("auditTotal").textContent = sum.total.toLocaleString();
  $("auditTotal").style.cursor = "pointer";
  $("auditTotal").onclick = () => { audit.filter = null; audit.shown = PAGE; drawAudit(); };
  const cards = $("auditCards");
  cards.hidden = false;
  cards.replaceChildren();
  const stat = (n, label, filter, color) => {
    const b = el("button", `stat ${color} ${audit.filter === filter ? "on" : ""}`);
    b.append(el("b", "", n.toLocaleString()), el("span", "", label));
    b.onclick = () => { audit.filter = audit.filter === filter ? null : filter; audit.shown = PAGE; drawAudit(); };
    cards.append(b);
  };
  stat(sum.counts[3] + sum.counts[4], "링크 공개", "link", "red");
  stat(sum.counts[2], "외부 계정", 2, "amber");
  stat(sum.counts[1], "도메인", 1, "gray");
  const vis = auditVisible();
  const list = $("auditList");
  list.replaceChildren();
  $("auditListCard").hidden = false;
  for (const it of vis.slice(0, audit.shown)) {
    const cb = Object.assign(document.createElement("input"), { type: "checkbox", checked: audit.picked.has(it.file.id) });
    cb.setAttribute("aria-label", `${it.file.name} 고르기`);
    cb.onchange = () => { cb.checked ? audit.picked.add(it.file.id) : audit.picked.delete(it.file.id); pickedChanged(); };
    const isFolder = it.file.mimeType === drive.FOLDER_MIME;
    const [chipText, chipColor] = EXP_CHIP[it.exposure] || ["", ""];
    const sub = [el("span", `chip ${chipColor}`, chipText), el("span", "", whoLine(it.views))];
    if (it.views.some((v) => v.likely)) sub.push(el("span", "badge", "일부 상위 폴더에서"));
    const row = rowOf(sq(isFolder ? "folder" : "file"), it.file.name, sub);
    if (it.path) row.title = it.path + it.file.name;
    const id = encodeURIComponent(it.file.id);
    const open = Object.assign(document.createElement("a"), {
      className: "go", target: "_blank", rel: "noopener noreferrer",
      href: isFolder ? `https://drive.google.com/drive/folders/${id}` : `https://drive.google.com/file/d/${id}/view`,
    });
    open.dataset.tip = isFolder ? "드라이브에서 폴더 열기" : "드라이브에서 파일 열기";
    open.setAttribute("aria-label", open.dataset.tip);
    open.className = "icon";
    open.append(icon(isFolder ? "folder" : "file"));
    row.prepend(cb);
    const acts = el("span", "acts"); acts.append(open); row.append(acts);
    list.append(row);
  }
  if (!vis.length) list.append(li(audit.items.length ? "이 종류는 없습니다" : "밖으로 공유된 항목이 없습니다", "muted"));
  $("auditMore").hidden = vis.length <= audit.shown;
  $("auditMore").textContent = `더 보기 (${(vis.length - audit.shown).toLocaleString()}개 남음)`;
  $("auditTools").hidden = !vis.length;
  $("auditAll").checked = vis.length > 0 && vis.every((it) => audit.picked.has(it.file.id));
  pickedChanged();
}

function pickedChanged() {
  const picked = audit.items.filter((it) => audit.picked.has(it.file.id));
  $("auditPicked").textContent = `${picked.length.toLocaleString()}개 선택`;
  $("auditDo").hidden = !audit.items.length;
  let n = 0;
  const reasons = new Map();
  for (const it of picked) {
    const p = sharing.plan(it.views, $("auditAction").value);
    n += p.changes.length;
    for (const sk of p.skips) reasons.set(sk.reason, (reasons.get(sk.reason) || 0) + 1);
  }
  $("auditPlan").textContent = picked.length
    ? `바뀌는 권한 ${n}개` + [...reasons].map(([r, c]) => ` · 건너뜀 ${c}개(${r})`).join("") + (n ? " · 알림 메일 없음" : "")
    : "바꿀 항목을 고르세요";
  $("auditGo").disabled = n === 0;
}

$("auditBtn").onclick = () => setView("audit");
$("auditBig").onclick = () => showBig({ view: "audit" });
async function ensureAudit() {
  await drive.requestFullAccess();
  if (!audit) {
    const me = await drive.myEmail().catch(() => "");
    audit = { me, internal: sharing.internalDomains(me), items: [], raw: [], filter: null, picked: new Set(), shown: PAGE };
    $("auditAction").replaceChildren(...Object.entries(sharing.ACTIONS).map(([k, full]) => Object.assign(document.createElement("option"), { value: k, textContent: ACTION_SHORT[k] || full, title: full })));
  }
}
$("auditMore").onclick = () => { audit.shown += PAGE; drawAudit(); };
$("auditAll").onchange = () => {
  for (const it of auditVisible()) $("auditAll").checked ? audit.picked.add(it.file.id) : audit.picked.delete(it.file.id);
  drawAudit();
};
$("auditAction").onchange = () => audit && pickedChanged();
$("auditStop").onclick = () => { if (audit) audit.stopping = true; };
$("auditStart").onclick = async () => {
  try { await ensureAudit(); } catch (e) { $("auditStatus").textContent = e.message; return; }
  audit.stopping = false;
  $("auditStart").disabled = true;
  $("auditStop").hidden = false;
  busy = true;
  try {
    const r = await drive.scanMyFiles({
      onProgress: (seen, shared) => { $("auditProgress").textContent = `파일 ${seen.toLocaleString()}개 확인 · 공유된 것 ${shared.toLocaleString()}개`; },
      stop: () => audit.stopping,
    });
    audit.raw = r.files; // every shared file (also parents shared only inside the school, for paths)
    audit.items = buildAudit(audit.raw, audit.me, audit.internal);
    audit.picked = new Set();
    audit.filter = null;
    audit.shown = PAGE;
    $("auditProgress").textContent = `${r.stopped ? "중지함 · " : ""}파일 ${r.seen.toLocaleString()}개 확인 · ${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" })}`;
    label($("auditStart"), "refresh", "다시 점검");
    drawAudit();
  } catch (e) { $("auditStatus").textContent = e.message; } finally {
    busy = false;
    $("auditStart").disabled = false;
    $("auditStop").hidden = true;
  }
};

async function reloadAuditItems(ids) {
  const fresh = (await Promise.all([...ids].map((id) => drive.refreshShared(id).catch(() => null)))).filter(Boolean);
  audit.raw = [...audit.raw.filter((f) => !ids.has(f.id)), ...fresh];
  audit.items = buildAudit(audit.raw, audit.me, audit.internal);
  drawAudit();
}

$("auditGo").onclick = async () => {
  const action = $("auditAction").value;
  const items = audit.items.filter((it) => audit.picked.has(it.file.id))
    .map((it) => ({ fileId: it.file.id, name: it.file.name, changes: sharing.plan(it.views, action).changes })).filter((x) => x.changes.length);
  const total = items.reduce((n, x) => n + x.changes.length, 0);
  if (!confirm(`${sharing.ACTIONS[action]}\n\n${items.length}개 항목의 권한 ${total}개를 바꿀까요? (알림 메일 없음, 「↩ 되돌리기」 가능)`)) return;
  $("auditGo").disabled = true;
  busy = true;
  try {
    const r = await sharing.apply(items, drive, (t) => { $("auditStatus").textContent = t; });
    audit.lastDone = r.done;
    $("auditUndo").hidden = !r.done.length;
    const text = `✓ ${r.done.length}개 바꿈` + (r.failed.length ? ` · ⚠ ${r.failed.length}개 실패(권한 없음 등): ${r.failed.slice(0, 3).map((f) => f.name).join(", ")}` : "");
    audit.picked = new Set();
    await reloadAuditItems(new Set(items.map((x) => x.fileId)));
    $("auditStatus").textContent = text;
  } catch (e) { $("auditStatus").textContent = e.message; } finally { busy = false; }
};
$("auditUndo").onclick = async () => {
  if (!audit?.lastDone?.length) return;
  busy = true;
  try {
    const done = audit.lastDone;
    const r = await sharing.undo(done, drive, (t) => { $("auditStatus").textContent = t; });
    audit.lastDone = null;
    $("auditUndo").hidden = true;
    await reloadAuditItems(new Set(done.map((d) => d.fileId)));
    $("auditStatus").textContent = r.failed.length ? `⚠ ${r.failed.length}개는 되돌리지 못했습니다` : "↩ 되돌렸습니다";
  } catch (e) { $("auditStatus").textContent = e.message; } finally { busy = false; }
};

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
  label($("reencGo"), "lock", mode === "edit" ? "다시 암호화하기" : "암호화하기");
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
    ? reenc.driveFiles.filter((f) => !reenc.removed.has(f.id)).map((f) => ({ name: f.name, id: f.id, state: "" }))
    : planMembers(reenc.existing, reenc.picked, reenc.removed).rows.filter((r) => r.state !== "뺌");
  const t = $("reencRows");
  t.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    tr.append(Object.assign(document.createElement("td"), { className: "muted", textContent: "파일을 골라 주세요" }));
    t.append(tr);
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.append(Object.assign(document.createElement("td"), { textContent: r.name }));
    if (r.state && r.state !== "그대로") tr.append(Object.assign(document.createElement("td"), { className: `state ${r.state}`, textContent: r.state }));
    const tdX = Object.assign(document.createElement("td"), { className: "x" });
    if (r.state !== "바꿈" && r.state !== "추가") {
      const x = Object.assign(document.createElement("button"), { textContent: "✕", title: "빼기" });
      x.setAttribute("aria-label", `${r.name} 빼기`);
      x.onclick = () => { reenc.removed.add(r.id || r.name); drawRows(); };
      tdX.append(x);
    } else {
      const x = Object.assign(document.createElement("button"), { textContent: "✕", title: "고른 파일 빼기" });
      x.onclick = () => { reenc.picked = reenc.picked.filter((p) => p.name !== r.name.split("/").pop()); drawRows(); };
      tdX.append(x);
    }
    tr.append(tdX);
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
  busy = true;
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
      // folders: everything inside, keeping the folder structure (`폴더/하위/파일`)
      const jobs = [];
      const skipped = [];
      for (const f of chosen) {
        if (f.mimeType === drive.FOLDER_MIME) {
          status(`「${f.name}」 폴더 안을 살펴보는 중…`);
          const tree = await drive.listFolderTree(f);
          const top = f.name.replace(/[\\/]/g, "_");
          skipped.push(...tree.skipped.map((p) => `${top}/${p}`));
          for (const t of tree.files) jobs.push({ file: t, prefix: `${top}/${t.path.split("/").slice(0, -1).join("/")}`.replace(/\/$/, "") });
          if (!tree.files.length) skipped.push(`${top}/ (빈 폴더)`);
        } else jobs.push({ file: f, prefix: "" });
      }
      if (!jobs.length) throw new ReencryptFailed("암호화할 파일이 없습니다 (빈 폴더)");
      for (const [i, { file: f, prefix }] of jobs.entries()) {
        status(`드라이브에서 받는 중… ${i + 1}/${jobs.length} (메모리에만)`);
        const got = await drive.fetchContent(f);
        fetched.push(got.bytes);
        const base = got.name.replace(/[\\/]/g, "_");
        let name = prefix ? `${prefix}/${base}` : base;
        for (let n = 2; files.has(name); n++) name = (prefix ? `${prefix}/` : "") + base.replace(/(\.[^.]*)?$/, ` (${n})$1`);
        files.set(name, got.bytes);
      }
      reenc.skipped = skipped;
      parent = chosen[0].parents?.[0] || null;
      trashIds = chosen.map((f) => f.id); // a folder goes to the trash with what is inside
    } else {
      files = planMembers(reenc.existing, reenc.picked, reenc.removed).files;
    }
    const result = await reencrypt({
      files, secret, parent, trashIds,
      names: reenc.mode === "drive" ? reenc.driveFiles.filter((f) => !reenc.removed.has(f.id)).map((f) => f.name) : undefined,
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
        : `🗑 원래 파일·폴더 ${trashIds.length}개를 휴지통으로 옮겼습니다 (30일 안에 복원 가능).`);
    }
    if (reenc.skipped?.length) lines.push(`ℹ 넣지 못한 항목 ${reenc.skipped.length}개(바로가기·양식·빈 폴더 등): ${reenc.skipped.slice(0, 5).join(", ")}${reenc.skipped.length > 5 ? " …" : ""}`);
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
    busy = false;
    for (const b of fetched) b.fill(0); // downloaded originals: best-effort wipe
  }
};
