// Viewer page: sign in → list encrypted files → unlock in memory → view HWP/HWPX/XLSX/DOCX/
// PDF/images/CSV/TXT → save a copy only when the user asks (with a warning).
// Decrypted bytes and parsed content live only in variables of this page and are dropped on
// close, after 10 idle minutes, and when the tab goes away.

import * as drive from "./lib/drive.js";
import { openArchive, passwordFor, parseRecoveryKey, tagFromName, WrongPassword, ArchiveError } from "./lib/vault.js";
import { viewModel } from "./lib/view.js";
import { renderModel } from "./lib/render.js";

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

function message(text) { $("message").textContent = text || ""; }

function forget() {
  encrypted = null;
  if (current) {
    for (const data of current.members.values()) data.fill(0); // best effort wipe
    current.members.clear();
  }
  current = null;
  release();
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

async function refresh() {
  message("");
  const list = $("files");
  list.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: "불러오는 중…" }));
  try {
    const files = await drive.listVaultFiles();
    setSignedIn(true);
    list.replaceChildren();
    if (!files.length) list.append(Object.assign(document.createElement("li"), { className: "muted", textContent: "암호화된 파일이 없습니다" }));
    for (const f of files) {
      const li = document.createElement("li");
      li.append(document.createTextNode(f.name));
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = `${(f.createdTime || "").slice(0, 10)} · ${(Number(f.size || 0) / 1024).toFixed(0)} KB`;
      li.append(meta);
      li.onclick = () => select(f, li);
      list.append(li);
    }
  } catch (e) {
    list.replaceChildren();
    message(e.message);
  }
}

$("login").onclick = async () => {
  try { await drive.signIn({ interactive: true }); setSignedIn(true); await refresh(); }
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
  li.classList.add("on");
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
    if (typed === null) {
      const { derivePassword } = await import("./lib/vault.js");
      password = await derivePassword(rememberedKey, tagFromName(file.name));
    } else {
      password = await passwordFor(file.name, typed);
      if ($("remember").checked) rememberedKey = await parseRecoveryKey(typed);
    }
    $("password").value = "";
    if (!encrypted || encrypted.id !== file.id) encrypted = { id: file.id, bytes: await drive.download(file) };
    message("푸는 중…");
    const members = await openArchive(encrypted.bytes, password);
    current = { file, members };
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
touch();
