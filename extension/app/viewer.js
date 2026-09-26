// Viewer page: sign in → list encrypted files → unlock in memory → view HWP/HWPX/XLSX/DOCX/
// PDF/images/CSV/TXT → save a copy only when the user asks (with a warning).
// Decrypted bytes and parsed content live only in variables of this page and are dropped on
// close, after 10 idle minutes, and when the tab goes away.

import * as drive from "./lib/drive.js";
import { openArchive, passwordFor, parseRecoveryKey, tagFromName, WrongPassword, ArchiveError } from "./lib/vault.js";
import { viewModel } from "./lib/view.js";
import { renderModel } from "./lib/render.js";
import { planMembers, reencrypt, ReencryptFailed } from "./lib/reencrypt.js";

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
    if (!encrypted || encrypted.id !== file.id) encrypted = { id: file.id, bytes: await drive.download(file) };
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
touch();

// -- E3: re-encrypt and upload -----------------------------------------------------------------
let reenc = null; // { mode: "edit"|"new", existing: Map, picked: [{name, bytes}], removed: Set }

function closeReenc() {
  if (reenc) for (const p of reenc.picked) p.bytes.fill(0);
  reenc = null;
  $("reenc").hidden = true;
  $("pick").value = "";
  $("newSecret").value = "";
  $("newSecret2").value = "";
  $("reencStatus").textContent = "";
}

function openReenc(mode) {
  closeReenc();
  message("");
  reenc = { mode, existing: mode === "edit" ? current.members : new Map(), picked: [], removed: new Set() };
  $("reenc").hidden = false;
  $("reencGo").disabled = false;
  $("reencTitle").textContent = mode === "edit" ? `다시 암호화: ${current.file.name}` : "새 파일 암호화해 올리기";
  $("secretStep").hidden = mode === "edit";
  $("trashStep").hidden = mode !== "edit";
  $("secretInfo").hidden = mode !== "edit";
  if (mode === "edit") {
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
  const { rows } = planMembers(reenc.existing, reenc.picked, reenc.removed);
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
    if (r.state === "그대로" || r.state === "뺌") {
      const cb = Object.assign(document.createElement("input"), { type: "checkbox", checked: r.state === "뺌", title: "빼기" });
      cb.onchange = () => { cb.checked ? reenc.removed.add(r.name) : reenc.removed.delete(r.name); drawRows(); };
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
  try {
    const { files } = planMembers(reenc.existing, reenc.picked, reenc.removed);
    const secret = reenc.mode === "edit" ? current.secret : await newSecret();
    const old = reenc.mode === "edit" ? current.file : null;
    const result = await reencrypt({
      files, secret,
      parent: old?.parents?.[0] || null,
      oldId: old?.id, trashOld: !!old && $("trashOld").checked,
      drive, onStep: status,
    });
    const lines = [`✓ 완료: ${result.name} (풀어서 비교 확인됨)`];
    lines.push(result.uploadVerified ? "✓ 올린 파일을 다시 받아 확인했습니다." : "⚠ 올린 파일 확인에 실패했습니다 — 예전 보관 파일은 지우지 않았습니다. 새 파일을 열어 확인해 보세요.");
    if (result.parentFallback) lines.push("ℹ 원래 폴더에 올릴 권한이 없어 내 드라이브 맨 위에 올렸습니다.");
    if (old && $("trashOld").checked && result.trashedOld) lines.push("🗑 예전 보관 파일을 휴지통으로 옮겼습니다 (30일 안에 복원 가능).");
    if (secret.password && reenc.mode === "new") lines.push("⚠ 직접 정한 비밀번호는 저장되지 않습니다. 잊으면 열 수 없습니다.");
    if (reenc.picked.length) lines.push("🧹 이 컴퓨터에서 고른 파일(암호 없음)은 다 썼으면 휴지통에 버리고 비우세요.");
    const keep = lines.join("\n");
    closeReenc();
    forget();
    selected = null;
    await refresh();
    message(keep, true);
  } catch (e) {
    status(e instanceof ReencryptFailed ? e.message : `실패: ${e.message || "알 수 없는 오류"} — 예전 보관 파일은 그대로입니다.`);
    $("reencGo").disabled = false;
  }
};
