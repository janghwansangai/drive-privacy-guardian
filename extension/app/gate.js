// The 드라이브 잠금 password screen (D-112), shown by drive_gate.js over Drive / Docs. The password
// goes only to this extension's background, which checks it against the stored PBKDF2 value.
const $ = (id) => document.getElementById(id);
const why = new URLSearchParams(location.search).get("why");
$("title").textContent = why === "folder" ? "잠긴 폴더입니다" : "잠긴 드라이브입니다";
$("why").textContent = why === "all" ? "이 크롬에서 구글 드라이브를 열려면 잠금 비밀번호가 필요합니다."
  : why === "folder" ? "이 폴더(또는 이 폴더 안의 파일)는 잠금 비밀번호가 있어야 열립니다."
    : "잠근 폴더 안인지 확인하지 못했습니다(확장 프로그램 로그인 필요). 잠금 비밀번호를 넣거나, 확장 프로그램 패널에서 구글 로그인을 해 주세요.";
// only Drive / Docs show this page (web_accessible_resources); reply to that page alone
const parentOrigin = [...(location.ancestorOrigins || [])][0] || "";
const PARENT = /^https:\/\/(drive|docs)\.google\.com$/.test(parentOrigin) ? parentOrigin : null;

$("form").onsubmit = async (ev) => {
  ev.preventDefault();
  const password = $("pw").value;
  $("pw").value = "";
  if (!password) { $("msg").textContent = "잠금 비밀번호를 넣어 주세요."; return; }
  const btn = $("form").querySelector("button");
  btn.disabled = true;
  $("msg").textContent = "";
  try {
    const r = await chrome.runtime.sendMessage({ type: "gateUnlock", password });
    if (r?.ok) { if (PARENT) window.parent.postMessage({ type: "dpgGateOpened" }, PARENT); }
    else $("msg").textContent = r?.error || "열지 못했습니다.";
  } catch { $("msg").textContent = "확장 프로그램과 연결되지 않았습니다. 페이지를 새로고침해 주세요."; }
  finally { btn.disabled = false; $("pw").focus(); }
};
$("pw").focus();
