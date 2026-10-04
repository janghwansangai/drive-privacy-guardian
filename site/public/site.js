// Feature showcase tabs: swap the screenshot and the step list.
const SHOTS = [
  ["img/04-audit.png", "공유 점검 화면"],
  ["img/05-pii.png", "개인정보 점검 화면"],
  ["img/02-vault.png", "암호화 관리 화면"],
  ["img/03-open.png", "파일 보기 화면"],
  ["img/01-setup.png", "처음 설정 화면"],
];
const tabs = [...document.querySelectorAll(".tab")];
const shot = document.getElementById("shot");
const steps = document.getElementById("steps");

function pick(i) {
  tabs.forEach((t, j) => { t.classList.toggle("on", i === j); t.setAttribute("aria-selected", String(i === j)); });
  [shot.src, shot.alt] = SHOTS[i];
  steps.replaceChildren(document.getElementById(`t${i}`).content.cloneNode(true));
}
tabs.forEach((t, i) => t.addEventListener("click", () => pick(i)));
pick(0);
