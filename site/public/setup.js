// "복사" buttons next to values the user pastes into the Google console.
for (const btn of document.querySelectorAll("[data-copy]")) {
  btn.addEventListener("click", async () => {
    const text = document.getElementById(btn.dataset.copy).textContent;
    try { await navigator.clipboard.writeText(text); btn.textContent = "복사됨 ✓"; }
    catch { btn.textContent = "직접 복사해 주세요"; }
    setTimeout(() => { btn.textContent = "복사"; }, 2000);
  });
}
