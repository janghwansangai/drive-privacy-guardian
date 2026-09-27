// Runs on drive.google.com (isolated from the page's own scripts). It only tells the side panel
// WHICH files are selected / double-clicked — their Drive IDs, nothing else. It never reads file
// contents, never changes the page, stores nothing and talks only to this extension (D-086).
// If Drive changes its page structure this simply stops finding IDs; the panel list still works.
(() => {
  const ID = /^[\w-]{20,}$/;
  // Name pattern of this app's encrypted archives (to let a double-click open them in the panel
  // instead of Drive's "no preview available" screen).
  const VAULT = /보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})\.(?:7z|zip)/;
  const send = (msg) => { try { chrome.runtime.sendMessage(msg).catch(() => {}); } catch { /* extension reloaded */ } };
  const itemOf = (el) => el?.closest?.("[data-id]");
  const idOf = (el) => { const id = el?.getAttribute("data-id"); return id && ID.test(id) ? id : null; };

  let last = "";
  let timer = null;
  const report = () => {
    const ids = [...new Set([...document.querySelectorAll('[data-id][aria-selected="true"]')].map(idOf).filter(Boolean))].slice(0, 50);
    const key = ids.join(",");
    if (key === last) return;
    last = key;
    send({ type: "driveSelection", ids });
  };
  const soon = () => { clearTimeout(timer); timer = setTimeout(report, 150); };
  new MutationObserver(soon).observe(document.documentElement, { attributes: true, subtree: true, attributeFilter: ["aria-selected"] });

  document.addEventListener("dblclick", (ev) => {
    const item = itemOf(ev.target);
    const id = idOf(item);
    if (!id || !VAULT.test(item.textContent || "")) return; // other files: Drive behaves as usual
    ev.preventDefault();
    ev.stopImmediatePropagation();
    send({ type: "driveOpen", id });
  }, true);
})();
