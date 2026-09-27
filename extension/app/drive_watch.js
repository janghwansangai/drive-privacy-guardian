// Runs on drive.google.com (isolated from the page's own scripts). It only tells the side panel
// WHICH files are selected / double-clicked — their Drive IDs — plus counts for a status line.
// It never reads file contents, never changes the page, stores nothing and talks only to this
// extension (D-086). If Drive changes its page structure it simply stops finding IDs; the panel
// list still works.
(() => {
  const ID = /^[\w-]{20,}$/;
  // Name pattern of this app's encrypted archives (a double-click on one opens it in the panel
  // instead of Drive's "no preview available" screen).
  const VAULT = /보관_\d{4}-\d{2}-\d{2}_(?:[0-9a-f]{4}|[0-9a-f]{8})\.(?:7z|zip)|\(암호화 [0-9a-f]{8}\)\.(?:7z|zip)/;
  const ROW = '[role="row"], [role="gridcell"], [role="option"], [role="listitem"], tr';
  const ITEM = `${ROW}, [data-id]`;
  const SELECTED = '[aria-selected="true"], [aria-checked="true"]';
  const send = (msg) => { try { chrome.runtime.sendMessage(msg).catch(() => {}); } catch { /* extension reloaded */ } };
  const validId = (v) => (v && ID.test(v) ? v : null);

  /** The Drive file ID of an item: on itself, an ancestor, or a descendant (layouts differ). */
  function idOf(el) {
    if (!el) return null;
    const own = validId(el.getAttribute?.("data-id"));
    if (own) return own;
    const up = el.closest?.("[data-id]");
    if (up && validId(up.getAttribute("data-id"))) return up.getAttribute("data-id");
    const down = el.querySelectorAll?.("[data-id]") || [];
    const ids = [...new Set([...down].map((d) => validId(d.getAttribute("data-id"))).filter(Boolean))];
    return ids.length === 1 ? ids[0] : null; // ambiguous containers are ignored
  }
  const itemOf = (el) => {
    const withId = el?.closest?.("[data-id]");
    if (withId && validId(withId.getAttribute("data-id"))) return withId.closest('[role="row"], tr') || withId;
    return el?.closest?.(ITEM) || null;
  };

  let last = "";
  let timer = null;
  const report = () => {
    const selected = [...document.querySelectorAll(SELECTED)].filter((e) => e.closest(ITEM));
    const ids = [...new Set(selected.map((e) => idOf(e) || idOf(e.closest(ROW))).filter(Boolean))].slice(0, 50);
    const items = document.querySelectorAll("[data-id]").length;
    send({ type: "driveStatus", items, selected: selected.length, found: ids.length });
    const key = ids.join(",");
    if (key === last) return;
    last = key;
    send({ type: "driveSelection", ids });
  };
  const soon = () => { clearTimeout(timer); timer = setTimeout(report, 150); };
  new MutationObserver(soon).observe(document.documentElement, {
    attributes: true, subtree: true, attributeFilter: ["aria-selected", "aria-checked"],
  });
  document.addEventListener("click", soon, true);
  document.addEventListener("keyup", soon, true);

  // Double-click (or the second click of one) on an encrypted archive → open it in the panel.
  let lastOpen = 0;
  const onOpen = (ev) => {
    if (ev.type !== "dblclick" && (ev.detail || 0) < 2) return;
    const item = itemOf(ev.target);
    const id = idOf(item) || idOf(ev.target);
    if (!id || !VAULT.test(item?.textContent || "")) return; // other files: Drive behaves as usual
    ev.preventDefault();
    ev.stopImmediatePropagation();
    if (Date.now() - lastOpen < 800) return;
    lastOpen = Date.now();
    send({ type: "driveOpen", id });
  };
  for (const type of ["dblclick", "mousedown", "click"]) window.addEventListener(type, onOpen, true);

  // The panel asks "are you there?" when it opens or when this tab becomes active.
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id === chrome.runtime.id && !sender.tab && msg?.type === "ping") { last = ""; report(); }
  });
  report(); // hello: lets the panel show that Drive is connected
})();
