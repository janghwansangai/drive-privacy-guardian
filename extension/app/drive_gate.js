// 드라이브 잠금 (D-112): runs on drive.google.com and docs.google.com from the start of the page.
// It asks this extension's background "is this page locked?" (the address only) and, if so,
// covers the whole page with this extension's password screen (gate.html in a full-screen
// iframe: the password is typed inside the extension's own page, which Drive cannot read).
// Drive changes pages without reloading, so the address is checked again when it changes.
// With 잠금 없음 (the default) nothing is ever shown. Reads no page content, stores nothing.
(() => {
  const ORIGIN = new URL(chrome.runtime.getURL("")).origin;
  let cover = null;
  let lastUrl = "";
  let asking = false;

  const show = (why) => {
    if (cover) return;
    cover = document.createElement("iframe");
    cover.src = chrome.runtime.getURL(`gate.html?why=${why === "all" ? "all" : why === "folder" ? "folder" : "unknown"}`);
    cover.title = "드라이브 잠금";
    cover.style.cssText = "position:fixed;inset:0;width:100vw;height:100vh;border:0;margin:0;z-index:2147483647;background:#f4f6f8;color-scheme:normal";
    (document.documentElement || document).append(cover);
    cover.focus();
  };
  const hide = () => { cover?.remove(); cover = null; };

  const check = async () => {
    if (asking) return;
    asking = true;
    lastUrl = location.href;
    try {
      const a = await chrome.runtime.sendMessage({ type: "gateCheck", url: location.href });
      if (a?.block) show(a.why); else hide();
    } catch {
      // extension reloaded or removed: nothing to enforce any more
      hide();
    } finally { asking = false; }
  };

  // the password screen says "opened" → ask again (the background decides, not the message)
  window.addEventListener("message", (ev) => {
    if (ev.origin === ORIGIN && cover && ev.source === cover.contentWindow && ev.data?.type === "dpgGateOpened") check();
  });
  // keys typed while covered go to the password screen, not to Drive's shortcuts
  document.addEventListener("keydown", (ev) => { if (cover && ev.target !== cover) { ev.stopImmediatePropagation(); cover.focus(); } }, true);

  setInterval(() => {
    if (location.href !== lastUrl) check(); // Drive moved to another folder or file
  }, 400);
  setInterval(check, 15000); // a lock turned on in the panel, or the auto-lock time passed
  check();
})();
