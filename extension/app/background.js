import { currentKey } from "./lib/keyring.js";

// The toolbar icon opens the viewer as a side panel next to the current tab (Google Drive),
// so encrypted files open on the same screen. The viewer can also open as a full tab.
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// Auto-lock (D-088): drop the unlocked key from session memory after the chosen idle time,
// even when no extension page is open.
chrome.alarms.create("autolock", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "autolock") currentKey({ touch: false }).catch(() => {}); });

const pendingOpen = new Map(); // windowId → { id, at } (memory only: a file ID, for a panel just opened)

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.type === "takePendingOpen" && !sender.tab) {
    const p = pendingOpen.get(msg.windowId);
    pendingOpen.delete(msg.windowId);
    reply(p && Date.now() - p.at < 15000 ? { id: p.id } : null);
    return;
  }
  // A double-clicked encrypted file in Drive: open the panel next to that tab (Chrome allows this
  // only right after a user action; if it is refused the panel, when open, still picks it up).
  if (msg?.type === "driveOpen" && sender.tab?.id !== undefined && sender.url?.startsWith("https://drive.google.com/")) {
    pendingOpen.set(sender.tab.windowId, { id: String(msg.id), at: Date.now() });
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
    return;
  }
  if (msg?.type !== "openTab") return;
  const url = chrome.runtime.getURL("viewer.html");
  chrome.tabs.query({ url }).then(([tab]) => (tab ? chrome.tabs.update(tab.id, { active: true }) : chrome.tabs.create({ url })));
});
