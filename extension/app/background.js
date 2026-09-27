import { currentKey } from "./lib/keyring.js";

// The toolbar icon opens the viewer as a side panel next to the current tab (Google Drive),
// so encrypted files open on the same screen. The viewer can also open as a full tab.
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// Auto-lock (D-088): drop the unlocked key from session memory after the chosen idle time,
// even when no extension page is open.
chrome.alarms.create("autolock", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "autolock") currentKey({ touch: false }).catch(() => {}); });

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (sender.id !== chrome.runtime.id || sender.tab || msg?.type !== "openTab") return;
  const url = chrome.runtime.getURL("viewer.html");
  chrome.tabs.query({ url }).then(([tab]) => (tab ? chrome.tabs.update(tab.id, { active: true }) : chrome.tabs.create({ url })));
});
