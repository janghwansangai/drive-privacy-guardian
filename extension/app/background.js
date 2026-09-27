// The toolbar icon opens the viewer as a side panel next to the current tab (Google Drive),
// so encrypted files open on the same screen. The viewer can also open as a full tab.
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (sender.id !== chrome.runtime.id || msg?.type !== "openTab") return;
  const url = chrome.runtime.getURL("viewer.html");
  chrome.tabs.query({ url }).then(([tab]) => (tab ? chrome.tabs.update(tab.id, { active: true }) : chrome.tabs.create({ url })));
});
