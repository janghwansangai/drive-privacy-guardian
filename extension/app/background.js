// One viewer tab (a popup would close when the Google sign-in window opens).
chrome.action.onClicked.addListener(async () => {
  const url = chrome.runtime.getURL("viewer.html");
  const [tab] = await chrome.tabs.query({ url });
  if (tab) await chrome.tabs.update(tab.id, { active: true });
  else await chrome.tabs.create({ url });
});
