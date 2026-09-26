// Opens the probe page in a tab (a popup would close when the Google sign-in window opens).
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL("probe.html") });
});
