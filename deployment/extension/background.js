chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkUrl") {
    fetch(`http://localhost:8501/`, {
      mode: "no-cors",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: request.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        sendResponse({ isPhishing: data.isPhishing });
      })
      .catch((error) => {
        sendResponse({ isPhishing: false });
      });
    return true; // Required for async response
  }
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  // Send the updated URL to the content script
  chrome.tabs.sendMessage(details.tabId, {
    action: "urlChanged",
    url: details.url,
  });
});
