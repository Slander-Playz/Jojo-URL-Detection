// popup.js
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  chrome.runtime.sendMessage(
    { action: "checkUrl", url: tabs[0].url },
    (response) => {
      document.getElementById("result").innerText =
        "Is Phishing: " + response.isPhishing;
    }
  );
});
