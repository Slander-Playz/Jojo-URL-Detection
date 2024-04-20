document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const tab = tabs[0];
    chrome.runtime.sendMessage(
      { action: "checkUrl", url: tab.url },
      function (response) {
        const statusElement = document.getElementById("status");
        if (response.isPhishing) {
          statusElement.textContent = "This URL may be phishing.";
          statusElement.style.color = "red";
        } else {
          statusElement.textContent = "This URL seems safe.";
          statusElement.style.color = "green";
        }
      }
    );
  });
});
