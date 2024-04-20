chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkUrl") {
    fetch(`http://localhost:8501/`, {
      // Adjust the port if needed
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
        console.error(error);
        sendResponse({ isPhishing: false });
      });
    return true; // Required for async response
  }
});
