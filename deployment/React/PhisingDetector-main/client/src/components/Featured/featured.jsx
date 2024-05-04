import { useState, useEffect } from "react";
import "./featured.scss";

// import getURLTypeAPI from "../../api/getURLTypeAPI";
import getModelResultAPI from "../../api/getModelResultAPI";
// import datasetAPI from "../../api/datasetAPI";

const Featured = () => {
  const [search, setSearch] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [result, setIsResult] = useState("Detect");

  function checkUrl(url) {
    // Check if the URL starts with "http://" or "https://"
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      alert(
        "Please enter a valid URL that starts with 'http://' or 'https://'"
      );
      return false;
    }

    // Check and remove "www." if it's after "http://" or "https://"
    const wwwPattern = /^(https?:\/\/)www\./;

    if (wwwPattern.test(url)) {
      url = url.replace(wwwPattern, "$1"); // Remove "www." from the URL
      console.log("Removed 'www.' from URL:", url);
    } else {
      console.log("No 'www.' to remove:", url);
    }

    return true;
  }

  useEffect(() => {
    // Set a timer to reset the result to "Detect" after 10 seconds
    const timer = setTimeout(() => {
      setIsResult("Detect");
    }, 7000); // 10,000 milliseconds = 10 seconds

    // Cleanup function to clear the timer if the component unmounts or result changes
    return () => {
      clearTimeout(timer);
    };
  }, [result]); // Depend on `result` to reset timer when `result` changes

  const handleDetect = async () => {
    if (!checkUrl(search)) {
      // If the URL is invalid, stop further execution
      return;
    }

    setIsSearching(true); // Indicate loading or processing
    try {
      // var response = await getURLTypeAPI(search);

      // if (response.data === null) {
      checkUrl(search);
      var response = await getModelResultAPI(search);

      //   const data = {
      //     url: search,
      //     type: response.data,
      //   };

      //   await datasetAPI(data);
      //   alert("Added to database successfully!");
      // }
      if (response.message && response.message === "Network Error")
        setIsResult(response.message);
      else setIsResult(response);
      console.log("API response:", response);
    } catch (err) {
      console.error("Error in detection:", err);
      alert("An unexpected error occurred while detecting URL type.");
    } finally {
      setIsSearching(false); // Reset loading or processing state
    }
  };

  return (
    <div className="featured">
      <div className="container">
        <div className="left">
          <h1>YOUR TRUSTED PHISHING DETECTION PLATFORM</h1>
          <div className="search">
            <div className="searchInput">
              <img
                className="searchIcon"
                src="./media/search.png"
                alt="search"
              />
              <input
                type="search"
                placeholder={"Paste any URL"}
                value={search}
                onChange={({ target: { value } }) =>
                  setSearch(value.toLowerCase())
                }
                aria-label="Search input" // Improve accessibility
              />
            </div>
            <button
              onClick={handleDetect}
              disabled={isSearching} // Disable button if empty or processing
            >
              {isSearching ? "Detecting..." : result}
            </button>
          </div>
        </div>

        <div className="right">
          <img src="./media/security2.jpg" alt="hero" />
        </div>
      </div>
    </div>
  );
};

export default Featured;
