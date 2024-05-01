import { useState } from "react";
import "./featured.scss";

// import getURLTypeAPI from "../../api/getURLTypeAPI";
import getModelResultAPI from "../../api/getModelResultAPI";
// import datasetAPI from "../../api/datasetAPI";

const Featured = () => {
  const [search, setSearch] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [result, setIsResult] = useState("Detect");

  const handleDetect = async () => {
    setIsSearching(true); // Indicate loading or processing
    try {
      // var response = await getURLTypeAPI(search);

      // if (response.data === null) {
      var response = await getModelResultAPI(search);

      //   const data = {
      //     url: search,
      //     type: response.data,
      //   };

      //   await datasetAPI(data);
      //   alert("Added to database successfully!");
      // }
      setIsResult(response);
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
                placeholder={"Enter the URL"}
                value={search}
                onChange={({ target: { value } }) => setSearch(value)}
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
