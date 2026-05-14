import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function Search({ user }) {
  const [keyword, setKeyword] = useState("");
  const [scheme, setScheme] = useState("peks");
  const [results, setResults] = useState([]);
  const [downloadedMessages, setDownloadedMessages] = useState([]);
  const [status, setStatus] = useState("");
  const [hasSearched, setHasSearched] = useState(false);

  const handleSearch = async () => {
    if (!keyword.trim()) {
      setStatus("Please enter a keyword.");
      setResults([]);
      setDownloadedMessages([]);
      setHasSearched(false);
      return;
    }

    try {
      setResults([]);
      setDownloadedMessages([]);
      setHasSearched(true);
      setStatus(`Searching encrypted data using ${scheme.toUpperCase()}...`);

      const indexes = await invoke("search_keyword", {
        user,
        keyword,
        scheme,
      });

      setResults(indexes);

      if (indexes.length === 0) {
        setStatus("No matching ciphertext found.");
      } else {
        setStatus(`Found ${indexes.length} result(s).`);
      }
    } catch (error) {
      console.error(error);
      setResults([]);
      setDownloadedMessages([]);
      setStatus(`Search failed: ${error}`);
    }
  };

  const handleDownload = async (index) => {
    try {
      const payload = await invoke("download_file", {
        user,
        index,
      });

      setDownloadedMessages((prev) => [
        ...prev,
        { index, payload },
      ]);
    } catch (error) {
      console.error(error);
      setStatus(`Download failed: ${error}`);
    }
  };

  const buildDataUrl = (payload) => {
    if (!payload?.contentBase64) {
      return "";
    }

    return `data:${payload.mimeType || "application/octet-stream"};base64,${payload.contentBase64}`;
  };

  return (
    <div className="section-card">
      <h2>Search over Encrypted Data</h2>

      <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
        <option value="peks">KR-PEKS</option>
        <option value="paeks">KR-PAEKS</option>
      </select>

      <input
        type="text"
        placeholder="Keyword"
        value={keyword}
        onChange={(e) => setKeyword(e.target.value)}
      />

      <button onClick={handleSearch}>Search</button>

      <p className="status-text">{status}</p>

      <div className="results-block">
        <h3>Search Results</h3>

        {!hasSearched ? (
          <p>No search performed yet.</p>
        ) : results.length === 0 ? (
          <p>No matching ciphertext found.</p>
        ) : (
          <ul>
            {results.map((index) => (
              <li key={index}>
                Ciphertext #{index}
                <button onClick={() => handleDownload(index)}>
                  Download
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="results-block">
        <h3>Downloaded Messages</h3>

        {downloadedMessages.length === 0 ? (
          <p>No downloaded messages yet.</p>
        ) : (
          downloadedMessages.map((item, i) => (
            <div key={`${item.index}-${i}`} className="message-box">
              <strong>From result #{item.index}</strong>
              {item.payload.payloadType === "text" ? (
                <p>{item.payload.content}</p>
              ) : (
                <div className="downloaded-file">
                  {item.payload.payloadType === "image" && (
                    <img
                      src={buildDataUrl(item.payload)}
                      alt={item.payload.fileName || "Downloaded image"}
                    />
                  )}
                  <div>
                    <p>{item.payload.content || "Encrypted file restored."}</p>
                    <a
                      href={buildDataUrl(item.payload)}
                      download={item.payload.fileName || "downloaded-file"}
                    >
                      Download {item.payload.fileName || "file"}
                    </a>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}