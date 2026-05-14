import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function Upload({ user }) {
  const [receiver, setReceiver] = useState("");
  const [message, setMessage] = useState("");
  const [keyword, setKeyword] = useState("");
  const [payloadType, setPayloadType] = useState("text");
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus] = useState("");

  const readFileAsBase64 = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();

      reader.onload = () => {
        const result = String(reader.result || "");
        resolve(result.includes(",") ? result.split(",")[1] : result);
      };

      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });

  const handleUpload = async () => {
    if (!receiver.trim() || !keyword.trim()) {
      setStatus("Please fill in receiver and keyword.");
      return;
    }

    if (payloadType === "text" && !message.trim()) {
      setStatus("Please enter a message.");
      return;
    }

    if (payloadType !== "text" && !selectedFile) {
      setStatus("Please choose a file.");
      return;
    }

    try {
      setStatus("Encrypting and uploading...");
      const contentBase64 =
        payloadType === "text" ? null : await readFileAsBase64(selectedFile);
      const effectivePayloadType =
        payloadType === "file" && selectedFile?.type.startsWith("image/")
          ? "image"
          : payloadType;

      await invoke("upload_file", {
        sender: user,
        receiver,
        msg: message,
        keyword,
        payloadType: effectivePayloadType,
        fileName: selectedFile?.name ?? null,
        mimeType: selectedFile?.type || null,
        contentBase64,
      });

      setStatus("Upload successful.");
      setReceiver("");
      setMessage("");
      setKeyword("");
      setSelectedFile(null);
    } catch (error) {
      console.error(error);
      setStatus(`Upload failed: ${error}`);
    }
  };

  return (
    <div className="section-card">
      <h2>Upload Secure Data</h2>

      <input
        type="text"
        placeholder="Receiver ID"
        value={receiver}
        onChange={(e) => setReceiver(e.target.value)}
      />

      <div className="mode-row">
        <button
          type="button"
          className={payloadType === "text" ? "active-mode" : "secondary-button"}
          onClick={() => {
            setPayloadType("text");
            setSelectedFile(null);
          }}
        >
          Text
        </button>
        <button
          type="button"
          className={payloadType === "file" ? "active-mode" : "secondary-button"}
          onClick={() => setPayloadType("file")}
        >
          File / Image
        </button>
      </div>

      {payloadType === "text" ? (
        <textarea
          placeholder="Message"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      ) : (
        <>
          <input
            type="file"
            onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
          />
          <textarea
            placeholder="Optional note"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          {selectedFile && (
            <p className="file-meta">
              Selected: {selectedFile.name} ({Math.ceil(selectedFile.size / 1024)} KB)
            </p>
          )}
        </>
      )}

      <input
        type="text"
        placeholder="Keyword"
        value={keyword}
        onChange={(e) => setKeyword(e.target.value)}
      />

      <button onClick={handleUpload}>Upload</button>

      <p className="status-text">{status}</p>
    </div>
  );
}
