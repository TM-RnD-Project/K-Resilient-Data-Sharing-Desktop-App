import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function AuthPage({ onLoginSuccess }) {
  const [userId, setUserId] = useState("");
  const [status, setStatus] = useState("Please register or login.");
  const [isBusy, setIsBusy] = useState(false);

  const handleRegister = async () => {
    if (!userId.trim()) {
      setStatus("Please enter a user ID first.");
      return;
    }

    try {
      setIsBusy(true);
      setStatus("Registering new user...");

      await invoke("register", { id: userId });

      setStatus(`User "${userId}" registered successfully. You may now login.`);
    } catch (error) {
      console.error(error);
      setStatus(`Registration failed: ${error}`);
    } finally {
      setIsBusy(false);
    }
  };

  const handleLogin = async () => {
    if (!userId.trim()) {
      setStatus("Please enter a user ID first.");
      return;
    }

    try {
      setIsBusy(true);
      setStatus("Starting KR-IBI login...");

      // Step 1: server creates challenge
      const [c1, c2] = await invoke("login_start", { id: userId });

      setStatus("Challenge received. Generating KR-IBI response...");

      // Step 2: client/backend-side response generation
      // In your current prototype, backend stores session state,
      // so only ID is needed here.
      const [s1, s2] = await invoke("login_respond", { id: userId });

      setStatus("Verifying login...");

      // Step 3: verification
      const verified = await invoke("login_verify", {
        id: userId,
        s1,
        s2,
      });

      if (verified) {
        setStatus(`Login successful. Welcome, ${userId}.`);
        onLoginSuccess(userId);
      } else {
        setStatus("Login failed. Invalid KR-IBI proof.");
      }
    } catch (error) {
      console.error(error);
      setStatus(`Login error: ${error}`);
    } finally {
      setIsBusy(false);
    }
  };

  return (
    <div className="auth-card">
      <h1>Secure Data Sharing Platform</h1>
      <h2>KR-IBI Authentication</h2>

      <input
        type="text"
        placeholder="Enter user ID"
        value={userId}
        onChange={(e) => setUserId(e.target.value)}
        disabled={isBusy}
      />

      <div className="auth-buttons">
        <button onClick={handleRegister} disabled={isBusy}>
          Register New User
        </button>

        <button onClick={handleLogin} disabled={isBusy}>
          Login
        </button>
      </div>

      <p className="status-text">{status}</p>
    </div>
  );
}