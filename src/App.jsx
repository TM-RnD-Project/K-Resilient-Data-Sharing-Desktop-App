import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import AuthPage from "./components/AuthPage";
import Dashboard from "./components/Dashboard";
import "./App.css";

function App() {
  const [currentUser, setCurrentUser] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [ready, setReady] = useState(false);
  const [setupError, setSetupError] = useState("");

  useEffect(() => {
    async function init() {
      try {
        await invoke("setup_all", { k: 3 });
        setReady(true);
      } catch (err) {
        console.error(err);
        setSetupError(String(err));
      }
    }

    init();
  }, []);

  if (setupError) {
    return <p>Setup failed: {setupError}</p>;
  }

  if (!ready) {
    return <p>Initialising cryptographic system...</p>;
  }

  return (
    <div className="app-container">
      {!isLoggedIn ? (
        <AuthPage
          onLoginSuccess={(id) => {
            setCurrentUser(id);
            setIsLoggedIn(true);
          }}
        />
      ) : (
        <Dashboard
          user={currentUser}
          onLogout={() => {
            setCurrentUser("");
            setIsLoggedIn(false);
          }}
        />
      )}
    </div>
  );
}

export default App;