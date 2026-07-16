import Upload from "./Upload";
import Search from "./Search";
import { invoke } from "@tauri-apps/api/core";

export default function Dashboard({ user, onLogout }) {
  const handleLogout = async () => {
    try {
      await invoke("logout", { id: user });
    } finally {
      onLogout();
    }
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <div>
          <span className="welcome-text">Logged in as: {user}</span>
          <button onClick={handleLogout}>Logout</button>
        </div>
      </div>

      <Upload user={user} />
      <Search user={user} />
    </div>
  );
}
