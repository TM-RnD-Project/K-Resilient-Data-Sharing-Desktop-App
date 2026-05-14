import Upload from "./Upload";
import Search from "./Search";

export default function Dashboard({ user, onLogout }) {
  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <div>
          <span className="welcome-text">Logged in as: {user}</span>
          <button onClick={onLogout}>Logout</button>
        </div>
      </div>

      <Upload user={user} />
      <Search user={user} />
    </div>
  );
}