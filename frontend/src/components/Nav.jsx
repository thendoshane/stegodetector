import { signOut } from "firebase/auth";
import { Link, useNavigate } from "react-router-dom";
import { auth } from "../firebase/firebase";

export default function Nav() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut(auth);
    navigate("/");
  };

  return (
    <nav style={{ 
      display: "flex", 
      justifyContent: "space-between", 
      padding: "1rem 2rem", 
      background: "#333", 
      color: "white" 
    }}>
      <div style={{ fontWeight: "bold", fontSize: "1.2rem" }}>
        <Link to="/dashboard" style={{ color: "white", textDecoration: "none" }}>StegoDetector</Link>
      </div>
      <div>
        <button 
          onClick={handleLogout} 
          style={{ background: "transparent", border: "1px solid white", color: "white", cursor: "pointer", padding: "5px 10px" }}
        >
          Logout
        </button>
      </div>
    </nav>
  );
}