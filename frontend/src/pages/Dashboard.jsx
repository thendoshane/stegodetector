import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { 
  collection, 
  query, 
  where, 
  orderBy, 
  onSnapshot, 
  addDoc, 
  serverTimestamp 
} from "firebase/firestore";
import { auth, db } from "../firebase/firebase";
import Nav from "../components/Nav";

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false); // Added loading state
  const navigate = useNavigate();
  const user = auth.currentUser;

  useEffect(() => {
    if (!user) return;
    
    // Listen for scans owned by this user
    const q = query(
      collection(db, "scans"),
      where("ownerUid", "==", user.uid),
      orderBy("createdAt", "desc") // changed from updatedAt to createdAt for consistent sorting
    );

    const unsub = onSnapshot(q, (snap) => {
      const list = [];
      snap.forEach(doc => list.push({ id: doc.id, ...doc.data() }));
      setScans(list);
    }, (error) => {
      console.error("Error fetching scans:", error);
      // If this errors, it's likely a missing index or permission issue
      if (error.code === 'failed-precondition') {
        alert("Firestore Index required. Check console for the link to create it.");
      }
    });

    return () => unsub();
  }, [user]);

  const createScan = async () => {
    if (!user) {
      alert("You must be logged in.");
      return;
    }

    setLoading(true);
    try {
      // 1. Attempt to create the document in Firestore
      const docRef = await addDoc(collection(db, "scans"), {
        ownerUid: user.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        name: `Scan ${new Date().toLocaleString()}`,
        // Initialize empty counters to prevent undefined errors later
        status: "created" 
      });

      // 2. Navigate to the new scan page
      console.log("Scan created with ID:", docRef.id);
      navigate(`/scan/${docRef.id}`);

    } catch (err) {
      console.error("Error creating scan:", err);
      // 3. Show the actual error to the user
      alert(`Failed to create scan: ${err.message}\n\nCheck if Firestore Rules allow writes!`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <Nav />
      <div style={{ padding: "2rem", maxWidth: "800px", margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "2rem", alignItems: "center" }}>
          <h1>My Scans</h1>
          <button 
            onClick={createScan}
            disabled={loading}
            className="btn-primary"
            style={{ 
              padding: "10px 20px", 
              background: loading ? "#ccc" : "#28a745", 
              color: "white", 
              border: "none", 
              borderRadius: "4px",
              cursor: loading ? "not-allowed" : "pointer",
              fontSize: "1rem"
            }}
          >
            {loading ? "Creating..." : "+ New Scan"}
          </button>
        </div>

        <div style={{ display: "grid", gap: "1rem" }}>
          {scans.length === 0 ? (
            <p style={{ opacity: 0.6 }}>No scans found. Click the green button to start.</p>
          ) : (
            scans.map(scan => (
              <div key={scan.id} className="card" style={{ padding: "1.5rem", border: "1px solid #ddd", borderRadius: "8px", background: "white" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <h3 style={{ margin: "0 0 5px 0" }}>{scan.name || "Untitled Scan"}</h3>
                    <div style={{ fontSize: "0.85rem", color: "#666" }}>
                      Created: {scan.createdAt?.toDate ? scan.createdAt.toDate().toLocaleString() : "Just now"}
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "#999" }}>ID: {scan.id}</div>
                  </div>
                  <Link 
                    to={`/scan/${scan.id}`} 
                    className="btn-primary"
                    style={{ textDecoration: "none", background: "#007bff", fontSize: "0.9rem" }}
                  >
                    Open Workspace
                  </Link>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}