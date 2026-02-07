import { Link } from "react-router-dom";
import Nav from "../components/Nav";
import { auth } from "../firebase/firebase";

export default function Home() {
  const user = auth.currentUser;

  return (
    <div>
      <Nav />
      <div style={{ padding: 24, maxWidth: 980, margin: "0 auto" }}>
        <h1 style={{ marginBottom: 6 }}>StegoDetector</h1>
        <p style={{ opacity: 0.85, lineHeight: 1.5 }}>
          This tool benchmarks detection of hidden payloads in images (LSB steganography) using:
          <b> YARA signature scanning</b>, <b>ML anomaly detection</b>, and a <b>hybrid fusion</b>.
        </p>

        <div className="card" style={{ padding: 16, marginTop: 16 }}>
          <h3 style={{ marginTop: 0 }}>How to use</h3>
          <ol style={{ opacity: 0.9, lineHeight: 1.6 }}>
            <li>Upload original images</li>
            <li>Generate stego images (payload embedded in LSB)</li>
            <li>Run YARA (payload extraction + signature match)</li>
            <li>Run anomaly detection (feature-based)</li>
            <li>Run hybrid + compute metrics</li>
            <li>Use VirusTotal for external AV benchmarking + export reports</li>
          </ol>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 18 }}>
          {!user ? (
            <>
              <Link className="btn-primary" to="/login">Login</Link>
              <Link className="btn-secondary" to="/register">Register</Link>
            </>
          ) : (
            <Link className="btn-primary" to="/dashboard">Go to Dashboard</Link>
          )}
        </div>
      </div>
    </div>
  );
}
