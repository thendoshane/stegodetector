// src/pages/Scan.jsx
import { useEffect, useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import Nav from "../components/Nav";
import { auth, db, storage } from "../firebase/firebase";
import { API_BASE } from "../api";
import {
  addDoc,
  collection,
  doc,
  onSnapshot,
  orderBy,
  query,
  serverTimestamp,
} from "firebase/firestore";
import { ref, uploadBytes, getDownloadURL } from "firebase/storage";
import { v4 as uuid } from "uuid";

const TABS = ["upload", "stego", "yara", "anomaly", "hybrid", "vt"];

const ProgressBar = ({ active, label }) => (
  <div style={{ margin: "12px 0" }}>
    {active ? (
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <div
          style={{
            width: 18,
            height: 18,
            borderRadius: "50%",
            border: "2px solid #666",
            borderTop: "2px solid white",
            animation: "spin 1s linear infinite",
          }}
        />
        <div style={{ opacity: 0.9 }}>{label || "Working..."}</div>
      </div>
    ) : null}

    <style>{`
      @keyframes spin { 0% {transform: rotate(0deg);} 100% {transform: rotate(360deg);} }
    `}</style>
  </div>
);

const downloadCSV = (rows, filename) => {
  if (!rows || rows.length === 0) {
    alert("Nothing to export.");
    return;
  }

  const headers = Array.from(
    rows.reduce((set, r) => {
      Object.keys(r || {}).forEach((k) => set.add(k));
      return set;
    }, new Set())
  );

  const esc = (v) => {
    if (v === null || v === undefined) return "";
    const s = String(v);
    if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };

  const lines = [];
  lines.push(headers.map(esc).join(","));
  for (const r of rows) {
    lines.push(headers.map((h) => esc(r?.[h])).join(","));
  }

  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = filename;
  a.click();
};


const downloadJSON = (data, filename) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = filename;
  a.click();
};

export default function Scan() {
  const { scanId } = useParams();

  const [activeTab, setActiveTab] = useState("upload");
  const [busy, setBusy] = useState({ active: false, label: "" });

  const [images, setImages] = useState([]);
  const [yaraRows, setYaraRows] = useState([]);
  const [anomRows, setAnomRows] = useState([]);
  const [hybridRows, setHybridRows] = useState([]);
  const [vtRows, setVtRows] = useState([]);
  const [metricsLatest, setMetricsLatest] = useState(null);

  // payload controls
  const [payloadMode, setPayloadMode] = useState("random"); // "random" | "user"
  const [payloadSize, setPayloadSize] = useState(2048);
  const [payloadEncoding, setPayloadEncoding] = useState("utf-8"); // "utf-8" | "base64"
  const [payloadText, setPayloadText] = useState("");

  // ML + fusion controls
  const [trainSet, setTrainSet] = useState("original");
  const [testOn, setTestOn] = useState("all");
  const [fusion, setFusion] = useState("OR");
  const [metricsScope, setMetricsScope] = useState("intersection");

  // custom yara rules
  const [yaraRulesFile, setYaraRulesFile] = useState(null);

  // auth
  const [user, setUser] = useState(auth.currentUser);

  useEffect(() => {
    const unsub = auth.onAuthStateChanged((u) => setUser(u));
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!scanId) return;

    const unsubImages = onSnapshot(
      query(
        collection(db, "scans", scanId, "images"),
        orderBy("createdAt", "desc")
      ),
      (snap) => {
        const r = [];
        snap.forEach((d) => r.push({ id: d.id, ...d.data() }));
        setImages(r);
      }
    );

    const unsubYara = onSnapshot(
      collection(db, "scans", scanId, "yara_results"),
      (snap) => {
        const r = [];
        snap.forEach((d) => r.push({ id: d.id, ...d.data() }));
        setYaraRows(r);
      }
    );

    const unsubAnom = onSnapshot(
      collection(db, "scans", scanId, "anomaly_results"),
      (snap) => {
        const r = [];
        snap.forEach((d) => r.push({ id: d.id, ...d.data() }));
        setAnomRows(r);
      }
    );

    const unsubHybrid = onSnapshot(
      collection(db, "scans", scanId, "hybrid_results"),
      (snap) => {
        const r = [];
        snap.forEach((d) => r.push({ id: d.id, ...d.data() }));
        setHybridRows(r);
      }
    );

    const unsubVT = onSnapshot(
      collection(db, "scans", scanId, "virustotal_results"),
      (snap) => {
        const r = [];
        snap.forEach((d) => r.push({ id: d.id, ...d.data() }));
        setVtRows(r);
      }
    );

    const unsubMetrics = onSnapshot(
      doc(db, "scans", scanId, "metrics", "latest"),
      (snap) => {
        setMetricsLatest(snap.exists() ? snap.data() : null);
      }
    );

    return () => {
      unsubImages();
      unsubYara();
      unsubAnom();
      unsubHybrid();
      unsubVT();
      unsubMetrics();
    };
  }, [scanId]);

  const payloadPreview = useMemo(() => {
    if (payloadMode !== "user") return null;
    const text = payloadText || "";

    if (payloadEncoding === "base64") {
      const cleaned = text.trim().replace(/\s+/g, "");
      const pad = cleaned.endsWith("==") ? 2 : cleaned.endsWith("=") ? 1 : 0;
      const approxBytes = Math.max(
        0,
        Math.floor((cleaned.length * 3) / 4) - pad
      );
      return {
        charCount: text.length,
        byteCount: approxBytes,
        note: "base64 estimate (backend validates)",
      };
    }

    const approxBytes = new TextEncoder().encode(text).length;
    return { charCount: text.length, byteCount: approxBytes, note: "utf-8 bytes" };
  }, [payloadMode, payloadText, payloadEncoding]);

  async function getToken() {
    if (!user) throw new Error("Not logged in.");
    let token = await user.getIdToken(false);
    return token;
  }

  async function apiCall(endpoint, body = null, method = "POST") {
    if (!user) throw new Error("Not logged in.");

    let token = await getToken();
    const opts = {
      method,
      headers: { Authorization: `Bearer ${token}` },
    };
    if (body) {
      opts.body = JSON.stringify(body);
      opts.headers["Content-Type"] = "application/json";
    }

    let res;
    try {
      res = await fetch(`${API_BASE}${endpoint}`, opts);
    } catch (e) {
      // This is what you see as “Failed to fetch” (CORS/network).
      throw new Error("Failed to fetch (check backend is running + CORS + URL).");
    }

    if (res.status === 401) {
      token = await user.getIdToken(true);
      opts.headers.Authorization = `Bearer ${token}`;
      res = await fetch(`${API_BASE}${endpoint}`, opts);
    }

    if (!res.ok) {
      const t = await res.text();
      throw new Error(t || `Request failed (${res.status})`);
    }

    // some endpoints may return empty
    const txt = await res.text();
    return txt ? JSON.parse(txt) : { ok: true };
  }

  async function apiCallFormData(endpoint, formData, method = "POST") {
    if (!user) throw new Error("Not logged in.");

    let token = await getToken();
    const opts = {
      method,
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    };

    let res;
    try {
      res = await fetch(`${API_BASE}${endpoint}`, opts);
    } catch (e) {
      throw new Error("Failed to fetch (check backend is running + CORS + URL).");
    }

    if (res.status === 401) {
      token = await user.getIdToken(true);
      opts.headers.Authorization = `Bearer ${token}`;
      res = await fetch(`${API_BASE}${endpoint}`, opts);
    }

    if (!res.ok) {
      const t = await res.text();
      throw new Error(t || `Request failed (${res.status})`);
    }

    const txt = await res.text();
    return txt ? JSON.parse(txt) : { ok: true };
  }

  async function run(endpoint, label, body = {}, method = "POST") {
    setBusy({ active: true, label });
    try {
      await apiCall(endpoint, { scanId, ...body }, method);
    } catch (e) {
      alert(e?.message || String(e));
    } finally {
      setBusy({ active: false, label: "" });
    }
  }

  async function runResetWorkspace() {
    setBusy({ active: true, label: "Resetting workspace (keeping originals)..." });
    try {
      // backend: POST /scan/{scan_id}/reset
      await apiCall(`/scan/${scanId}/reset`, null, "POST");
      alert("Workspace reset complete (originals kept).");
    } catch (e) {
      alert(e?.message || String(e));
    } finally {
      setBusy({ active: false, label: "" });
    }
  }

  async function uploadYaraRules() {
    if (!yaraRulesFile) {
      alert("Select a .yar / .yara file first.");
      return;
    }
    const fn = (yaraRulesFile.name || "").toLowerCase();
    if (!(fn.endsWith(".yar") || fn.endsWith(".yara"))) {
      alert("Upload a .yar or .yara file.");
      return;
    }

    setBusy({ active: true, label: "Uploading custom YARA rules..." });
    try {
      const fd = new FormData();
      fd.append("file", yaraRulesFile);

      // backend: POST /yara/rules/upload?scanId=...
      await apiCallFormData(`/yara/rules/upload?scanId=${encodeURIComponent(scanId)}`, fd, "POST");
      alert("Custom YARA rules uploaded for this scan.");
      setYaraRulesFile(null);
    } catch (e) {
      alert(e?.message || String(e));
    } finally {
      setBusy({ active: false, label: "" });
    }
  }

    function buildDecisionRows() {
    // Join images + YARA + Anomaly + Hybrid into one decision-ready table.
    const imgMap = new Map(images.map((x) => [x.id, x]));
    const yaraMap = new Map(yaraRows.map((x) => [x.id, x]));
    const anomMap = new Map(anomRows.map((x) => [x.id, x]));
    const hybMap = new Map(hybridRows.map((x) => [x.id, x]));

    const ids = Array.from(imgMap.keys());

    return ids.map((id) => {
      const img = imgMap.get(id) || {};
      const y = yaraMap.get(id) || {};
      const a = anomMap.get(id) || {};
      const h = hybMap.get(id) || {};

      return {
        id,
        filename: img.filename || y.file || a.file || h.file || "",
        type: img.type || "",
        true_label: img.true_label ?? "",

        // YARA (LSB-aware)
        yara_detected: y.yara_detected ?? "",
        matched_rules: y.matched_rules ?? "",
        scanned_as: y.scanned_as ?? "",
        scan_source: y.scan_source ?? "",
        extract_error: y.extract_error ?? "",

        // ML
        ml_detected: a.ml_detected ?? "",
        anomaly_score: a.anomaly_score ?? "",
        threshold: a.threshold ?? "",
        trained_on: a.trained_on ?? "",
        tested_on: a.tested_on ?? "",

        // Hybrid
        fusion: h.fusion ?? "",
        final_pred: h.final_pred ?? "",
        decision_source: h.decision_source ?? "",
      };
    });
  }

  function exportYaraCSV() {
    const rows = (yaraRows || []).map((r) => ({
      id: r.id,
      file: r.file || "",
      yara_detected: r.yara_detected ?? "",
      matched_rules: r.matched_rules ?? "",
      scanned_as: r.scanned_as ?? "",
      scan_source: r.scan_source ?? "",
      extract_error: r.extract_error ?? "",
      createdAt: r.createdAt?.toDate ? r.createdAt.toDate().toISOString() : "",
    }));
    downloadCSV(rows, `yara_${scanId}.csv`);
  }

  function exportDecisionCSV() {
    const rows = buildDecisionRows();
    downloadCSV(rows, `decision_metrics_${scanId}.csv`);
  }

  function exportMetricsCSV() {
    if (!metricsLatest) {
      alert("No metrics yet. Run Hybrid then Compute Metrics.");
      return;
    }

    const rows = ["yara", "ml", "hybrid"].map((k) => ({
      method: k,
      evaluated: metricsLatest?.evaluated_counts?.[k] ?? 0,
      TP: metricsLatest?.counts?.[k]?.TP ?? 0,
      FP: metricsLatest?.counts?.[k]?.FP ?? 0,
      TN: metricsLatest?.counts?.[k]?.TN ?? 0,
      FN: metricsLatest?.counts?.[k]?.FN ?? 0,
      accuracy: metricsLatest?.metrics?.[k]?.accuracy ?? 0,
      precision: metricsLatest?.metrics?.[k]?.precision ?? 0,
      recall: metricsLatest?.metrics?.[k]?.recall ?? 0,
      f1: metricsLatest?.metrics?.[k]?.f1 ?? 0,
      fpr: metricsLatest?.metrics?.[k]?.fpr ?? 0,
      fnr: metricsLatest?.metrics?.[k]?.fnr ?? 0,
      scope: metricsLatest?.scope ?? "",
      fusion: metricsLatest?.fusion ?? "",
      total_images: metricsLatest?.evaluated_counts?.total_images ?? 0,
      hybrid_fp_count: (metricsLatest?.misclassifications?.hybrid_false_positives || []).length,
      hybrid_fn_count: (metricsLatest?.misclassifications?.hybrid_false_negatives || []).length,
    }));

    downloadCSV(rows, `metrics_summary_${scanId}.csv`);
  }

  async function uploadOriginal(file) {
    if (!user) {
      alert("You are not logged in.");
      return;
    }
    if (!file.type.startsWith("image/")) {
      alert("Please upload an image file.");
      return;
    }

    const id = uuid();
    const storagePath = `users/${user.uid}/scans/${scanId}/original/${id}_${file.name}`;
    const storageRef = ref(storage, storagePath);

    setBusy({ active: true, label: "Uploading image..." });
    try {
      await uploadBytes(storageRef, file);
      const url = await getDownloadURL(storageRef);

      await addDoc(collection(db, "scans", scanId, "images"), {
        ownerUid: user.uid,
        type: "original",
        true_label: 0,
        filename: file.name,
        storagePath,
        url,
        createdAt: serverTimestamp(),
      });
    } catch (e) {
      alert(e?.message || String(e));
    } finally {
      setBusy({ active: false, label: "" });
    }
  }

  const originals = useMemo(() => images.filter((x) => x.type === "original"), [images]);
  const stegos = useMemo(() => images.filter((x) => x.type === "stego"), [images]);

  const yaraDetected = useMemo(
    () => yaraRows.filter((x) => Number(x.yara_detected) === 1),
    [yaraRows]
  );
  const yaraMissed = useMemo(
    () => yaraRows.filter((x) => Number(x.yara_detected) === 0),
    [yaraRows]
  );

  const anomDetected = useMemo(
    () => anomRows.filter((x) => Number(x.ml_detected) === 1),
    [anomRows]
  );
  const anomClean = useMemo(
    () => anomRows.filter((x) => Number(x.ml_detected) === 0),
    [anomRows]
  );

  // NEW hybrid model: backend writes only intersection rows (IDs that have BOTH YARA + ML)
  const hybridDetected = useMemo(
    () => hybridRows.filter((x) => Number(x.final_pred) === 1),
    [hybridRows]
  );
  const hybridClean = useMemo(
    () => hybridRows.filter((x) => Number(x.final_pred) === 0),
    [hybridRows]
  );

  const canRunEmbed =
    originals.length > 0 &&
    !busy.active &&
    !!user &&
    (payloadMode === "random" ||
      (payloadMode === "user" && (payloadText || "").trim().length > 0));

  const canRunYara = images.length > 0 && !busy.active && !!user;
  const canRunAnom = images.length > 0 && !busy.active && !!user;

  // backend now errors if there is no intersection, so require BOTH
  const canRunHybrid = yaraRows.length > 0 && anomRows.length > 0 && !busy.active && !!user;

  const canRunMetrics = !busy.active && !!user;
  const canRunVT = !busy.active && !!user && anomRows.length > 0;

  // Gallery (always show previews)
  const Gallery = ({ title, list }) => (
    <div style={{ marginTop: 14 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <h4 style={{ margin: 0 }}>{title}</h4>
        <div style={{ opacity: 0.75, fontSize: 12 }}>Items: {list.length}</div>
      </div>

      {list.length === 0 ? (
        <div style={{ opacity: 0.8, marginTop: 8 }}>No images.</div>
      ) : (
        <div
          style={{
            marginTop: 10,
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
            gap: 12,
          }}
        >
          {list.map((img) => (
            <div key={img.id} className="card" style={{ padding: 10 }}>
              <img
                src={img.url}
                alt={img.filename}
                style={{ width: "100%", borderRadius: 8 }}
              />
              <div style={{ fontSize: 12, marginTop: 8, opacity: 0.9 }}>
                {img.filename}
              </div>
              <div style={{ fontSize: 12, opacity: 0.75 }}>
                type: {img.type || "—"}
                {img.type === "stego" ? ` | len: ${img.payload_len ?? "—"}` : ""}
              </div>

              {img.type === "stego" && (
                <>
                  <div style={{ fontSize: 12, opacity: 0.75 }}>
                    mode: {img.payload_mode ?? "—"} | enc: {img.payload_encoding ?? "—"}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      opacity: 0.7,
                      wordBreak: "break-all",
                      marginTop: 6,
                    }}
                  >
                    preview(b64): {img.payload_preview_base64 ?? "—"}
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <div>
      <Nav />
      <div style={{ padding: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <h2 style={{ marginBottom: 6 }}>Scan Workspace</h2>
            <div style={{ opacity: 0.8, fontSize: 13 }}>Scan ID: {scanId}</div>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <Link className="btn-secondary" to="/dashboard">Back</Link>

            <button
              className="btn-secondary"
              disabled={busy.active || !user}
              onClick={runResetWorkspace}
              title="Deletes stego + all results/metrics/VT, keeps originals."
            >
              Reset Workspace
            </button>

            <button
              className="btn-secondary"
              onClick={() =>
                downloadJSON(
                  { images, yaraRows, anomRows, hybridRows, vtRows, metricsLatest },
                  `Scan_${scanId}_Report.json`
                )
              }
            >
              Export JSON
            </button>
          </div>
        </div>

        <ProgressBar active={busy.active} label={busy.label} />

        {/* Tabs */}
        <div style={{ display: "flex", gap: 10, marginTop: 18, flexWrap: "wrap" }}>
          {TABS.map((t) => (
            <button
              key={t}
              className={`nav-btn ${activeTab === t ? "active" : ""}`}
              onClick={() => setActiveTab(t)}
            >
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        {/* UPLOAD */}
        {activeTab === "upload" && (
          <div style={{ marginTop: 18 }}>
            <h3>Upload Original Images</h3>
            <input
              type="file"
              accept="image/*"
              multiple
              disabled={busy.active || !user}
              onChange={(e) => {
                const files = Array.from(e.target.files || []);
                files.forEach(uploadOriginal);
                e.target.value = "";
              }}
            />

            <div style={{ marginTop: 16, opacity: 0.85 }}>
              <div>Originals: {originals.length}</div>
              <div>Stego: {stegos.length}</div>
              <div>YARA results: {yaraRows.length}</div>
              <div>Anomaly results: {anomRows.length}</div>
              <div>Hybrid results (intersection only): {hybridRows.length}</div>
              <div>VirusTotal results: {vtRows.length}</div>
            </div>

            {/* Payload controls */}
            <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 10, maxWidth: 760 }}>
              <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                <span style={{ opacity: 0.85 }}>Payload mode:</span>
                <select value={payloadMode} onChange={(e) => setPayloadMode(e.target.value)} disabled={busy.active || !user}>
                  <option value="random">Random</option>
                  <option value="user">User</option>
                </select>

                {payloadMode === "random" && (
                  <>
                    <span style={{ opacity: 0.85 }}>Random bytes:</span>
                    <input
                      type="number"
                      min={1}
                      max={32768}
                      value={payloadSize}
                      onChange={(e) => setPayloadSize(Number(e.target.value))}
                      style={{ width: 120 }}
                      disabled={busy.active || !user}
                    />
                  </>
                )}

                {payloadMode === "user" && (
                  <>
                    <span style={{ opacity: 0.85 }}>Encoding:</span>
                    <select value={payloadEncoding} onChange={(e) => setPayloadEncoding(e.target.value)} disabled={busy.active || !user}>
                      <option value="utf-8">UTF-8</option>
                      <option value="base64">Base64</option>
                    </select>
                  </>
                )}
              </div>

              {payloadMode === "user" && (
                <>
                  <textarea
                    value={payloadText}
                    onChange={(e) => setPayloadText(e.target.value)}
                    placeholder={payloadEncoding === "base64" ? "Paste base64 payload here…" : "Type/paste payload text here…"}
                    rows={5}
                    disabled={busy.active || !user}
                    style={{ width: "100%", padding: 10, borderRadius: 8 }}
                  />
                  <div style={{ fontSize: 12, opacity: 0.8 }}>
                    Preview: {payloadPreview?.charCount ?? 0} chars | ~{payloadPreview?.byteCount ?? 0} bytes{" "}
                    <span style={{ opacity: 0.75 }}>({payloadPreview?.note || ""})</span>
                  </div>
                </>
              )}
            </div>

            <div style={{ marginTop: 18, display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button
                className="btn-primary"
                disabled={!canRunEmbed}
                onClick={() =>
                  run("/embed", "Generating stego images…", {
                    payload_mode: payloadMode,
                    payload_size: Number(payloadSize),
                    payload_text: payloadMode === "user" ? payloadText : null,
                    payload_encoding: payloadMode === "user" ? payloadEncoding : "utf-8",
                  })
                }
              >
                Generate Stego
              </button>
            </div>

            <p style={{ marginTop: 14, opacity: 0.75 }}>
              Pipeline order: <b>Embed → YARA → Anomaly → Hybrid → Metrics</b>
            </p>

            <Gallery title="Original images (preview)" list={originals} />
            <Gallery title="Stego images (preview)" list={stegos} />
          </div>
        )}

        {/* STEGO */}
        {activeTab === "stego" && (
          <div style={{ marginTop: 18 }}>
            <h3>Stego Images</h3>
            <Gallery title="Stego images (preview)" list={stegos} />
            <Gallery title="Original images (preview)" list={originals} />
          </div>
        )}

        {/* YARA */}
        {activeTab === "yara" && (
          <div style={{ marginTop: 18 }}>
            <h3>YARA (Signature Detection)</h3>

            {/* Custom rules upload */}
            <div style={{ marginTop: 10, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <input
                type="file"
                accept=".yar,.yara"
                disabled={busy.active || !user}
                onChange={(e) => setYaraRulesFile((e.target.files || [])[0] || null)}
              />
              <button
                className="btn-secondary"
                disabled={busy.active || !user || !yaraRulesFile}
                onClick={uploadYaraRules}
                title="Uploads per-scan rules used by /yara"
              >
                Upload Custom Rules
              </button>
              <div style={{ fontSize: 12, opacity: 0.75 }}>
                {yaraRulesFile ? `Selected: ${yaraRulesFile.name}` : "No rules selected (default rules will be used)."}
              </div>
            </div>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 12 }}>
              <button
                className="btn-secondary"
                disabled={!canRunYara}
                onClick={() => run("/yara", "Running YARA on originals…", { target_type: "original" })}
              >
                Scan Originals
              </button>
              <button
                className="btn-secondary"
                disabled={!canRunYara}
                onClick={() => run("/yara", "Running YARA on stego…", { target_type: "stego" })}
              >
                Scan Stego
              </button>
              <button
                className="btn-primary"
                disabled={!canRunYara}
                onClick={() => run("/yara", "Running YARA on ALL images…", { target_type: "all" })}
              >
                Scan All (Original + Stego)
              </button>

              <button
                className="btn-secondary"
                disabled={busy.active || !user || yaraRows.length === 0}
                onClick={exportYaraCSV}
                title="Download the current YARA table as CSV"
              >
                Export YARA CSV
              </button>

            </div>

            <div style={{ marginTop: 14, opacity: 0.85 }}>
              <div>Detected: {yaraDetected.length}</div>
              <div>Not detected: {yaraMissed.length}</div>
            </div>

            {yaraRows.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <table border="1" cellPadding="6" style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Detected</th>
                      <th>Rules</th>
                      <th>Scanned As</th>
                      <th>Scan Source</th>
                      <th>Extract Error</th>

                    </tr>
                  </thead>
                  <tbody>
                    {yaraRows
                      .slice()
                      .sort((a, b) => Number(b.yara_detected) - Number(a.yara_detected))
                      .map((r) => (
                        <tr key={r.id}>
                          <td>{r.file}</td>
                          <td style={{ fontWeight: Number(r.yara_detected) ? "bold" : "normal" }}>
                            {Number(r.yara_detected) ? "YES" : "NO"}
                          </td>
                          <td style={{ fontSize: 12 }}>{r.matched_rules || "—"}</td>
                          <td style={{ fontSize: 12 }}>{r.scanned_as || "—"}</td>
                          <td style={{ fontSize: 12 }}>{r.scan_source || "—"}</td>
                          <td style={{ fontSize: 12, maxWidth: 420, whiteSpace: "pre-wrap" }}>
                            {r.extract_error || "—"}
                          </td>

                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}

            <Gallery title="Original images (preview)" list={originals} />
            <Gallery title="Stego images (preview)" list={stegos} />
          </div>
        )}

        {/* ANOMALY */}
        {activeTab === "anomaly" && (
          <div style={{ marginTop: 18 }}>
            <h3>ML Anomaly Detection</h3>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Train on:
                <select value={trainSet} onChange={(e) => setTrainSet(e.target.value)} disabled={busy.active || !user}>
                  <option value="original">original</option>
                  <option value="stego">stego (not recommended)</option>
                </select>
              </label>

              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Test on:
                <select value={testOn} onChange={(e) => setTestOn(e.target.value)} disabled={busy.active || !user}>
                  <option value="all">all</option>
                  <option value="original">original</option>
                  <option value="stego">stego</option>
                  <option value="yara_detected">yara_detected</option>
                  <option value="yara_missed">yara_missed</option>
                </select>
              </label>

              <button
                className="btn-primary"
                disabled={!canRunAnom}
                onClick={() => run("/anomaly", "Running anomaly detection…", { train_on: trainSet, test_on: testOn })}
              >
                Run Anomaly
              </button>

              <Link className="btn-secondary" to={`/scan/${scanId}/anomaly`}>Open Full Anomaly Page</Link>
            </div>

            <div style={{ marginTop: 14, opacity: 0.85 }}>
              <div>Detected anomalies: {anomDetected.length}</div>
              <div>Normal: {anomClean.length}</div>
            </div>

            {anomRows.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <table border="1" cellPadding="6" style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Score</th>
                      <th>Threshold</th>
                      <th>Detected</th>
                      <th>Train</th>
                      <th>Test</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anomRows
                      .slice()
                      .sort((a, b) => Number(b.anomaly_score) - Number(a.anomaly_score))
                      .map((r) => (
                        <tr key={r.id}>
                          <td>{r.file}</td>
                          <td>{Number(r.anomaly_score ?? 0).toFixed(6)}</td>
                          <td>{Number(r.threshold ?? 0).toFixed(6)}</td>
                          <td style={{ fontWeight: Number(r.ml_detected) ? "bold" : "normal" }}>
                            {Number(r.ml_detected) ? "YES" : "NO"}
                          </td>
                          <td style={{ fontSize: 12 }}>{r.trained_on || "—"}</td>
                          <td style={{ fontSize: 12 }}>{r.tested_on || "—"}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}

            <Gallery title="Original images (preview)" list={originals} />
            <Gallery title="Stego images (preview)" list={stegos} />
          </div>
        )}

        {/* HYBRID + METRICS */}
        {activeTab === "hybrid" && (
          <div style={{ marginTop: 18 }}>
            <h3>Hybrid Fusion + Metrics</h3>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Fusion:
                <select value={fusion} onChange={(e) => setFusion(e.target.value)} disabled={busy.active || !user}>
                  <option value="OR">OR (YARA or ML)</option>
                  <option value="AND">AND (YARA and ML)</option>
                </select>
              </label>

              <button
                className="btn-primary"
                disabled={!canRunHybrid}
                onClick={() => run("/hybrid", "Fusing YARA + ML (intersection only)…", { fusion })}
                title="Hybrid now evaluates ONLY the intersection of IDs that have BOTH YARA + ML results."
              >
                Run Hybrid
              </button>

              <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                Metrics scope:
                <select value={metricsScope} onChange={(e) => setMetricsScope(e.target.value)} disabled={busy.active || !user}>
                  <option value="intersection">intersection (only evaluated items)</option>
                  <option value="require_all">require_all (strict)</option>
                </select>
              </label>

              <button
                className="btn-secondary"
                disabled={!canRunMetrics}
                onClick={() => run("/metrics", "Computing metrics…", { fusion, scope: metricsScope })}
              >
                Compute Metrics
              </button>

              <button
                className="btn-secondary"
                disabled={busy.active || !user || !metricsLatest}
                onClick={exportMetricsCSV}
                title="Download the latest metrics summary as CSV"
              >
                Export Metrics CSV
              </button>

              <button
                className="btn-secondary"
                disabled={busy.active || !user || images.length === 0}
                onClick={exportDecisionCSV}
                title="Download per-image joined results (images + YARA + ML + Hybrid) as CSV"
              >
                Export Decision CSV
              </button>

            </div>

            <div style={{ marginTop: 12, opacity: 0.8, fontSize: 12 }}>
              Note: Hybrid rows are now written only for the <b>intersection</b> (images that have BOTH YARA + ML results).
              If you choose <b>require_all</b> but you did not run YARA+ML on every image, the backend will correctly return “Missing results”.
            </div>

            <div style={{ marginTop: 14, opacity: 0.85 }}>
              <div>Hybrid rows (evaluated): {hybridRows.length}</div>
              <div>Hybrid detected: {hybridDetected.length}</div>
              <div>Hybrid benign: {hybridClean.length}</div>
            </div>

            {/* Metrics latest */}
            <div style={{ marginTop: 18 }}>
              <h4 style={{ marginBottom: 8 }}>Latest Metrics</h4>
              {!metricsLatest ? (
                <div style={{ opacity: 0.8 }}>No metrics yet. Run Hybrid, then Compute Metrics.</div>
              ) : (
                <div className="card" style={{ padding: 14 }}>
                  <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 10 }}>
                    Evaluated: YARA={metricsLatest?.evaluated_counts?.yara ?? 0} | ML={metricsLatest?.evaluated_counts?.ml ?? 0} | HYBRID={metricsLatest?.evaluated_counts?.hybrid ?? 0} | Total images={metricsLatest?.evaluated_counts?.total_images ?? 0}
                    <br />
                    Scope: {metricsLatest?.scope || "—"} | Fusion: {metricsLatest?.fusion || "—"}
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
                    {["yara", "ml", "hybrid"].map((k) => (
                      <div key={k} className="card" style={{ padding: 12 }}>
                        <div style={{ fontWeight: "bold", marginBottom: 8 }}>{k.toUpperCase()}</div>
                        <div style={{ fontSize: 13, opacity: 0.9 }}>
                          <div><b>Counts</b>: {JSON.stringify(metricsLatest?.counts?.[k] || {})}</div>
                          <div><b>Accuracy</b>: {(metricsLatest?.metrics?.[k]?.accuracy ?? 0).toFixed(4)}</div>
                          <div><b>Precision</b>: {(metricsLatest?.metrics?.[k]?.precision ?? 0).toFixed(4)}</div>
                          <div><b>Recall</b>: {(metricsLatest?.metrics?.[k]?.recall ?? 0).toFixed(4)}</div>
                          <div><b>F1</b>: {(metricsLatest?.metrics?.[k]?.f1 ?? 0).toFixed(4)}</div>
                          <div><b>FPR</b>: {(metricsLatest?.metrics?.[k]?.fpr ?? 0).toFixed(4)}</div>
                          <div><b>FNR</b>: {(metricsLatest?.metrics?.[k]?.fnr ?? 0).toFixed(4)}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ marginTop: 10, fontSize: 12, opacity: 0.8 }}>
                    Hybrid FP: {(metricsLatest?.misclassifications?.hybrid_false_positives || []).length} | Hybrid FN: {(metricsLatest?.misclassifications?.hybrid_false_negatives || []).length}
                  </div>
                </div>
              )}
            </div>

            <Gallery title="Original images (preview)" list={originals} />
            <Gallery title="Stego images (preview)" list={stegos} />
          </div>
        )}

        {/* VIRUSTOTAL */}
        {activeTab === "vt" && (
          <div style={{ marginTop: 18 }}>
            <h3>VirusTotal Benchmarking</h3>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button
                className="btn-primary"
                disabled={!canRunVT}
                onClick={() => run("/virustotal", "Submitting ML undetected files to VirusTotal…", { mode: "undetected" })}
              >
                Submit ML Undetected
              </button>

              <button
                className="btn-secondary"
                disabled={!canRunVT}
                onClick={() => run("/virustotal", "Submitting ML detected files to VirusTotal…", { mode: "detected" })}
              >
                Submit ML Detected
              </button>

              <button
                className="btn-secondary"
                disabled={busy.active || !user}
                onClick={() => run("/virustotal/refresh", "Refreshing queued VirusTotal results…", { only_status: "queued", max_items: 25 })}
              >
                Refresh Queued VT
              </button>

              <Link className="btn-secondary" to={`/scan/${scanId}/virustotal`}>Open Full VirusTotal Page</Link>
            </div>

            {vtRows.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <table border="1" cellPadding="6" style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Status</th>
                      <th>Detections</th>
                      <th>Engines</th>
                      <th>Ratio</th>
                      <th>Analysis ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vtRows.map((r) => {
                      const det = r.detections === null || r.detections === undefined ? "—" : Number(r.detections);
                      const eng = r.engines === null || r.engines === undefined ? "—" : Number(r.engines);
                      const ratio =
                        typeof det === "number" && typeof eng === "number" && eng
                          ? (det / eng).toFixed(4)
                          : "—";

                      return (
                        <tr key={r.id}>
                          <td>{r.file}</td>
                          <td>{r.status}</td>
                          <td>{det}</td>
                          <td>{eng}</td>
                          <td>{ratio}</td>
                          <td style={{ fontSize: 12 }}>{r.analysisId || "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            <Gallery title="Original images (preview)" list={originals} />
            <Gallery title="Stego images (preview)" list={stegos} />
          </div>
        )}
      </div>
    </div>
  );
}