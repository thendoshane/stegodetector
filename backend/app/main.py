from dotenv import load_dotenv
load_dotenv()

import base64
import hashlib
import io
import os
import random
import time
from datetime import timedelta
from uuid import uuid4
from typing import Any, Dict, List, Optional, Tuple, Literal

import numpy as np
import requests
from PIL import Image

from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import firebase_admin
from firebase_admin import credentials, auth, firestore, storage, initialize_app

import yara
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# -----------------------------
# CONFIGURATION
# -----------------------------
RULES_PATH = os.environ.get("RULES_PATH", "stego_rules.yar")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

FEATURE_ORDER = [
    # structural
    "file_size_bytes", "width", "height",

    # byte-level statistics
    "byte_entropy", "byte_chi_square_uniform", "byte_zero_ratio",

    # color channel statistics
    "r_mean", "r_var", "g_mean", "g_var", "b_mean", "b_var",

    # LSB statistics (pixel-level)
    "lsb_ratio_r", "lsb_ratio_g", "lsb_ratio_b",
    "lsb_entropy_r", "lsb_entropy_g", "lsb_entropy_b",
    "lsb_transition_rate"
]

RNG_SEED = int(os.environ.get("RNG_SEED", "42"))
DEFAULT_CONTAMINATION = float(os.environ.get("IF_CONTAMINATION", "0.01"))
DEFAULT_VAL_QUANTILE = float(os.environ.get("VAL_QUANTILE", "0.95"))

PAYLOAD_PREVIEW_BYTES = int(os.environ.get("PAYLOAD_PREVIEW_BYTES", "24"))
MAX_PAYLOAD_BYTES = int(os.environ.get("MAX_PAYLOAD_BYTES", "32768"))

# Baseline/global model limits (avoid exploding cost)
BASELINE_MAX_TRAIN = int(os.environ.get("BASELINE_MAX_TRAIN", "600"))
BASELINE_MAX_VAL = int(os.environ.get("BASELINE_MAX_VAL", "200"))

app = FastAPI()

# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# FIREBASE INIT
# -----------------------------
FIREBASE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET")
if not firebase_admin._apps:
    if FIREBASE_BUCKET:
        initialize_app(options={"storageBucket": FIREBASE_BUCKET})
    else:
        initialize_app()

db = firestore.client()
bucket = storage.bucket()

# -----------------------------
# REQUEST MODELS
# -----------------------------
class EmbedReq(BaseModel):
    scanId: str
    payload_mode: Literal["random", "user"] = "random"
    payload_size: int = 2048
    payload_text: Optional[str] = None
    payload_encoding: Literal["utf-8", "base64"] = "utf-8"

    @field_validator("payload_size")
    @classmethod
    def _payload_size_bounds(cls, v: int) -> int:
        if v < 1:
            raise ValueError("payload_size must be >= 1")
        if v > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload_size too large (max {MAX_PAYLOAD_BYTES})")
        return v


class YaraReq(BaseModel):
    scanId: str
    target_type: Literal["original", "stego", "all"] = "stego"


class AnomReq(BaseModel):
    scanId: str

    # "workspace" = train on current scan originals/stegos (like before)
    # "baseline"  = use persistent baseline model trained from ALL original images across your workspaces
    model_mode: Literal["workspace", "baseline"] = "workspace"

    # only used when model_mode="workspace"
    train_on: Literal["original", "stego"] = "original"

    test_on: Literal["original", "stego", "all", "yara_detected", "yara_missed"] = "all"


class BaselineTrainReq(BaseModel):
    # Optional: if you want to force baseline to include this scan even if small
    scanId: Optional[str] = None
    # only originals are used for baseline (clean distribution)
    max_train: int = BASELINE_MAX_TRAIN
    max_val: int = BASELINE_MAX_VAL


class HybridReq(BaseModel):
    scanId: str
    fusion: Literal["OR", "AND"] = "OR"


class MetricsReq(BaseModel):
    scanId: str
    fusion: Literal["OR", "AND"] = "OR"
    scope: Literal["intersection", "require_all"] = "intersection"


class VTSubmitReq(BaseModel):
    scanId: str
    mode: Literal["undetected", "detected"] = "undetected"


class VTRefreshReq(BaseModel):
    scanId: str
    only_status: Literal["queued", "all"] = "queued"
    max_items: int = 25


# -----------------------------
# HELPERS
# -----------------------------
def verify_user(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(401, "Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization must be: Bearer <token>")

    token = authorization.split(" ", 1)[1].strip()
    try:
        decoded = auth.verify_id_token(token, check_revoked=False)
        return decoded["uid"]
    except Exception as e:
        print("TOKEN VERIFY ERROR:", repr(e))
        raise HTTPException(401, f"Invalid token: {str(e)}")


def get_scan_ref(scan_id: str):
    return db.collection("scans").document(scan_id)


def assert_scan_owner(uid: str, scan_id: str):
    ref = get_scan_ref(scan_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Scan not found")
    data = doc.to_dict() or {}
    if data.get("ownerUid") != uid:
        raise HTTPException(403, "Forbidden")
    return ref


def download_bytes(path: str) -> bytes:
    blob = bucket.blob(path)
    if not blob.exists():
        raise HTTPException(404, f"File missing: {path}")
    return blob.download_as_bytes()


def upload_bytes(path: str, data: bytes, content_type: str = "application/octet-stream"):
    bucket.blob(path).upload_from_string(data, content_type=content_type)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_features(img_bytes: bytes) -> Dict[str, float]:
    pil = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    arr = np.array(pil, dtype=np.uint8)

    b_arr = np.frombuffer(img_bytes, dtype=np.uint8)
    counts = np.bincount(b_arr, minlength=256).astype(np.float64)
    total_b = float(len(b_arr)) if len(b_arr) else 1.0

    probs = counts[counts > 0] / total_b
    byte_entropy = float(-np.sum(probs * np.log2(probs))) if probs.size else 0.0

    expected = total_b / 256.0
    byte_chi_square_uniform = float(np.sum(((counts - expected) ** 2) / (expected + 1e-12)))
    byte_zero_ratio = float(counts[0] / total_b)

    r = arr[:, :, 0].astype(np.float64)
    g = arr[:, :, 1].astype(np.float64)
    b = arr[:, :, 2].astype(np.float64)

    r_lsb = (arr[:, :, 0] & 1).astype(np.uint8).reshape(-1)
    g_lsb = (arr[:, :, 1] & 1).astype(np.uint8).reshape(-1)
    b_lsb = (arr[:, :, 2] & 1).astype(np.uint8).reshape(-1)

    def _bit_entropy(bits: np.ndarray) -> float:
        p1 = float(np.mean(bits)) if bits.size else 0.0
        p0 = 1.0 - p1
        e = 0.0
        if p0 > 0:
            e -= p0 * np.log2(p0)
        if p1 > 0:
            e -= p1 * np.log2(p1)
        return float(e)

    lsb_ratio_r = float(np.mean(r_lsb)) if r_lsb.size else 0.0
    lsb_ratio_g = float(np.mean(g_lsb)) if g_lsb.size else 0.0
    lsb_ratio_b = float(np.mean(b_lsb)) if b_lsb.size else 0.0

    lsb_entropy_r = _bit_entropy(r_lsb)
    lsb_entropy_g = _bit_entropy(g_lsb)
    lsb_entropy_b = _bit_entropy(b_lsb)

    combined = np.concatenate([r_lsb, g_lsb, b_lsb]) if (r_lsb.size and g_lsb.size and b_lsb.size) else np.array([], dtype=np.uint8)
    if combined.size > 1:
        lsb_transition_rate = float(np.mean(combined[1:] != combined[:-1]))
    else:
        lsb_transition_rate = 0.0

    return {
        "file_size_bytes": float(len(img_bytes)),
        "width": float(pil.size[0]),
        "height": float(pil.size[1]),

        "byte_entropy": byte_entropy,
        "byte_chi_square_uniform": byte_chi_square_uniform,
        "byte_zero_ratio": byte_zero_ratio,

        "r_mean": float(np.mean(r)),
        "r_var": float(np.var(r)),
        "g_mean": float(np.mean(g)),
        "g_var": float(np.var(g)),
        "b_mean": float(np.mean(b)),
        "b_var": float(np.var(b)),

        "lsb_ratio_r": lsb_ratio_r,
        "lsb_ratio_g": lsb_ratio_g,
        "lsb_ratio_b": lsb_ratio_b,

        "lsb_entropy_r": lsb_entropy_r,
        "lsb_entropy_g": lsb_entropy_g,
        "lsb_entropy_b": lsb_entropy_b,

        "lsb_transition_rate": lsb_transition_rate,
    }


# -----------------------------
# LSB PAYLOAD EXTRACTION (for YARA-on-LSB)
# -----------------------------
def _extract_lsb_payload(img_bytes: bytes, max_payload_bytes: int = MAX_PAYLOAD_BYTES) -> bytes:
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    except Exception as e:
        raise ValueError(f"Cannot open image for LSB extraction: {e}")

    arr = np.array(img, dtype=np.uint8).reshape(-1)
    if arr.size < 32:
        raise ValueError("Image too small for LSB length header")

    lsb = (arr & 1).astype(np.uint8)

    length_bits = lsb[:32]
    length = 0
    for bit in length_bits:
        length = (length << 1) | int(bit)

    if length <= 0:
        raise ValueError("No payload length found (length <= 0)")
    if length > max_payload_bytes:
        raise ValueError(f"Payload length {length} exceeds max {max_payload_bytes}")

    needed_bits = 32 + (length * 8)
    if needed_bits > lsb.size:
        raise ValueError("Not enough LSB capacity for declared payload length")

    payload_bits = lsb[32:needed_bits]
    payload = np.packbits(payload_bits).tobytes()
    if len(payload) != length:
        payload = payload[:length]

    return payload


def _infer_true_label(img_doc: Dict[str, Any]) -> int:
    if "true_label" in img_doc:
        try:
            return int(img_doc["true_label"])
        except Exception:
            pass
    t = (img_doc.get("type") or "").lower()
    return 1 if t == "stego" else 0


def _delete_collection(col_ref, batch_size: int = 250):
    while True:
        docs = list(col_ref.limit(batch_size).stream())
        if not docs:
            break
        batch = db.batch()
        for d in docs:
            batch.delete(d.reference)
        batch.commit()


def _scan_custom_yara_path(scan_id: str) -> Optional[str]:
    scan_doc = db.collection("scans").document(scan_id).get()
    if not scan_doc.exists:
        return None
    data = scan_doc.to_dict() or {}
    return data.get("yaraRulesPath")


def _compile_yara_rules_for_scan(scan_id: str) -> yara.Rules:
    custom = _scan_custom_yara_path(scan_id)
    if custom:
        try:
            b = download_bytes(custom)
            return yara.compile(source=b.decode("utf-8"))
        except Exception as e:
            print(f"Failed to load custom rules {custom}: {e}")

    if not os.path.exists(RULES_PATH):
        dummy_rule = 'rule dummy { condition: false }'
        return yara.compile(source=dummy_rule)

    return yara.compile(filepath=RULES_PATH)


def _get_images(scan_id: str, img_type: Optional[str] = None):
    col = db.collection("scans").document(scan_id).collection("images")
    if img_type:
        return col.where("type", "==", img_type).stream()
    return col.stream()


def _get_yara_map(scan_id: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for d in db.collection("scans").document(scan_id).collection("yara_results").stream():
        out[d.id] = d.to_dict() or {}
    return out


def _get_anom_map(scan_id: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for d in db.collection("scans").document(scan_id).collection("anomaly_results").stream():
        out[d.id] = d.to_dict() or {}
    return out


def _payload_from_req(req: EmbedReq) -> Tuple[bytes, Dict[str, Any]]:
    if req.payload_mode == "random":
        payload = os.urandom(int(req.payload_size))
        meta = {
            "payload_mode": "random",
            "payload_encoding": "bytes",
            "payload_len": int(len(payload)),
            "payload_sha256": sha256(payload),
            "payload_preview_base64": base64.b64encode(payload[:PAYLOAD_PREVIEW_BYTES]).decode("ascii"),
        }
        return payload, meta

    if not req.payload_text or not req.payload_text.strip():
        raise HTTPException(400, "payload_text is required when payload_mode='user'")

    if req.payload_encoding == "base64":
        try:
            payload = base64.b64decode(req.payload_text.strip(), validate=True)
        except Exception:
            raise HTTPException(400, "Invalid base64 payload_text")
        enc = "base64"
    else:
        payload = req.payload_text.encode("utf-8")
        enc = "utf-8"

    if len(payload) < 1:
        raise HTTPException(400, "payload_text is empty")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise HTTPException(400, f"payload too large (max {MAX_PAYLOAD_BYTES} bytes)")

    meta = {
        "payload_mode": "user",
        "payload_encoding": enc,
        "payload_len": int(len(payload)),
        "payload_sha256": sha256(payload),
        "payload_preview_base64": base64.b64encode(payload[:PAYLOAD_PREVIEW_BYTES]).decode("ascii"),
    }
    return payload, meta


# -----------------------------
# OPTIMIZED NUMPY EMBEDDING
# -----------------------------
def _embed_lsb(img: Image.Image, payload: bytes) -> Image.Image:
    img = img.convert("RGB")
    width, height = img.size

    length_bytes = len(payload).to_bytes(4, "big")
    full_payload = length_bytes + payload
    payload_bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    payload_len = len(payload_bits)

    img_arr = np.array(img)
    flat_arr = img_arr.flatten()
    total_pixels = flat_arr.size

    if payload_len > total_pixels:
        raise ValueError(f"Payload too big. Need {payload_len} bits, have {total_pixels} channels.")

    flat_arr[:payload_len] = (flat_arr[:payload_len] & 0xFE) | payload_bits
    reshaped_arr = flat_arr.reshape((height, width, 3))
    return Image.fromarray(reshaped_arr.astype("uint8"), "RGB")


# -----------------------------
# ML MODEL STORAGE (Baseline + Workspace)
# -----------------------------
def _baseline_paths(uid: str) -> Dict[str, str]:
    base = f"users/{uid}/models/baseline"
    return {
        "model": f"{base}/iforest.pkl",
        "scaler": f"{base}/scaler.pkl",
        "meta": f"{base}/meta.json",
    }


def _workspace_paths(uid: str, scan_id: str, train_on: str) -> Dict[str, str]:
    base = f"users/{uid}/models/workspaces/{scan_id}"
    return {
        "model": f"{base}/{train_on}_iforest.pkl",
        "scaler": f"{base}/{train_on}_scaler.pkl",
        "meta": f"{base}/{train_on}_meta.json",
    }


def _upload_joblib(path: str, obj: Any):
    tmp = f"/tmp/{uuid4().hex}.pkl"
    joblib.dump(obj, tmp)
    with open(tmp, "rb") as f:
        upload_bytes(path, f.read(), content_type="application/octet-stream")
    try:
        os.remove(tmp)
    except Exception:
        pass


def _download_joblib(path: str) -> Any:
    b = download_bytes(path)
    tmp = f"/tmp/{uuid4().hex}.pkl"
    with open(tmp, "wb") as f:
        f.write(b)
    obj = joblib.load(tmp)
    try:
        os.remove(tmp)
    except Exception:
        pass
    return obj


def _save_model_bundle(uid: str, model: IsolationForest, scaler: StandardScaler, info: Dict[str, Any], paths: Dict[str, str]):
    _upload_joblib(paths["model"], model)
    _upload_joblib(paths["scaler"], scaler)
    # store meta in firestore + also blob (optional)
    db.collection("users").document(uid).collection("models_meta").document(paths["meta"].replace("/", "_")).set(
        {**info, "storage_model": paths["model"], "storage_scaler": paths["scaler"], "updatedAt": firestore.SERVER_TIMESTAMP},
        merge=True
    )


def _load_model_bundle(uid: str, paths: Dict[str, str]) -> Tuple[IsolationForest, StandardScaler]:
    model = _download_joblib(paths["model"])
    scaler = _download_joblib(paths["scaler"])
    return model, scaler


def _train_iforest_with_calibrated_threshold_from_matrix(
    X: np.ndarray,
    val_quantile: float = DEFAULT_VAL_QUANTILE,
    contamination: float = DEFAULT_CONTAMINATION,
) -> Tuple[IsolationForest, StandardScaler, float]:
    if X.shape[0] < 4:
        raise HTTPException(400, "Need at least 4 samples (train+val).")

    rng = np.random.default_rng(RNG_SEED)
    idx = np.arange(X.shape[0])
    rng.shuffle(idx)

    split = int(X.shape[0] * 0.8)
    train_idx = idx[:split]
    val_idx = idx[split:] if (idx[split:].size > 0) else idx[:1]

    X_train = X[train_idx]
    X_val = X[val_idx]

    scaler = StandardScaler()
    Xs_train = scaler.fit_transform(X_train)

    model = IsolationForest(
        contamination=contamination,
        random_state=RNG_SEED,
        n_estimators=200,
    ).fit(Xs_train)

    raw_val = model.decision_function(scaler.transform(X_val))
    score_val = -raw_val
    threshold = float(np.quantile(score_val, val_quantile))
    return model, scaler, threshold


def _features_vector_from_bytes(img_bytes: bytes) -> List[float]:
    feats = extract_features(img_bytes)
    return [float(feats[k]) for k in FEATURE_ORDER]


def _collect_user_original_feature_matrix(uid: str, max_train: int, max_val: int) -> np.ndarray:
    # Collect originals across ALL scans owned by this uid.
    # We do "best effort" sampling to keep cost bounded.
    scans = db.collection("scans").where("ownerUid", "==", uid).stream()

    vectors: List[List[float]] = []
    limit = max_train + max_val

    for s in scans:
        sid = s.id
        imgs = db.collection("scans").document(sid).collection("images").where("type", "==", "original").stream()
        for d in imgs:
            if len(vectors) >= limit:
                break
            img = d.to_dict() or {}
            sp = img.get("storagePath")
            if not sp:
                continue
            try:
                b = download_bytes(sp)
                vectors.append(_features_vector_from_bytes(b))
            except Exception:
                continue
        if len(vectors) >= limit:
            break

    if len(vectors) < 4:
        raise HTTPException(400, "Not enough original images across your workspaces to train baseline (need >= 4).")

    return np.array(vectors, dtype=float)


# -----------------------------
# METRICS HELPERS
# -----------------------------
def _fusion_or(yara_hit: int, ml_hit: int) -> int:
    return 1 if (yara_hit == 1 or ml_hit == 1) else 0


def _fusion_and(yara_hit: int, ml_hit: int) -> int:
    return 1 if (yara_hit == 1 and ml_hit == 1) else 0


def _apply_fusion(fusion: str, yara_hit: int, ml_hit: int) -> int:
    f = (fusion or "OR").upper()
    return _fusion_and(yara_hit, ml_hit) if f == "AND" else _fusion_or(yara_hit, ml_hit)


def _confusion_counts(y_true: List[int], y_pred: List[int]) -> Dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn}


def _metrics_from_counts(c: Dict[str, int]) -> Dict[str, float]:
    TP, FP, TN, FN = c["TP"], c["FP"], c["TN"], c["FN"]
    total = TP + FP + TN + FN
    acc = (TP + TN) / total if total else 0.0
    prec = TP / (TP + FP) if (TP + FP) else 0.0
    rec = TP / (TP + FN) if (TP + FN) else 0.0
    f1 = (2 * TP) / (2 * TP + FP + FN) if (2 * TP + FP + FN) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0
    fnr = FN / (FN + TP) if (FN + TP) else 0.0
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": float(fpr),
        "fnr": float(fnr),
    }


# -----------------------------
# ENDPOINTS
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/whoami")
def whoami(authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    return {"ok": True, "uid": uid}


@app.post("/embed")
def embed(req: EmbedReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    payload, payload_meta = _payload_from_req(req)

    originals = (
        db.collection("scans").document(req.scanId)
        .collection("images")
        .where("type", "==", "original")
        .stream()
    )

    count = 0
    errors: List[Dict[str, Any]] = []

    for doc_snap in originals:
        try:
            img_doc = doc_snap.to_dict() or {}
            b = download_bytes(img_doc["storagePath"])
            stego_img = _embed_lsb(Image.open(io.BytesIO(b)), payload)

            buf = io.BytesIO()
            stego_img.save(buf, format="PNG")
            out_bytes = buf.getvalue()

            base_name = os.path.splitext(img_doc.get("filename", "image"))[0]
            name = f"{base_name}_stego.png"
            path = f"users/{uid}/scans/{req.scanId}/stego/{doc_snap.id}_{name}"

            upload_bytes(path, out_bytes, content_type="image/png")

            db.collection("scans").document(req.scanId).collection("images").add({
                "ownerUid": uid,
                "type": "stego",
                "true_label": 1,
                "filename": name,
                "storagePath": path,
                "url": None,
                "parentImageId": doc_snap.id,
                "sha256": sha256(out_bytes),
                "createdAt": firestore.SERVER_TIMESTAMP,
                **payload_meta,
            })
            count += 1
        except Exception as e:
            print(f"Error processing {doc_snap.id}: {e}")
            errors.append({"image_id": doc_snap.id, "error": str(e)})

    return {"ok": True, "count": count, "payload": payload_meta, "errors": errors[:20]}


@app.post("/yara/rules/upload")
async def upload_yara_rules(
    scanId: str,
    authorization: Optional[str] = Header(None),
    file: UploadFile = File(...)
):
    uid = verify_user(authorization)
    assert_scan_owner(uid, scanId)

    fn = (file.filename or "").lower()
    if not fn.endswith((".yar", ".yara")):
        raise HTTPException(400, "Upload a .yar or .yara file")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Empty YARA file")

    try:
        yara.compile(source=content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(400, f"Invalid YARA rules: {str(e)}")

    rules_path = f"users/{uid}/scans/{scanId}/yara_rules/{uuid4().hex}_{file.filename}"
    bucket.blob(rules_path).upload_from_string(content, content_type="text/plain")

    db.collection("scans").document(scanId).set({
        "yaraRulesPath": rules_path,
        "yaraRulesUpdatedAt": firestore.SERVER_TIMESTAMP,
    }, merge=True)

    return {"ok": True, "rulesPath": rules_path}


@app.post("/yara")
def yara_scan(req: YaraReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    t0 = time.time()
    rules = _compile_yara_rules_for_scan(req.scanId)
    res_col = db.collection("scans").document(req.scanId).collection("yara_results")

    targets: List[str]
    if req.target_type == "all":
        targets = ["original", "stego"]
    else:
        targets = [req.target_type]

    total = 0
    detected = 0
    per_target = {}

    for target in targets:
        t_total = 0
        t_detected = 0
        imgs = (
            db.collection("scans").document(req.scanId)
            .collection("images")
            .where("type", "==", target)
            .stream()
        )

        for doc_snap in imgs:
            img = doc_snap.to_dict() or {}

            try:
                b = download_bytes(img["storagePath"])
            except HTTPException:
                continue
            except Exception:
                continue

            scan_source = "file_bytes"
            scan_data = b
            extract_error = None

            # Thesis requirement: for stego, scan extracted LSB payload (best effort)
            if target == "stego":
                try:
                    scan_data = _extract_lsb_payload(b)
                    scan_source = "lsb_payload"
                except Exception as ex:
                    extract_error = str(ex)
                    scan_data = b
                    scan_source = "file_bytes_fallback"

            matches = rules.match(data=scan_data)
            hit = 1 if matches else 0

            res_col.document(doc_snap.id).set({
                "file": img.get("filename", ""),
                "yara_detected": hit,
                "matched_rules": "; ".join([m.rule for m in matches]),
                "scanned_as": target,
                "scan_source": scan_source,
                "extract_error": extract_error,
                "createdAt": firestore.SERVER_TIMESTAMP,
            }, merge=True)

            t_total += 1
            t_detected += hit

        per_target[target] = {"total": t_total, "detected": t_detected}
        total += t_total
        detected += t_detected

    elapsed_s = float(time.time() - t0)
    db.collection("scans").document(req.scanId).set({
        "lastRun": {
            "yara": {"elapsed_s": elapsed_s, "target_type": req.target_type, "updatedAt": firestore.SERVER_TIMESTAMP}
        }
    }, merge=True)

    return {"ok": True, "total": total, "detected": detected, "targets": per_target, "elapsed_s": elapsed_s}


# -----------------------------
# BASELINE MODEL ENDPOINTS
# -----------------------------
@app.post("/models/baseline/train")
def baseline_train(req: BaselineTrainReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)

    t0 = time.time()

    X = _collect_user_original_feature_matrix(uid, max_train=max(10, req.max_train), max_val=max(4, req.max_val))

    model, scaler, threshold = _train_iforest_with_calibrated_threshold_from_matrix(
        X,
        val_quantile=DEFAULT_VAL_QUANTILE,
        contamination=DEFAULT_CONTAMINATION,
    )

    paths = _baseline_paths(uid)
    info = {
        "mode": "baseline",
        "trained_on": "all_workspaces_originals",
        "samples": int(X.shape[0]),
        "threshold": float(threshold),
        "feature_order": FEATURE_ORDER,
        "contamination": float(DEFAULT_CONTAMINATION),
        "val_quantile": float(DEFAULT_VAL_QUANTILE),
        "rng_seed": RNG_SEED,
        "ownerUid": uid,
        "elapsed_s": float(time.time() - t0),
        "createdAt": firestore.SERVER_TIMESTAMP,
    }

    _save_model_bundle(uid, model, scaler, info, paths)

    # Also store a friendly doc
    db.collection("users").document(uid).collection("models").document("baseline").set(
        {**info, "storage_model": paths["model"], "storage_scaler": paths["scaler"], "updatedAt": firestore.SERVER_TIMESTAMP},
        merge=True
    )

    return {"ok": True, "threshold": float(threshold), "samples": int(X.shape[0]), "elapsed_s": float(time.time() - t0)}


@app.get("/models/baseline/info")
def baseline_info(authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    d = db.collection("users").document(uid).collection("models").document("baseline").get()
    return {"ok": True, "baseline": (d.to_dict() if d.exists else None)}


@app.delete("/models/baseline")
def baseline_delete(authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)

    paths = _baseline_paths(uid)
    for k in ("model", "scaler"):
        p = paths.get(k)
        if p:
            try:
                blob = bucket.blob(p)
                if blob.exists():
                    blob.delete()
            except Exception:
                pass

    db.collection("users").document(uid).collection("models").document("baseline").delete()
    return {"ok": True}


@app.post("/anomaly")
def anomaly(req: AnomReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    t0 = time.time()

    model_mode = (req.model_mode or "workspace").lower()

    # -----------------------------
    # Choose model
    # -----------------------------
    if model_mode == "baseline":
        # Use persistent baseline (no retraining each time)
        paths = _baseline_paths(uid)
        try:
            model, scaler = _load_model_bundle(uid, paths)
        except Exception as e:
            raise HTTPException(
                400,
                f"Baseline model not found or failed to load. Train it first: POST /models/baseline/train. Details: {e}"
            )

        baseline_doc = db.collection("users").document(uid).collection("models").document("baseline").get()
        baseline_meta = baseline_doc.to_dict() if baseline_doc.exists else {}
        threshold = float(baseline_meta.get("threshold", 0.0))

        if threshold <= 0:
            raise HTTPException(400, "Baseline model has invalid threshold. Retrain baseline.")

        trained_on = "baseline_all_workspaces_originals"

    else:
        # Workspace model: trained from current scan (like before, but we persist into Storage too)
        # Collect train data from scan's train_on type
        docs = [d for d in _get_images(req.scanId, req.train_on)]
        if len(docs) < 4:
            raise HTTPException(400, f"Need at least 4 '{req.train_on}' images (train+val).")

        # Build X from this scan's images
        ids = [d.id for d in docs]
        rng = random.Random(RNG_SEED)
        rng.shuffle(ids)

        X_list: List[List[float]] = []
        for image_id in ids:
            img = db.collection("scans").document(req.scanId).collection("images").document(image_id).get().to_dict() or {}
            sp = img.get("storagePath")
            if not sp:
                continue
            try:
                b = download_bytes(sp)
                X_list.append(_features_vector_from_bytes(b))
            except Exception:
                continue

        if len(X_list) < 4:
            raise HTTPException(400, f"Need at least 4 readable '{req.train_on}' images.")

        X = np.array(X_list, dtype=float)

        model, scaler, threshold = _train_iforest_with_calibrated_threshold_from_matrix(
            X,
            val_quantile=DEFAULT_VAL_QUANTILE,
            contamination=DEFAULT_CONTAMINATION,
        )

        # Persist workspace model so you can reuse it later (no “start from bottom” for that workspace)
        paths = _workspace_paths(uid, req.scanId, req.train_on)
        info = {
            "mode": "workspace",
            "trained_on": req.train_on,
            "scanId": req.scanId,
            "samples": int(X.shape[0]),
            "threshold": float(threshold),
            "feature_order": FEATURE_ORDER,
            "contamination": float(DEFAULT_CONTAMINATION),
            "val_quantile": float(DEFAULT_VAL_QUANTILE),
            "rng_seed": RNG_SEED,
            "ownerUid": uid,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
        _save_model_bundle(uid, model, scaler, info, paths)

        db.collection("scans").document(req.scanId).collection("model_info").document(f"{req.train_on}_iforest").set({
            **info,
            "storage_model": paths["model"],
            "storage_scaler": paths["scaler"],
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }, merge=True)

        trained_on = req.train_on

    # -----------------------------
    # Build test set
    # -----------------------------
    test_ids: List[str] = []

    if req.test_on in ("original", "stego"):
        docs = db.collection("scans").document(req.scanId).collection("images").where("type", "==", req.test_on).stream()
        test_ids = [d.id for d in docs]

    elif req.test_on == "all":
        docs = db.collection("scans").document(req.scanId).collection("images").stream()
        test_ids = [d.id for d in docs]

    elif req.test_on == "yara_detected":
        y = db.collection("scans").document(req.scanId).collection("yara_results").where("yara_detected", "==", 1).stream()
        test_ids = [d.id for d in y]

    elif req.test_on == "yara_missed":
        y = db.collection("scans").document(req.scanId).collection("yara_results").stream()
        test_ids = [d.id for d in y if int((d.to_dict() or {}).get("yara_detected", 0)) == 0]

    if not test_ids:
        raise HTTPException(400, f"No images found for test condition: {req.test_on}")

    a_col = db.collection("scans").document(req.scanId).collection("anomaly_results")

    rows = 0
    detected = 0

    for mid in test_ids:
        doc_snap = db.collection("scans").document(req.scanId).collection("images").document(mid).get()
        if not doc_snap.exists:
            continue
        img = doc_snap.to_dict() or {}

        try:
            b = download_bytes(img["storagePath"])
            vec = np.array([[v for v in _features_vector_from_bytes(b)]], dtype=float)

            raw = model.decision_function(scaler.transform(vec))[0]
            score = -float(raw)
            is_det = 1 if score >= float(threshold) else 0

            a_col.document(mid).set({
                "file": img.get("filename", ""),
                "anomaly_score": score,
                "ml_detected": is_det,
                "threshold": float(threshold),
                "trained_on": trained_on,
                "tested_on": req.test_on,
                "model_mode": model_mode,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)

            rows += 1
            detected += is_det
        except Exception as e:
            print(f"Skipping anomaly test for {mid}: {e}")

    elapsed_s = float(time.time() - t0)
    db.collection("scans").document(req.scanId).set({
        "lastRun": {
            "anomaly": {
                "elapsed_s": elapsed_s,
                "train_on": req.train_on,
                "test_on": req.test_on,
                "model_mode": model_mode,
                "updatedAt": firestore.SERVER_TIMESTAMP,
            }
        }
    }, merge=True)

    return {
        "ok": True,
        "total": rows,
        "detected": int(detected),
        "threshold": float(threshold),
        "trained_on": trained_on,
        "tested_on": req.test_on,
        "model_mode": model_mode,
        "elapsed_s": elapsed_s,
    }


@app.post("/hybrid")
def hybrid(req: HybridReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    t0 = time.time()

    yara_map = _get_yara_map(req.scanId)
    anom_map = _get_anom_map(req.scanId)

    out_col = db.collection("scans").document(req.scanId).collection("hybrid_results")
    fusion = req.fusion.upper()

    yara_ids = set(yara_map.keys())
    ml_ids = set(anom_map.keys())
    fuse_ids = sorted(list(yara_ids.intersection(ml_ids)))

    if not fuse_ids:
        raise HTTPException(400, "No intersection of YARA and ML results. Run YARA and Anomaly on the same target set.")

    total = 0
    detected = 0

    for mid in fuse_ids:
        img_doc = db.collection("scans").document(req.scanId).collection("images").document(mid).get()
        if not img_doc.exists:
            continue
        img = img_doc.to_dict() or {}

        y = yara_map.get(mid) or {}
        a = anom_map.get(mid) or {}

        yara_hit = int(y.get("yara_detected", 0) or 0)
        ml_hit = int(a.get("ml_detected", 0) or 0)

        final_pred = int(_apply_fusion(fusion, yara_hit, ml_hit))
        source = "BOTH" if (yara_hit and ml_hit) else ("YARA" if yara_hit else ("ML" if ml_hit else "NONE"))

        out_col.document(mid).set({
            "file": img.get("filename", ""),
            "fusion": fusion,
            "yara_detected": yara_hit,
            "ml_detected": ml_hit,
            "final_pred": final_pred,
            "decision_source": source,
            "missing_yara": False,
            "missing_ml": False,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }, merge=True)

        total += 1
        detected += 1 if final_pred == 1 else 0

    elapsed_s = float(time.time() - t0)
    db.collection("scans").document(req.scanId).set({
        "lastRun": {"hybrid": {"elapsed_s": elapsed_s, "fusion": fusion, "updatedAt": firestore.SERVER_TIMESTAMP}}
    }, merge=True)

    return {"ok": True, "evaluated": total, "hybrid_detected": detected, "fusion": fusion, "elapsed_s": elapsed_s}


@app.post("/metrics")
def metrics(req: MetricsReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    t0 = time.time()

    yara_map = _get_yara_map(req.scanId)
    anom_map = _get_anom_map(req.scanId)
    hyb_map = {d.id: (d.to_dict() or {}) for d in db.collection("scans").document(req.scanId).collection("hybrid_results").stream()}

    images = [(d.id, (d.to_dict() or {})) for d in _get_images(req.scanId)]
    if not images:
        raise HTTPException(400, "No images found to score.")

    def build_eval_set(method: str) -> Tuple[List[int], List[int], List[str]]:
        y_true: List[int] = []
        y_pred: List[int] = []
        used_ids: List[str] = []

        for mid, img in images:
            true_label = _infer_true_label(img)

            if method == "yara":
                row = yara_map.get(mid)
                if row is None:
                    continue
                pred = int(row.get("yara_detected", 0) or 0)

            elif method == "ml":
                row = anom_map.get(mid)
                if row is None:
                    continue
                pred = int(row.get("ml_detected", 0) or 0)

            elif method == "hybrid":
                row = hyb_map.get(mid)
                if row is None:
                    continue
                if row.get("final_pred", None) is None:
                    continue
                pred = int(row.get("final_pred"))

            else:
                raise ValueError("unknown method")

            y_true.append(true_label)
            y_pred.append(pred)
            used_ids.append(mid)

        return y_true, y_pred, used_ids

    if req.scope == "require_all":
        all_ids = [mid for mid, _ in images]
        missing_yara = [mid for mid in all_ids if mid not in yara_map]
        missing_ml = [mid for mid in all_ids if mid not in anom_map]
        missing_hyb = [mid for mid in all_ids if (mid not in hyb_map) or (hyb_map.get(mid, {}).get("final_pred") is None)]

        if missing_yara or missing_ml or missing_hyb:
            raise HTTPException(
                400,
                {
                    "error": "Missing results. Run scans first.",
                    "missing": {"yara": missing_yara[:50], "ml": missing_ml[:50], "hybrid": missing_hyb[:50]}
                }
            )

    y_true_yara, y_pred_yara, ids_yara = build_eval_set("yara")
    y_true_ml, y_pred_ml, ids_ml = build_eval_set("ml")
    y_true_hyb, y_pred_hyb, ids_hyb = build_eval_set("hybrid")

    def calc(y_true: List[int], y_pred: List[int]) -> Tuple[Dict[str, int], Dict[str, float]]:
        c = _confusion_counts(y_true, y_pred) if y_true else {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        m = _metrics_from_counts(c) if y_true else {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0, "fnr": 0.0}
        return c, m

    c_yara, m_yara = calc(y_true_yara, y_pred_yara)
    c_ml, m_ml = calc(y_true_ml, y_pred_ml)
    c_hyb, m_hyb = calc(y_true_hyb, y_pred_hyb)

    fp = []
    fn = []
    ids_hyb_set = set(ids_hyb)

    for mid, img in images:
        if mid not in ids_hyb_set:
            continue
        true_label = _infer_true_label(img)
        pred = int(hyb_map.get(mid, {}).get("final_pred"))
        if true_label == 0 and pred == 1:
            fp.append(mid)
        elif true_label == 1 and pred == 0:
            fn.append(mid)

    out = {
        "scope": req.scope,
        "evaluated_counts": {
            "yara": len(ids_yara),
            "ml": len(ids_ml),
            "hybrid": len(ids_hyb),
            "total_images": len(images),
        },
        "counts": {"yara": c_yara, "ml": c_ml, "hybrid": c_hyb},
        "metrics": {"yara": m_yara, "ml": m_ml, "hybrid": m_hyb},
        "misclassifications": {"hybrid_false_positives": fp, "hybrid_false_negatives": fn},
        "fusion": req.fusion.upper(),
    }

    db_payload = {**out, "createdAt": firestore.SERVER_TIMESTAMP}
    db.collection("scans").document(req.scanId).collection("metrics").document("latest").set(db_payload, merge=True)

    elapsed_s = float(time.time() - t0)
    db.collection("scans").document(req.scanId).set({
        "lastRun": {"metrics": {"elapsed_s": elapsed_s, "fusion": req.fusion.upper(), "scope": req.scope, "updatedAt": firestore.SERVER_TIMESTAMP}}
    }, merge=True)

    return {"ok": True, **out, "elapsed_s": elapsed_s}


@app.post("/virustotal")
def virustotal_submit(req: VTSubmitReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    if not VT_API_KEY:
        raise HTTPException(500, "VT_API_KEY missing")

    target_val = 0 if req.mode == "undetected" else 1
    anom = (
        db.collection("scans").document(req.scanId)
        .collection("anomaly_results")
        .where("ml_detected", "==", target_val)
        .stream()
    )
    ids = [d.id for d in anom]
    if not ids:
        raise HTTPException(400, "No target images found (based on anomaly_results).")

    vt_col = db.collection("scans").document(req.scanId).collection("virustotal_results")
    submitted = 0

    for mid in ids:
        img_doc = db.collection("scans").document(req.scanId).collection("images").document(mid).get()
        if not img_doc.exists:
            continue
        img = img_doc.to_dict() or {}

        try:
            b = download_bytes(img["storagePath"])
            h = {"x-apikey": VT_API_KEY}
            r1 = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=h,
                files={"file": (img.get("filename", "file.bin"), b)}
            )
            if r1.status_code >= 300:
                vt_col.document(mid).set({
                    "file": img.get("filename", ""),
                    "status": "failed",
                    "error": r1.text,
                    "createdAt": firestore.SERVER_TIMESTAMP
                }, merge=True)
                continue

            aid = r1.json()["data"]["id"]

            vt_col.document(mid).set({
                "file": img.get("filename", ""),
                "status": "queued",
                "analysisId": aid,
                "detections": None,
                "engines": None,
                "results": None,
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)

            submitted += 1

        except Exception as e:
            vt_col.document(mid).set({
                "file": img.get("filename", ""),
                "status": "failed",
                "error": str(e),
                "createdAt": firestore.SERVER_TIMESTAMP
            }, merge=True)

    return {"ok": True, "submitted": submitted, "mode": req.mode}


@app.post("/virustotal/refresh")
def virustotal_refresh(req: VTRefreshReq, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, req.scanId)

    if not VT_API_KEY:
        raise HTTPException(500, "VT_API_KEY missing")

    vt_col = db.collection("scans").document(req.scanId).collection("virustotal_results")

    docs = list(vt_col.stream())
    rows = []
    for d in docs:
        row = d.to_dict() or {}
        if req.only_status == "queued" and row.get("status") != "queued":
            continue
        if not row.get("analysisId"):
            continue
        rows.append((d.id, row))

    rows = rows[: max(1, min(req.max_items, 100))]
    updated = 0

    h = {"x-apikey": VT_API_KEY}
    for mid, row in rows:
        aid = row["analysisId"]
        r2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=h)
        if r2.status_code >= 300:
            continue

        d2 = (r2.json().get("data", {}) or {}).get("attributes", {}) or {}
        status = d2.get("status", "queued")

        results = d2.get("results", {}) or {}
        stats = d2.get("stats", {}) or {}

        if status != "completed":
            vt_col.document(mid).set({"status": status}, merge=True)
            updated += 1
            continue

        simple_res = {k: (v or {}).get("category", "undetected") for k, v in results.items()}
        vt_col.document(mid).set({
            "status": "completed",
            "detections": int(stats.get("malicious", 0) + stats.get("suspicious", 0)),
            "engines": int(sum(stats.values())) if stats else 0,
            "results": simple_res,
            "createdAt": firestore.SERVER_TIMESTAMP
        }, merge=True)
        updated += 1

    return {"ok": True, "checked": len(rows), "updated": updated}


@app.post("/scan/{scan_id}/reset")
def reset_scan(scan_id: str, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    ref = assert_scan_owner(uid, scan_id)

    img_col = ref.collection("images")
    all_imgs = list(img_col.stream())

    for d in all_imgs:
        data = d.to_dict() or {}
        t = (data.get("type") or "").lower()
        if t == "original":
            continue

        sp = data.get("storagePath")
        if sp:
            try:
                blob = bucket.blob(sp)
                if blob.exists():
                    blob.delete()
            except Exception:
                pass

        d.reference.delete()

    for sub in ["yara_results", "anomaly_results", "hybrid_results", "virustotal_results", "metrics", "model_info"]:
        _delete_collection(ref.collection(sub))

    scan_doc = ref.get().to_dict() or {}
    rp = scan_doc.get("yaraRulesPath")
    if rp:
        try:
            blob = bucket.blob(rp)
            if blob.exists():
                blob.delete()
        except Exception:
            pass
        ref.set({"yaraRulesPath": firestore.DELETE_FIELD}, merge=True)

    ref.set({"updatedAt": firestore.SERVER_TIMESTAMP}, merge=True)

    return {
        "ok": True,
        "status": "reset_complete",
        "kept": "original images only",
        "deleted": ["stego images", "yara", "ml", "hybrid", "metrics", "virustotal", "model_info", "custom_yara_rules"]
    }


@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    ref = assert_scan_owner(uid, scan_id)

    for sub in ["images", "yara_results", "anomaly_results", "hybrid_results", "virustotal_results", "metrics", "model_info"]:
        _delete_collection(ref.collection(sub))

    ref.delete()

    try:
        for blob in bucket.list_blobs(prefix=f"users/{uid}/scans/{scan_id}/"):
            blob.delete()
    except Exception:
        pass

    return {"ok": True}


@app.delete("/image/{scan_id}/{image_id}")
def delete_image(scan_id: str, image_id: str, authorization: Optional[str] = Header(None)):
    uid = verify_user(authorization)
    assert_scan_owner(uid, scan_id)

    ref = db.collection("scans").document(scan_id).collection("images").document(image_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Not found")
    data = doc.to_dict() or {}
    if data.get("ownerUid") != uid:
        raise HTTPException(403, "Forbidden")

    if "storagePath" in data:
        try:
            blob = bucket.blob(data["storagePath"])
            if blob.exists():
                blob.delete()
        except Exception:
            pass

    ref.delete()
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
