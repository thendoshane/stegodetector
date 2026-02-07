import os

# Google Cloud Run provides 'PORT', default to 8080 for local
PORT = int(os.environ.get("PORT", 8080))

# Rules path: look in current directory or /app/
RULES_PATH = os.environ.get("RULES_PATH", "stego_rules.yar")

# Firebase Bucket Name (Required for Cloud Storage)
FIREBASE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET", "stego-detector-531f5.firebasestorage.app")

# VirusTotal API Key
VT_API_KEY = os.environ.get("VT_API_KEY", "")