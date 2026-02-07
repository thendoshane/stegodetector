import firebase_admin
from firebase_admin import credentials, firestore, storage, auth
from .config import FIREBASE_BUCKET

def init_firebase():
    """Initializes Firebase only if not already initialized."""
    if not firebase_admin._apps:
        try:
            # On Cloud Run, this uses the Default Service Account automatically.
            # Locally, it looks for GOOGLE_APPLICATION_CREDENTIALS.
            firebase_admin.initialize_app(options={
                'storageBucket': FIREBASE_BUCKET
            })
            print("Firebase initialized successfully.")
        except Exception as e:
            print(f"Warning: Firebase init failed: {e}")

# Initialize immediately
init_firebase()
db = firestore.client()
bucket = storage.bucket()

def verify_token(token: str):
    """Verifies a Firebase ID Token."""
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        decoded = auth.verify_id_token(token)
        return decoded["uid"]
    except Exception as e:
        return None