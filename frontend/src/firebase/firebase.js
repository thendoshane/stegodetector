import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyA6FImGKhxx0Kv5W0EfkEk9sXW9QvvxPO4",
  authDomain: "stegodetector.firebaseapp.com",
  projectId: "stegodetector",
  storageBucket: "stegodetector.firebasestorage.app",
  messagingSenderId: "755152818329",
  appId: "1:755152818329:web:b7f0085f9f7ce1fd116808",
  measurementId: "G-FWGRHL0ZSD"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);