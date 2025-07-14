import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider} from "firebase/auth"
import { applyMiddleware } from "redux";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyAJ7R-Wl3HQVhdpHZ2EXprasLyawAB5q24",
  authDomain: "rentmycar-e3f36.firebaseapp.com",
  projectId: "rentmycar-e3f36",
  storageBucket: "rentmycar-e3f36.appspot.com",
  messagingSenderId: "596095519966",
  appId: "1:596095519966:web:116f676c8c7d1e24bac64f"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth();
export const provider = new GoogleAuthProvider();
// export default app;

const storage = getStorage(app);
export default {storage, app};