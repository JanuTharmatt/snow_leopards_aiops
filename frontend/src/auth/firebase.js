/**
 * Firebase Client SDK Configuration & Authentication Initialization.
 * Phase 5.5: Multi-Tenant Identity & Auth Provider.
 */

import { initializeApp, getApps, getApp } from "firebase/app";
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence
} from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// Production Firebase Configuration (populated via environment variables)
const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY || process.env.VITE_FIREBASE_API_KEY || "AIzaSyDEMO-KEY-SNOWLEOPARDS-2026",
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN || process.env.VITE_FIREBASE_AUTH_DOMAIN || "snow-leopards-aiops.firebaseapp.com",
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID || process.env.VITE_FIREBASE_PROJECT_ID || "snow-leopards-aiops",
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET || process.env.VITE_FIREBASE_STORAGE_BUCKET || "snow-leopards-aiops.appspot.com",
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID || "1029384756",
  appId: process.env.REACT_APP_FIREBASE_APP_ID || "1:1029384756:web:abcdef123456"
};

// Initialize Firebase App singleton
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();

// Initialize Authentication with local session persistence
const auth = getAuth(app);
setPersistence(auth, browserLocalPersistence).catch((err) => {
  console.warn("Firebase local persistence fallback:", err);
});

// Initialize Cloud Firestore client
const db = getFirestore(app);

export {
  app,
  auth,
  db,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  signOut,
  onAuthStateChanged
};
