import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import {
  setAuth as storageSetAuth,
  clearAuth as storageClearAuth,
  AUTH_CHANGE_EVENT,
} from "../auth/authStorage";

const AuthContext = createContext(null);

// Read the persisted user synchronously so the very first render already
// knows whether someone is logged in (otherwise ProtectedRoute redirects to
// /login on every page refresh / direct URL visit).
const readUserFromStorage = () => {
  const accessToken = localStorage.getItem("accessToken");
  if (!accessToken) return null;

  return {
    id: localStorage.getItem("userId"),
    role: localStorage.getItem("role"),
    fullName: localStorage.getItem("fullName"),
  };
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readUserFromStorage);
  const [loading, setLoading] = useState(false);

  const restoreFromStorage = useCallback(() => {
    setUser(readUserFromStorage());
    setLoading(false);
  }, []);

  useEffect(() => {
    restoreFromStorage();

    const onStorage = (e) => {
      if (e.key === "accessToken") {
        // token added/removed in another tab — rehydrate
        restoreFromStorage();
      }
      if (e.key === "fullName" || e.key === "role" || e.key === "userId") {
        restoreFromStorage();
      }
    };

    // Same-tab changes made via setAuth/clearAuth (e.g. logout buttons)
    window.addEventListener("storage", onStorage);
    window.addEventListener(AUTH_CHANGE_EVENT, restoreFromStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(AUTH_CHANGE_EVENT, restoreFromStorage);
    };
  }, [restoreFromStorage]);

  const login = ({ accessToken, refreshToken, user }) => {
    // persist tokens & basic user info
    storageSetAuth({ accessToken, refreshToken, user });
    setUser({ id: user.id, role: user.role, fullName: user.fullName });
  };

  const logout = () => {
    storageClearAuth();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export default AuthContext;
