import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../context/AuthContext";
import { validateGoogleCallback } from "../auth/pkce";
import "./Auth.css";

const FAILED = "Google sign-in failed. Please try again.";

const CALLBACK_ERRORS = {
  access_denied: "Google sign-in was cancelled.",
  provider_error: FAILED,
  missing_code: FAILED,
  invalid_state: "Invalid sign-in state. Please start Google sign-in again.",
};

// Google redirects here with ?code&state (or ?error). The state is checked and
// the stored PKCE transaction consumed BEFORE the backend is called.
export default function GoogleCallback() {
  const { login } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [error, setError] = useState("");

  // StrictMode runs effects twice in development: process the code only once
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const result = validateGoogleCallback(location.search, window.sessionStorage);

    // Drop code and state from the address bar and history
    nav(location.pathname, { replace: true });

    if (!result.ok) {
      // Result of consuming the external, single-use OAuth transaction; must not run during render
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setError(CALLBACK_ERRORS[result.reason] || FAILED);
      return;
    }

    // Plain client: no Bearer header and no refresh-and-retry on 401
    api
      .post("/auth/oauth/google", {
        code: result.code,
        codeVerifier: result.codeVerifier,
        redirectUri: import.meta.env.VITE_GOOGLE_REDIRECT_URI,
        nonce: result.nonce,
      })
      .then((res) => {
        if (res.data?.user?.role !== "patient") {
          setError(FAILED);
          return;
        }
        login(res.data);
        nav("/patient/dashboard", { replace: true });
      })
      .catch((err) => {
        // Account-state (403) and linking (409) messages are safe to show
        const status = err.response?.status;
        setError(status === 403 || status === 409 ? err.response.data?.message || FAILED : FAILED);
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="auth-page">
      <div className="auth-noise" />
      <div className="auth-form-panel">
        <div className="auth-form-container">
          <span className="auth-overline">Google Sign-In</span>
          <h1 className="auth-title">
            {error ? "Sign-in " : "Signing "}
            <span className="auth-title-accent">{error ? "failed" : "in…"}</span>
          </h1>

          {error ? (
            <>
              <div className="auth-msg auth-msg--error">{error}</div>
              <div className="auth-footer-links auth-footer-links--center">
                <Link to="/login" className="auth-link auth-link--accent">
                  Back to Sign In
                </Link>
              </div>
            </>
          ) : (
            <p className="auth-subtitle">Completing your Google sign-in, please wait.</p>
          )}
        </div>
      </div>
    </div>
  );
}
