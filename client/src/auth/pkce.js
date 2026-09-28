// Google OpenID Connect sign-in helpers: Authorization Code flow with PKCE (S256).
//
// Pure functions over Web Crypto and a Storage object (sessionStorage in the
// browser), with no React or Vite imports, so they run unchanged under
// `node --test`. The client secret never reaches the browser: the backend
// exchanges the code.

export const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_SCOPE = "openid email profile";

export const STORAGE_KEYS = {
  state: "careline_google_state",
  nonce: "careline_google_nonce",
  verifier: "careline_google_verifier",
};

export const base64UrlEncode = (bytes) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// 32 random bytes → 43 base64url characters
const randomBase64Url = (byteLength = 32) =>
  base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));

export const generateState = () => randomBase64Url();
export const generateNonce = () => randomBase64Url();

// RFC 7636 §4.1: 43–128 characters of [A-Z a-z 0-9 - . _ ~]; base64url is a subset
export const generateCodeVerifier = () => randomBase64Url();

// RFC 7636 §4.2: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
export const createCodeChallenge = async (codeVerifier) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  return base64UrlEncode(new Uint8Array(digest));
};

export const buildGoogleAuthUrl = ({ clientId, redirectUri, state, nonce, codeChallenge }) => {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: GOOGLE_SCOPE,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  return `${GOOGLE_AUTH_ENDPOINT}?${params}`;
};

export const saveTransaction = ({ state, nonce, codeVerifier }, storage) => {
  storage.setItem(STORAGE_KEYS.state, state);
  storage.setItem(STORAGE_KEYS.nonce, nonce);
  storage.setItem(STORAGE_KEYS.verifier, codeVerifier);
};

export const clearTransaction = (storage) => {
  for (const key of Object.values(STORAGE_KEYS)) storage.removeItem(key);
};

// Same result time for every mismatch position
const safeEqual = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

// Single use: the stored transaction is always cleared, and the nonce and
// verifier are returned only when the returned state matches the stored one.
export const consumeTransaction = (returnedState, storage) => {
  const state = storage.getItem(STORAGE_KEYS.state);
  const nonce = storage.getItem(STORAGE_KEYS.nonce);
  const codeVerifier = storage.getItem(STORAGE_KEYS.verifier);
  clearTransaction(storage);

  if (!state || !nonce || !codeVerifier || !safeEqual(returnedState, state)) return null;
  return { nonce, codeVerifier };
};

// Creates and stores a new transaction, returns the Google authorization URL
export const startGoogleSignIn = async ({ clientId, redirectUri, storage }) => {
  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await createCodeChallenge(codeVerifier);

  saveTransaction({ state, nonce, codeVerifier }, storage);
  return buildGoogleAuthUrl({ clientId, redirectUri, state, nonce, codeChallenge });
};

// Checks the query string Google redirected back with. Every outcome clears
// the stored transaction; { ok: true } is the only case where the backend
// may be called.
export const validateGoogleCallback = (search, storage) => {
  const params = new URLSearchParams(search);

  if (params.get("error")) {
    clearTransaction(storage);
    return { ok: false, reason: params.get("error") === "access_denied" ? "access_denied" : "provider_error" };
  }

  const code = params.get("code");
  const returnedState = params.get("state");
  if (!code || !returnedState) {
    clearTransaction(storage);
    return { ok: false, reason: "missing_code" };
  }

  const transaction = consumeTransaction(returnedState, storage);
  if (!transaction) return { ok: false, reason: "invalid_state" };

  return { ok: true, code, nonce: transaction.nonce, codeVerifier: transaction.codeVerifier };
};
