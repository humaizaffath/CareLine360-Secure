// Google OIDC + PKCE browser helpers (client/src/auth/pkce.js)
// Run from client/:  node --test tests/pkce.test.mjs
// Uses Node's built-in test runner and Web Crypto; no frontend test dependency.
import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  GOOGLE_AUTH_ENDPOINT,
  STORAGE_KEYS,
  base64UrlEncode,
  generateState,
  generateNonce,
  generateCodeVerifier,
  createCodeChallenge,
  buildGoogleAuthUrl,
  saveTransaction,
  consumeTransaction,
  startGoogleSignIn,
  validateGoogleCallback,
} from "../src/auth/pkce.js";

const CLIENT_ID = "careline-test.apps.googleusercontent.com";
const REDIRECT_URI = "http://localhost:5173/auth/google/callback";
const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

// Minimal Storage (sessionStorage) stand-in
class MemoryStorage {
  #items = new Map();
  getItem(key) { return this.#items.has(key) ? this.#items.get(key) : null; }
  setItem(key, value) { this.#items.set(key, String(value)); }
  removeItem(key) { this.#items.delete(key); }
  get size() { return this.#items.size; }
}

let storage;
beforeEach(() => {
  storage = new MemoryStorage();
});

const storedTransaction = () => Object.values(STORAGE_KEYS).map((key) => storage.getItem(key));
const assertCleared = () => assert.deepEqual(storedTransaction(), [null, null, null]);

// ─── Random values ───────────────────────────────────────────────────────────

describe("random values", () => {
  test("1. code_verifier is 43-128 valid PKCE characters and unique", () => {
    const verifiers = new Set();
    for (let i = 0; i < 200; i++) {
      const v = generateCodeVerifier();
      assert.match(v, PKCE_VERIFIER);
      verifiers.add(v);
    }
    assert.equal(verifiers.size, 200);
  });

  test("2. state is non-empty and random (43 base64url chars = 256 bits)", () => {
    const states = new Set(Array.from({ length: 200 }, generateState));
    assert.equal(states.size, 200);
    for (const s of states) assert.match(s, /^[A-Za-z0-9_-]{43}$/);
  });

  test("3. nonce is non-empty and random (43 base64url chars = 256 bits)", () => {
    const nonces = new Set(Array.from({ length: 200 }, generateNonce));
    assert.equal(nonces.size, 200);
    for (const n of nonces) assert.match(n, /^[A-Za-z0-9_-]{43}$/);
  });

  test("never uses Math.random()", async () => {
    const original = Math.random;
    Math.random = () => {
      throw new Error("Math.random must not be used");
    };
    try {
      generateState();
      generateNonce();
      await startGoogleSignIn({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, storage });
    } finally {
      Math.random = original;
    }
  });
});

// ─── S256 challenge ──────────────────────────────────────────────────────────

describe("S256 code challenge", () => {
  test("4. matches the RFC 7636 Appendix B test vector", async () => {
    const challenge = await createCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert.equal(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  test("base64url encoding has no padding or +/ characters", () => {
    assert.equal(base64UrlEncode(new Uint8Array([251, 255, 191])), "-_-_");
    assert.equal(base64UrlEncode(new Uint8Array([1])), "AQ");
  });
});

// ─── Authorization URL ───────────────────────────────────────────────────────

describe("Google authorization URL", () => {
  test("5. has the required OIDC + PKCE parameters and nothing more", async () => {
    const url = new URL(await startGoogleSignIn({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, storage }));
    const p = url.searchParams;
    const [state, nonce, verifier] = storedTransaction();

    assert.equal(`${url.origin}${url.pathname}`, GOOGLE_AUTH_ENDPOINT);
    assert.equal(p.get("response_type"), "code");
    assert.equal(p.get("client_id"), CLIENT_ID);
    assert.equal(p.get("redirect_uri"), REDIRECT_URI);
    assert.equal(p.get("scope"), "openid email profile");
    assert.equal(p.get("state"), state);
    assert.equal(p.get("nonce"), nonce);
    assert.equal(p.get("code_challenge"), await createCodeChallenge(verifier));
    assert.equal(p.get("code_challenge_method"), "S256");
    assert.deepEqual(
      [...p.keys()].sort(),
      ["client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"]
    );
    // No offline access / Google refresh token requested
    assert.equal(p.get("access_type"), null);
  });

  test("6. contains no client secret and not the verifier itself", async () => {
    const url = await startGoogleSignIn({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, storage });
    const verifier = storage.getItem(STORAGE_KEYS.verifier);

    assert.doesNotMatch(url, /client_secret|GOCSPX-|secret/i);
    assert.equal(url.includes(verifier), false);
  });

  test("buildGoogleAuthUrl encodes values safely", () => {
    const url = new URL(
      buildGoogleAuthUrl({ clientId: CLIENT_ID, redirectUri: `${REDIRECT_URI}?x=1&y=2`, state: "s", nonce: "n", codeChallenge: "c" })
    );
    assert.equal(url.searchParams.get("redirect_uri"), `${REDIRECT_URI}?x=1&y=2`);
  });
});

// ─── Single-use transaction ──────────────────────────────────────────────────

describe("single-use transaction", () => {
  test("the transaction is kept in the given storage under the careline_google_* keys", async () => {
    await startGoogleSignIn({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, storage });

    assert.equal(storage.size, 3);
    for (const key of ["careline_google_state", "careline_google_nonce", "careline_google_verifier"]) {
      assert.ok(storage.getItem(key));
    }
  });

  test("7. a valid state is consumed once and returns the nonce and verifier", () => {
    saveTransaction({ state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1" }, storage);

    assert.deepEqual(consumeTransaction("state-1", storage), { nonce: "nonce-1", codeVerifier: "verifier-1" });
    assertCleared();
  });

  test("8. replay after consume fails", () => {
    saveTransaction({ state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1" }, storage);
    consumeTransaction("state-1", storage);

    assert.equal(consumeTransaction("state-1", storage), null);
  });

  test("9. tampered state is rejected", () => {
    saveTransaction({ state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1" }, storage);

    assert.equal(consumeTransaction("state-2", storage), null);
  });

  test("10. transaction is cleared after a tampered or missing state", () => {
    saveTransaction({ state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1" }, storage);
    consumeTransaction("tampered", storage);
    assertCleared();

    saveTransaction({ state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1" }, storage);
    consumeTransaction(null, storage);
    assertCleared();
  });

  test("no stored transaction (e.g. a callback opened in another tab) is rejected", () => {
    assert.equal(consumeTransaction("state-1", storage), null);
  });
});

// ─── O-4 / O-10 callback validation ──────────────────────────────────────────

describe("O-4 / O-10 callback validation", () => {
  const start = () => startGoogleSignIn({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, storage });

  test("valid callback → ok with code, nonce and verifier; transaction consumed", async () => {
    await start();
    const [state, nonce, verifier] = storedTransaction();

    const result = validateGoogleCallback(`?code=auth-code&state=${encodeURIComponent(state)}`, storage);

    assert.deepEqual(result, { ok: true, code: "auth-code", nonce, codeVerifier: verifier });
    assertCleared();
  });

  test("O-4 tampered state → not ok (no backend call), transaction cleared", async () => {
    await start();

    const result = validateGoogleCallback("?code=auth-code&state=attacker-chosen-state", storage);

    assert.deepEqual(result, { ok: false, reason: "invalid_state" });
    assertCleared();
  });

  test("O-4 replaying the same callback URL → not ok (verifier already gone)", async () => {
    await start();
    const [state] = storedTransaction();
    const search = `?code=auth-code&state=${encodeURIComponent(state)}`;

    assert.equal(validateGoogleCallback(search, storage).ok, true);
    assert.deepEqual(validateGoogleCallback(search, storage), { ok: false, reason: "invalid_state" });
  });

  test("O-10 ?error=access_denied → not ok, transaction cleared", async () => {
    await start();

    assert.deepEqual(validateGoogleCallback("?error=access_denied&state=x", storage), { ok: false, reason: "access_denied" });
    assertCleared();
  });

  test("O-10 other Google error → not ok, transaction cleared", async () => {
    await start();

    assert.deepEqual(validateGoogleCallback("?error=server_error", storage), { ok: false, reason: "provider_error" });
    assertCleared();
  });

  test("O-10 missing code or state → not ok, transaction cleared", async () => {
    await start();
    const [state] = storedTransaction();
    assert.deepEqual(validateGoogleCallback(`?state=${state}`, storage), { ok: false, reason: "missing_code" });
    assertCleared();

    await start();
    assert.deepEqual(validateGoogleCallback("?code=auth-code", storage), { ok: false, reason: "missing_code" });
    assertCleared();
  });
});

// ─── O-4 structural check of the callback page ───────────────────────────────

describe("O-4 GoogleCallback.jsx calls the backend only after validation", () => {
  const source = readFileSync(new URL("../src/pages/GoogleCallback.jsx", import.meta.url), "utf8");

  test("validation and the early return come before the single api.post", () => {
    const validate = source.indexOf("validateGoogleCallback(location.search");
    const earlyReturn = source.indexOf("if (!result.ok)");
    const post = source.search(/api\s*\.post\(/);

    assert.ok(validate > 0 && earlyReturn > validate && post > earlyReturn, "validate → if (!result.ok) return → api.post");
    assert.equal(source.split(".post(").length - 1, 1, "exactly one backend call");
    assert.match(source.slice(earlyReturn, post), /return;/);
  });

  test("uses a useRef guard, the plain API client and useAuth().login", () => {
    assert.match(source, /useRef\(false\)/);
    assert.match(source, /if \(started\.current\) return;/);
    assert.match(source, /import api from "\.\.\/services\/api"/);
    assert.match(source, /login\(res\.data\)/);
  });

  test("the verifier, nonce and code are sent only from the validated result", () => {
    assert.match(source, /code: result\.code/);
    assert.match(source, /codeVerifier: result\.codeVerifier/);
    assert.match(source, /nonce: result\.nonce/);
    assert.doesNotMatch(source, /console\.(log|info|debug)/);
  });
});
