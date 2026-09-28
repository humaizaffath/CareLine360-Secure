# Google Sign-In – OpenID Connect, Authorization Code + PKCE

**Owner:** Inaam · **Branch:** `inaam/v6-v7-oauth`
**Backend commits:** `2e6de87` (session helpers + refresh-token hardening) · `2d06bcb` (google-auth-library) · `44c667a` (OIDC backend)
**Frontend commit:** `aad24c0` (Google sign-in with PKCE) · **Automated evidence captured:** 2026-09-27 on committed HEAD `aad24c0`
**Mapping:** OWASP Top 10 2021 A07 Identification and Authentication Failures; OAuth 2.0 Security BCP (RFC 9700), PKCE (RFC 7636), OpenID Connect Core 1.0

> **Status:** everything below under *Automated evidence* has been run and captured. Everything under *Manual evidence* still needs a real Google OAuth client and has **not** been done yet.

## Design

```
Browser (Login page)                       CareLine360 API                         Google
────────────────────                       ───────────────                         ──────
state, nonce, code_verifier  ← Web Crypto
code_challenge = BASE64URL(SHA-256(verifier))
store state/nonce/verifier in sessionStorage
redirect ─────────────────────────────────────────────────────────────────────────→ /o/oauth2/v2/auth
                                                                                     (code_challenge, S256,
                                                                                      state, nonce, openid email profile)
/auth/google/callback ←──────────────────────────────────────────────────────────── ?code&state
check state, consume + clear transaction
(mismatch / ?error / missing code → stop, no API call)
POST /api/auth/oauth/google ────────────→ redirectUri on allowlist?
{code, codeVerifier, redirectUri, nonce}  exchange code + verifier + secret ──────────→ /token
                                          ←────────────────────────────────────────── id_token
                                          verifyIdToken: signature, iss, aud, exp
                                          email_verified === true, nonce matches
                                          find / link / create PATIENT
                                          same account-state rules as password login
login(res.data) ←──────────────────────── CareLine access + refresh JWT
→ /patient/dashboard
```

- The client secret exists only on the server (`GOOGLE_CLIENT_SECRET`). The browser has only the public client ID.
- Only `sub`, `email` and `name` from the **verified** ID token are used. Role, email and name are never read from the request.
- Only `User.googleSub` is stored. Google's access token, refresh token and ID token are never stored, returned or logged.
- Google sign-in is **patient-only**. Doctor, admin and responder accounts with a matching email are refused without being modified.
- An existing **unverified** local patient with the same email is linked, marked verified, and has its password and sessions invalidated. This is a pre-account-takeover defence.

## Automated evidence

| ID | What is proven | Where | Result |
|---|---|---|---|
| O-1 | New Google user → one ACTIVE, verified **patient**, one Patient profile, CareLine JWT pair that works on `/auth/me`; code exchanged server-side with the PKCE verifier and redirect URI; repeat sign-in reuses the same user | `oauth-backend-tests.txt` | ✅ |
| O-2 | Existing verified local patient → same user ID, no duplicate, `googleSub` linked, password login still works | `oauth-backend-tests.txt` | ✅ |
| O-3 | OAuth-issued refresh token works on `/auth/refresh`, fails after logout | `oauth-backend-tests.txt` | ✅ |
| O-4 | Tampered state, replayed callback, missing state → rejected and transaction cleared; `GoogleCallback.jsx` validates **before** its only `api.post` | `oauth-frontend-pkce-tests.txt` | ✅ (browser Network-tab proof: manual) |
| O-5 | `invalid_grant` / `invalid_request` / `unauthorized_client` from Google, or no ID token → generic 401, nothing created | `oauth-backend-tests.txt` | ✅ (mocked Google; real replay: manual) |
| O-6 | Wrong audience, wrong issuer, expired, foreign signature, `email_verified` false / missing / `"true"`, nonce mismatch / missing, no email → 401, nothing created. **google-auth-library's real `verifyIdToken` runs** against locally signed RS256 tokens; only Google's key download and token endpoint are stubbed | `oauth-backend-tests.txt` | ✅ |
| O-7 | Existing patient deactivated / PENDING / REJECTED / SUSPENDED, and a linked patient later suspended → 403, not linked, not modified, no tokens | `oauth-backend-tests.txt` | ✅ |
| O-8 | Other `googleSub` already linked → 409; unverified account → linked, old password 401, old refresh 401; `role:"admin"` in body ignored; doctor/admin/responder → 403 unchanged; a new login ends the previous refresh session | `oauth-backend-tests.txt` | ✅ |
| O-9 | No client secret in `client/src`, `client/dist` or `client/.env.example`; a canary `GOOGLE_CLIENT_SECRET` in the build environment does not reach the bundle; authorization URL has only public values; backend responses, database and logs contain no secret, code or Google token | `oauth-secret-scan.txt`, `oauth-backend-tests.txt` | ✅ |
| O-10 | Missing/invalid code, verifier, nonce, redirect URI → 400 before Google is called; redirect URI must match exactly (prefix, extra path, query all refused); `?error=access_denied`, other Google errors and missing code → no API call | both test files | ✅ |

Test counts at capture time:

| Suite | Result |
|---|---|
| Backend `oauth-google.test.js` | 50 / 50 |
| All backend security suites (V3, V4, V6, V7, OAuth) | 123 / 123 |
| Frontend `client/tests/pkce.test.mjs` (Node built-in runner) | 24 / 24 (includes the RFC 7636 Appendix B S256 test vector) |
| `client` production build (placeholder public Google settings) | succeeds |

### Refresh-token hardening (found during OAuth work)

Refresh tokens were stored as `bcrypt(token)`. bcrypt reads only the first 72 bytes, and every refresh token of a user shares them (JWT header + `userId`). Any older, unexpired refresh token therefore still matched after a new login, and even after a password reset once the owner logged in again. Commit `2e6de87` stores `bcrypt(SHA-256(token))` and adds a random `jti`. The O-8 "new login ends the previous refresh session" and "unverified account … old refresh 401" tests fail without this change and pass with it.

## Manual evidence still required (real Google client)

These need a Google Cloud OAuth client (type *Web application*) with the redirect URIs below. **None of these are captured yet.**

1. Google Console: client type and **Authorized redirect URIs** (`http://localhost:5173/auth/google/callback` and the deployed URL), with the client secret redacted.
2. Login page → **Continue with Google** → Google consent screen (address bar showing `code_challenge_method=S256`, `state`, `nonce`, `scope=openid email profile`, no secret).
3. Redirect to `/auth/google/callback?code=…&state=…` and the Network tab showing **one** `POST /api/auth/oauth/google` with `{code, codeVerifier, redirectUri, nonce}` and a `200` response with CareLine tokens, and no request from the browser to Google's token endpoint.
4. Patient dashboard reached after Google sign-in; `/api/auth/me` returns `role: patient`.
5. Tampered state: edit `state` in the callback URL → error page, and the Network tab shows **no** `/api/auth/oauth/google` request.
6. Replay: reload the used callback URL → error page, no backend call (transaction already consumed). Where practical, replay the same code against the backend and show Google's `invalid_grant` → `401`.
7. A doctor/admin email or a suspended patient signing in with Google → `403`, not logged in.

## Configuration

| Where | Variable | Notes |
|---|---|---|
| server | `GOOGLE_CLIENT_ID` | public client ID |
| server | `GOOGLE_CLIENT_SECRET` | **secret**: server `.env` only (git-ignored), never in `client/` or any `VITE_` variable |
| server | `GOOGLE_REDIRECT_URIS` | comma-separated exact allowlist |
| client | `VITE_GOOGLE_CLIENT_ID` | same public client ID |
| client | `VITE_GOOGLE_REDIRECT_URI` | must be one of `GOOGLE_REDIRECT_URIS` |

## Files

- `oauth-backend-tests.txt`: all backend security suites, `--verbose`
- `oauth-frontend-pkce-tests.txt`: `node --test tests/pkce.test.mjs`
- `oauth-secret-scan.txt`: O-9 static scan of source and a configured production build
- Backend: `server/services/googleAuthService.js`, `server/routes/authRoutes.js`, `server/controllers/authController.js`, `server/models/User.js`, `server/services/authService.js`
- Frontend: `client/src/auth/pkce.js`, `client/src/components/GoogleSignInButton.jsx`, `client/src/pages/GoogleCallback.jsx`, `client/src/pages/Login.jsx`, `client/src/App.jsx`

## Reproduce

```sh
cd server && npm ci && npx jest tests/integration/security --verbose
cd client && node --test tests/pkce.test.mjs && npm run build
```

## Known limitations

- **Nonce binding.** The backend checks that the ID token's nonce equals the one the browser sends. Binding that nonce to the browser session relies on the single-use `sessionStorage` transaction.
- **Code replay.** Protection relies on Google's single-use codes and the consumed verifier; there is no server-side PKCE state.
- **Email changes.** A linked user's email is not updated when their Google email changes.
- **Suspension (existing behaviour).** As with password login, refresh and the auth middleware do not recheck `status`, so an admin suspension ends a session only at token expiry or logout.
- **Password for Google-only patients.** They can set a local password later through forgot-password (by design).
- **Deployment.** Sessions issued before `2e6de87` must sign in again once after it is deployed.
