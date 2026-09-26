# V7 – Missing Rate Limiting on Account Reactivation

**Owner:** Inaam · **Branch:** `inaam/v6-v7-oauth`
**BEFORE captured:** 2026-09-26 on `76a29c4` (committed as `7b8fe6a`) · **AFTER captured:** 2026-09-26 on `7b8fe6a` + V7 fix
**Mapping:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) · OWASP Top 10 2021 A07 Identification and Authentication Failures

## Vulnerability

`POST /api/auth/reactivate` takes an identifier and a password, checks the password with bcrypt, and reactivates the account if it matches. It is a second password-checking endpoint next to `/login`, but it was mounted with **no rate limiter** (`router.post("/reactivate", reactivateAccount)`), while `/login` uses `authLimiter` (30 requests per 10 minutes per IP). An attacker could guess passwords through `/reactivate` without limit. A correct guess also reactivates a deactivated account.

## BEFORE vs AFTER

| Check | BEFORE (`76a29c4`) | AFTER (V7 fix) |
|---|---|---|
| `/reactivate`, repeated wrong passwords from one IP | 50 attempts → **`401 x50`, no 429** | 10 attempts → `401 401 401 401 401 429 429 429 429 429` |
| `/reactivate` response once limited | – | `429 {"message": "Too many reactivation attempts, try again later"}` with `RateLimit-Policy` / `RateLimit` headers (no legacy `X-RateLimit-*`) |
| `/reactivate` with the **correct** password after the limit | accepted (`200`, account reactivated) | `429`, account stays deactivated |
| V6 behaviour before the limit (known + wrong password vs unknown) | `401 "Invalid credentials"` both | unchanged: `401 "Invalid credentials"` both |
| **Control:** `/login`, 31 wrong passwords from one IP | `401 x30, 429 x1` | unchanged: `401 x30, 429 x1`, `{"message": "Too many attempts, try again later"}` |
| **Positive:** login → deactivate → login → reactivate → login (fresh IP) | `200 → 200 → 403 → 200 → 200` | unchanged: `200 → 200 → 403 → 200 → 200` (account `ACTIVE`, patient profile restored) |

Test results:

| Run | Result |
|---|---|
| BEFORE, baseline test file on `76a29c4` (`v7-before-76a29c4.txt`) | 1 failed, 2 passed |
| Final test file on the baseline route (no limiter) | 2 failed (both security tests), 3 passed |
| AFTER, final test file with the fix (`v7-after-fix.txt`) | **5 passed** |
| V6 test file with the V7 fix | 19 passed |
| Full backend suite (`v7-regression.txt`) | no new failures; V3, V4, V6 and V7 security suites pass |

## Fix

[`server/routes/authRoutes.js`](../../server/routes/authRoutes.js) adds a dedicated `reactivateLimiter`, separate from the shared `authLimiter`, which is unchanged:

```js
const reactivateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many reactivation attempts, try again later" },
});

router.post("/reactivate", reactivateLimiter, reactivateAccount);
```

Each client IP gets 5 reactivation requests per 15 minutes. The 6th and later requests in the window are rejected with `429` before the password is checked.

## Files

- `v7-before-76a29c4.txt`: BEFORE output (baseline test file; 50 wrong-password requests → `401 x50`)
- `v7-after-fix.txt`: AFTER output, including the route diff and the status sequences
- `v7-regression.txt`: full backend suite with and without the fix
- Test: [`server/tests/integration/security/v7-reactivate-ratelimit.test.js`](../../server/tests/integration/security/v7-reactivate-ratelimit.test.js)

## Reproduce

```sh
cd server
npm ci
npx jest tests/integration/security/v7-reactivate-ratelimit.test.js --verbose
```

The real `routes/authRoutes.js` and `routes/patientRoutes.js` run on an in-memory MongoDB (`mongodb-memory-server`) with synthetic patients; no external service is used. Each scenario sends from its own client IP (`X-Forwarded-For` with `trust proxy` set to 1). This matters because the rate-limit counters are kept per IP in memory, so the scenarios cannot affect each other.

## Limitations

- **Per-IP only.** An attacker spread across many IPs gets 5 attempts per IP per 15 minutes. There is no per-account lockout.
- **In-memory store.** Counters reset when the server restarts and are not shared between multiple server instances.
- **Proxy deployments.** `server.js` does not set `trust proxy`. Behind a reverse proxy, every client would appear as the proxy's IP and share one budget. This applies equally to the existing `authLimiter`.
- **Successful requests count too.** A legitimate user who mistypes their password 5 times must wait up to 15 minutes.

## Known related issue (not fixed here)

`reactivateAccount` sets `status = "ACTIVE"` for any account whose password matches. A `PENDING` or `REJECTED` doctor, or an admin-suspended user, can therefore make their own account active. This is recorded separately and left untouched in the V7 fix.
