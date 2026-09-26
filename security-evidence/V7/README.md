# V7 – Missing Rate Limiting on Account Reactivation

**Owner:** Inaam · **Branch:** `inaam/v6-v7-oauth` · **Commit:** `76a29c4` (baseline `150128b` + V6 fix; V7 code unchanged)
**Captured:** 2026-09-26 · **Stage:** BEFORE evidence (no fix applied)
**Mapping:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) · OWASP Top 10 2021 A07 Identification and Authentication Failures

## Vulnerability

`POST /api/auth/reactivate` takes an identifier and a password, checks the password with bcrypt, and reactivates the account if it matches. It is a second password-checking endpoint next to `/login`, but it is mounted with **no rate limiter** ([`server/routes/authRoutes.js`](../../server/routes/authRoutes.js), `router.post("/reactivate", reactivateAccount)`), while `/login` uses `authLimiter` (30 requests per 10 minutes per IP). An attacker can guess passwords through `/reactivate` without limit. A correct guess also reactivates a deactivated account.

## BEFORE results (`76a29c4`)

| # | Test | Result | Observed |
|---|---|---|---|
| 1 | **Security:** 50 wrong-password `POST /api/auth/reactivate` requests from one IP are eventually answered with `429` | **FAIL** | `401 x50`, **no 429** |
| 2 | **Control:** 31 wrong-password `POST /api/auth/login` requests from one IP | PASS | `401 x30, 429 x1`, so the existing limiter works |
| 3 | **Positive:** login → `PATCH /api/patients/me/deactivate` → login blocked (`403 "Account is deactivated"`) → reactivate with the correct password → login | PASS | `200` → `200` → `403` → `200 "Account reactivated successfully"` → `200` (account `ACTIVE`, patient profile restored) |

The attack sent 50 requests, more than the 30 that `/login` allows in the same window. Every one of them was processed as a normal wrong-password attempt.

## Files

- `v7-before-76a29c4.txt`: branch, commit, command and full Jest `--verbose` output, including the logged status sequences
- Test: [`server/tests/integration/security/v7-reactivate-ratelimit.test.js`](../../server/tests/integration/security/v7-reactivate-ratelimit.test.js)

## Reproduce

```sh
cd server
npm ci
npx jest tests/integration/security/v7-reactivate-ratelimit.test.js --verbose
```

The real `routes/authRoutes.js` and `routes/patientRoutes.js` run on an in-memory MongoDB (`mongodb-memory-server`) with synthetic patients; no external service is used. Each scenario sends from its own client IP (`X-Forwarded-For` with `trust proxy` set to 1). This matters because `authLimiter` keeps a per-IP counter in memory, so the `/login` control cannot affect the `/reactivate` measurement.

## Known related issue (not part of this evidence, not fixed)

`reactivateAccount` sets `status = "ACTIVE"` for any account whose password matches. A `PENDING` or `REJECTED` doctor, or an admin-suspended user, can therefore make their own account active. This is recorded separately and left untouched in this pass.
