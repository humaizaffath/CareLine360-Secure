# V6 – User Enumeration and Weak OTP

**Owner:** Inaam · **Branch:** `inaam/v6-v7-oauth` · **Baseline commit:** `150128b` (same as `integration-branch`)
**Captured:** 2026-09-26 · **Stage:** BEFORE evidence (no fix applied)
**Mapping:** CWE-203 (Observable Discrepancy), CWE-204 (Observable Response Discrepancy), CWE-338 (Use of Cryptographically Weak PRNG) · OWASP Top 10 2021 A07 Identification and Authentication Failures

## What this shows

The tests state the secure behaviour. On the current code the three security tests fail, which proves V6 exists. The positive control passes.

| # | Test | Result on `150128b` | Observed |
|---|---|---|---|
| 1 | `POST /api/auth/password/forgot`: known vs unknown account answer identically | **FAIL** | known → `200 "Password reset OTP sent to email"`; unknown → `404 "User not found"` |
| 2 | `POST /api/auth/reactivate` with a wrong password: known vs unknown account answer identically | **FAIL** | known → `401 "Invalid credentials"`; unknown → `404 "User not found"` |
| 3 | `generateOtp()` does not use `Math.random()` | **FAIL** | `Math.random` called once; with it pinned to `0.5` the OTP is always `"550000"` |
| 4 | Positive control: 1,000 OTPs all match `/^\d{6}$/` | **PASS** | – |

Root causes: [`server/services/authService.js`](../../server/services/authService.js) (`sendPasswordResetOtp` returns 404 for unknown users), [`server/controllers/patientController.js`](../../server/controllers/patientController.js) (`reactivateAccount` returns 404 before checking the password), and [`server/utils/otp.js`](../../server/utils/otp.js) (`generateOtp` uses `Math.random()`).

## Files

- `v6-before-150128b.txt`: full terminal output (branch, commit, Jest `--verbose` run)
- Test: [`server/tests/integration/security/v6-enumeration-otp.test.js`](../../server/tests/integration/security/v6-enumeration-otp.test.js)

## Reproduce

```sh
cd server
npm ci
npx jest tests/integration/security/v6-enumeration-otp.test.js --verbose
```

The routes are mounted from the real `routes/authRoutes.js` on an in-memory MongoDB (`mongodb-memory-server`) with synthetic users. `services/emailService` is mocked, so no email is sent and no shared database or external service is used.
