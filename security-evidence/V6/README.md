# V6 – User Enumeration and Weak OTP

**Owner:** Inaam · **Branch:** `inaam/v6-v7-oauth` · **Baseline commit:** `150128b` (same as `integration-branch`)
**BEFORE captured:** 2026-09-26 on `150128b` (committed as `f730ad2`) · **AFTER captured:** 2026-09-26 on `f730ad2` + V6 fix
**Mapping:** CWE-203 (Observable Discrepancy), CWE-204 (Observable Response Discrepancy), CWE-338 (Use of Cryptographically Weak PRNG) · OWASP Top 10 2021 A07 Identification and Authentication Failures

## Vulnerability

- **Enumeration.** Password-recovery, email-verification, reactivation and login endpoints answered differently for existing and non-existing accounts (`404 "User not found"` vs success or `401`). Login also revealed that an account was deactivated before checking the password. Anyone could test whether an email or phone number is registered with CareLine360, a healthcare service.
- **Weak OTP.** `generateOtp()` used `Math.random()`, a non-cryptographic PRNG whose output is predictable. Password-reset and email-verification codes were derived from it.

## BEFORE vs AFTER

| Check | BEFORE (`150128b`) | AFTER (V6 fix) |
|---|---|---|
| `POST /password/forgot` known vs unknown | `200 "Password reset OTP sent to email"` vs **`404 "User not found"`** | both `200 "If the account exists, a password reset code has been sent."` |
| `POST /reactivate` known + wrong password vs unknown | `401 "Invalid credentials"` vs **`404 "User not found"`** | both `401 "Invalid credentials"` |
| `POST /password/reset` unknown account | **`404 "User not found"`** | `400 "OTP not found or expired"` (same as a known account with no pending code) |
| `POST /email/verify-otp` unknown account | **`404 "User not found"`** | `400 "OTP not found or expired"` (same as known) |
| `POST /email/send-verify-otp` unknown / verified / unverified | **`404` / `200 "Email already verified"` / `200 "…sent"`** | all `200 "If the account exists and is not yet verified, a verification code has been sent."` |
| `POST /login` deactivated account + wrong password | **`403 "Account is deactivated"`** | `401 "Invalid credentials"` (same as unknown) |
| `POST /login` deactivated account + correct password | `403` | `403 "Account is deactivated"` (unchanged: the Reactivate button still appears) |
| OTP generator | **`Math.random()`**; pinned to `0.5` it always gives `"550000"` | `crypto.randomInt(0, 1000000)`, zero-padded |
| **Positive:** OTP format | 6 digits | 6 digits, leading zeros kept (`42` → `"000042"`); 1,000/1,000 match `/^\d{6}$/` |
| **Positive:** reset flow (forgot → email OTP → reset → login) | works | works; old password rejected, new password accepted |
| **Positive:** OTP storage | SHA-256 hash, 10 min, `attemptsLeft = 5` | unchanged; 6th wrong attempt still returns `429` |
| **Positive:** unknown account side effects | – | no OTP stored, no email sent |
| Password given as a JSON array (`["<correct password>"]`) | `500` (bcrypt throws) | `401`, account unchanged |
| Email provider rejects while sending an OTP | error propagates, `500` | logged, response still `200`, no unhandled rejection |

Test results: the BEFORE run on the baseline test file had **3 failed, 1 passed**. The final 19-test file on the baseline code has **11 failed, 8 passed**: every security test fails and every positive/behaviour test passes. With the fix, all **19 pass**.

## Fix

| File | Change |
|---|---|
| `server/utils/otp.js` | `generateOtp()` uses `crypto.randomInt` (CSPRNG) and keeps 6 digits with leading zeros |
| `server/utils/password.js` (new) | `verifyPassword(user, password)` compares against a dummy bcrypt hash when the account does not exist, so the response *time* does not reveal it either; it accepts only a string password |
| `server/services/authService.js` | Generic responses for unknown / phone-only / already-verified accounts in `sendEmailVerificationOtp` and `sendPasswordResetOtp`; unknown accounts in `verifyEmailOtp` and `resetPasswordWithOtp` get the same answer as "no pending OTP"; `loginUser` checks the password before revealing `isActive`; OTP emails are sent without being awaited so timing does not depend on whether an email went out |
| `server/controllers/patientController.js` | `reactivateAccount` returns the same `401 "Invalid credentials"` for unknown accounts and wrong passwords |

## Files

- `v6-before-150128b.txt`: BEFORE output (baseline test file on `150128b`)
- `v6-after-fix.txt`: AFTER output (19 tests, all passing)
- `v6-regression.txt`: full backend suite with and without the fix; no new failures
- Test: [`server/tests/integration/security/v6-enumeration-otp.test.js`](../../server/tests/integration/security/v6-enumeration-otp.test.js)

## Reproduce

```sh
cd server
npm ci
npx jest tests/integration/security/v6-enumeration-otp.test.js --verbose
```

The routes are mounted from the real `routes/authRoutes.js` on an in-memory MongoDB (`mongodb-memory-server`) with synthetic users. `services/emailService` is mocked (OTPs are read from the mocked email), so no email is sent and no shared database or external service is used.

## Residual risk (out of this fix)

- `POST /register` still returns `409 "User already exists"` for a taken email or phone. This is kept deliberately for usability and noted as accepted residual risk.
- The OTP hash is unsalted SHA-256 compared with `===`. It is not exploitable online (5 attempts, 10-minute expiry), but a leaked database could be brute-forced offline across the 10⁶ possible values.
