# V3 – Missing Authentication / Sensitive Data Exposure

**Owner:** Umair · **Branch:** `umair/v3-v4-auth-socket` (based on `integration-branch` @ `e5f31a9`)
**Mapping:** CWE-306 (Missing Authentication for Critical Function), CWE-200 (Exposure of Sensitive Information), CWE-639 (Authorization Bypass Through User-Controlled Key) · OWASP Top 10 2021 A01 Broken Access Control, A07 Identification and Authentication Failures

## Vulnerability

`/api/users`, `/api/emergency` and `/api/payments` were mounted in `server/server.js` with no authentication middleware. Anyone could:

- list every user with `refreshTokenHash` (`GET /api/users`, `GET /api/users/:id`);
- read every emergency case with the patient's name, email, phone and GPS location, raise an SOS for any patient, and change dispatch status;
- read, create, verify or fail any payment. Payment responses populated the full patient `User` document, including **`passwordHash` and `refreshTokenHash`**.

## Evidence

All requests were sent **without an `Authorization` header**, using synthetic data in an in-memory MongoDB, with routes mounted exactly as in `server.js`. Personal data, hashes and IDs are redacted in the JSON files.

| Route | Before | After | Secrets in response before fix |
|---|---|---|---|
| GET /api/users | 200 | 401 | refreshTokenHash |
| GET /api/users?role=doctor | 200 | 401 | refreshTokenHash |
| GET /api/users/:id | 200 | 401 | refreshTokenHash |
| GET /api/emergency | 200 | 401 | – (patient PII + location) |
| GET /api/emergency/:id | 200 | 401 | – (patient PII + location) |
| GET /api/emergency/:id/nearest-hospital | 200 | 401 | – |
| POST /api/emergency | 201 | 401 | – (SOS forged for another patient) |
| PATCH /api/emergency/:id/status | 200 | 401 | – (case marked RESOLVED) |
| POST /api/payments | 201 | 401 | passwordHash, refreshTokenHash |
| GET /api/payments/:id | 200 | 401 | passwordHash, refreshTokenHash |
| GET /api/payments/appointment/:appointmentId | 200 | 401 | passwordHash, refreshTokenHash |
| PATCH /api/payments/:id/verify | 200 | 401 | passwordHash, refreshTokenHash |
| PATCH /api/payments/:id/fail | 200 | 401 | passwordHash, refreshTokenHash |
| GET /api/payments/:id/receipt | 200 (PDF) | 401 | – |

- `baseline-no-token.json`: redacted responses before the fix
- `after-fix-no-token.json`: redacted responses after the fix
- `capture-evidence.js`: reproduces both files (`node security-evidence/V3/capture-evidence.js <label>`)

## Fix: access policy

| Endpoint | Allowed |
|---|---|
| `GET /api/users` | admin (all roles, admin field set); any logged-in user only with `?role=doctor` (`_id, role, fullName, email`) |
| `GET /api/users/:id` | admin, or the user themselves |
| `POST /api/emergency` | patient; `patient` is always the caller |
| `GET /api/emergency`, `GET /:id`, `PATCH /:id/status`, `GET /:id/nearest-hospital` | admin, responder |
| `POST /api/payments` | patient, for their own appointment; payer is always the caller |
| other `/api/payments` routes | the payment's patient, the appointment's doctor, or admin |

User responses use explicit field allow-lists. Payment responses populate `patient` with `fullName email phone` only.

## Tests

```
cd server
npx jest tests/integration/security/v3-auth-exposure.test.js --forceExit
npx jest tests/unit/payment tests/integration/payment --forceExit
```

Note: `server.js` registers an upload error handler before `middleware/errorHandler` that answers every error with 500 (part of deferred V5). The payment controller therefore sends its own 4xx errors, such as the 403 from the access check, instead of relying on the global handler. The V3 test app reproduces that error chain.

`tests/integration/security/v3-auth-exposure.test.js` covers unauthenticated requests (401), allowed roles and owners (2xx), disallowed roles and non-owners (403, with no state change), and the absence of `passwordHash`/`refreshTokenHash` in successful responses. Against the pre-fix code, 28 of its 32 tests fail.
