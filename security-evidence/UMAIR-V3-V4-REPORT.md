# SE4030 – Umair's Contribution: V3 and V4

Scope: V3 (Missing Authentication / Sensitive Data Exposure) and V4 (Socket.IO Room Authorization) in CareLine360-Secure. This covers Umair's part of the shared report and video only.

All results below were produced in this repository with synthetic accounts in an in-memory MongoDB. No real credentials, tokens, hashes, personal data or chat content appear in this document or the evidence files. **No OWASP ZAP scan output is included, and none is claimed.**

## Branch and commits

| Item | Reference |
|---|---|
| Working branch | `umair/v3-v4-auth-socket` (pushed to `origin`) |
| Base (pre-fix, includes the team's V2 fix) | `e5f31a9` from `integration-branch` |
| V3 + V4 code fixes, V3/V4 evidence, V3 tests | `0e996c0` (message "baseline evidence"; contains the fixes) |
| V3 payment 403/4xx handling fix + test harness update | `c80414f` |
| V4 Socket.IO authorization tests + V4 README | `d8f51c6` |
| This report, end-to-end check, evidence script `SERVER_DIR` option | `bf18e48` |
| Merge into `integration-branch` | see the integration merge commit on `origin/integration-branch` |

---

## V3 – Missing Authentication and Sensitive Data Exposure

### Vulnerable behaviour

`server/server.js` mounted three routers with no authentication middleware:

- `/api/users` → `server/routes/userRoutes.js`, `server/controllers/userController.js`
- `/api/emergency` → `server/routes/emergencyRoutes.js`, `server/controllers/emergencyController.js`
- `/api/payments` → `server/routes/paymentRoutes.js`, `server/controllers/paymentController.js`, `server/services/paymentService.js`

On top of the missing authentication, the responses exposed secrets:

- **Users:** `userController` excluded only `passwordHash` (`.select("-passwordHash")`), so **`refreshTokenHash`** was returned for every user.
- **Payments:** `paymentService` populated the full patient `User` document (`populate("appointment patient")`), so both **`passwordHash` and `refreshTokenHash`** were returned.

### Proof of concept (no `Authorization` header)

Script: `security-evidence/V3/capture-evidence.js`. Recorded output: `security-evidence/V3/baseline-no-token.json` (redacted).

| Endpoint | Before fix | Secret fields returned |
|---|---|---|
| `GET /api/users` | 200 | refreshTokenHash |
| `GET /api/users?role=doctor` | 200 | refreshTokenHash |
| `GET /api/users/:id` | 200 | refreshTokenHash |
| `GET /api/emergency` | 200 | – (patient name, email, phone, GPS location) |
| `GET /api/emergency/:id` | 200 | – (same) |
| `GET /api/emergency/:id/nearest-hospital` | 200 | – |
| `POST /api/emergency` (SOS for another patient) | 201 | – |
| `PATCH /api/emergency/:id/status` (set RESOLVED) | 200 | – |
| `POST /api/payments` | 201 | passwordHash, refreshTokenHash |
| `GET /api/payments/:id` | 200 | passwordHash, refreshTokenHash |
| `GET /api/payments/appointment/:appointmentId` | 200 | passwordHash, refreshTokenHash |
| `PATCH /api/payments/:id/verify` | 200 | passwordHash, refreshTokenHash |
| `PATCH /api/payments/:id/fail` | 200 | passwordHash, refreshTokenHash |
| `GET /api/payments/:id/receipt` | 200 (PDF) | – |

All 14 requests succeeded without authentication. 8 of them returned secret hash fields.

### Security impact

- **Account data harvesting:** an unauthenticated attacker could list every account's email, phone number, role and account state.
- **Leaked credential material:**
  - `passwordHash` allows offline password-guessing attacks.
  - Neither hash should ever leave the server.
- **Health-related exposure:** emergency cases exposed patient identity, precise GPS location and incident descriptions.
- **Integrity and safety:**
  - Anyone could raise a false SOS in a patient's name.
  - Anyone could mark a live emergency as RESOLVED, disrupting dispatch.
- **Financial integrity:** anyone could create, verify or fail payments and download receipts.

### CWE / OWASP mapping

| Mapping | Justification |
|---|---|
| **CWE-306** Missing Authentication for Critical Function | The emergency dispatch and payment state changes required no identity at all. |
| **CWE-200** Exposure of Sensitive Information to an Unauthorized Actor | Password and refresh-token hashes and patient personal data were returned to anonymous callers. |
| **CWE-639** Authorization Bypass Through User-Controlled Key | Once authentication is added, a payment ID alone must not grant access, so object-level ownership checks were added. |
| **OWASP Top 10 2021 A01** Broken Access Control | Primary category: missing access control on the API. |
| **OWASP Top 10 2021 A07** Identification and Authentication Failures | CWE-306 is listed in this category. |
| OWASP API Security Top 10 2023 **API3** Broken Object Property Level Authorization | Over-exposure of properties (hash fields). |

### Remediation

| File | Change |
|---|---|
| `server/routes/userRoutes.js` | `router.use(authMiddleware)` (line 7) |
| `server/controllers/userController.js` | Explicit field allow-lists replace `-passwordHash` (lines 5–6). Non-admins may only list doctors (line 18), with `_id, role, fullName, email` only. `GET /:id` is allowed for an admin or the user themselves (line 34). The `role` filter is validated. |
| `server/routes/emergencyRoutes.js` | `router.use(authMiddleware)` (line 14). `POST` is for patients only (line 19). List, detail, status and nearest-hospital are for admin and responder (line 17). |
| `server/controllers/emergencyController.js` | The SOS is recorded for `req.user.userId`. A client-supplied `patient` is ignored, and only `description`, `latitude` and `longitude` are accepted (line 9). |
| `server/routes/paymentRoutes.js` | `authMiddleware` plus roles patient, doctor and admin (line 17). `POST` is for patients only (line 19). |
| `server/services/paymentService.js` | `PAYMENT_POPULATE` limits patient fields to `fullName email phone` (line 6). `assertPaymentAccess` allows the payment's patient, the appointment's doctor or an admin, and denies by default (line 23). Payments are created only for the caller's own appointment, with the payer set to the caller (line 55). |
| `server/controllers/paymentController.js` | Passes `req.user` to the service. `handleError` (line 10) returns 4xx errors directly (see limitations). |

The existing payment unit and integration tests were updated to authenticate. Their assertions are unchanged.

### Before/after and test evidence

- **No-token requests:** all 14 endpoints went from 2xx to **401** (`security-evidence/V3/after-fix-no-token.json`).
- **Focused tests:** `server/tests/integration/security/v3-auth-exposure.test.js`
  - **32/32 pass** on the fix; **28 of the 32 fail** against the pre-fix code at `e5f31a9`. The 4 that pass cover legitimate access that already worked.
  - Coverage: no token → 401; allowed role or owner → 2xx; disallowed role or non-owner → 403 with no state change; no `passwordHash`/`refreshTokenHash` in any successful response.
  - The test app reproduces `server.js`'s error-handler chain.
- **Payment tests:** unit and integration, 52 + 18 tests, all pass.
- **End-to-end:** `security-evidence/e2e-v3-v4-check.js` runs the real `server.js` with real `/api/auth/login` tokens. **All 23 V3 checks pass** (`security-evidence/e2e-v3-v4-results.json`). This includes the fields the existing client pages read: the booking doctor list, the payment page, and the emergency monitoring page.
- **Regression:** the full server suite has the same 51 failing tests before and after, compared test by test. Those failures are in other modules; none are new.

### Remaining limitations and team decisions

- **Error-handler bypass:** `server.js` has an upload error handler that turns every error into HTTP 500 before the global `errorHandler` runs. This is part of deferred **V5**.
  - Payment 4xx errors are handled in `paymentController`, so a denied payment request correctly returns 403.
  - Other modules still get 500 for thrown client errors.
- **Patients can verify their own payments:** a patient can still mark their own payment as verified. The payment flow is simulated; this is a business-logic issue and is outside V3.
- **Doctor emails are visible:** any logged-in user can see doctors' emails, because the booking UI uses them as a name fallback.
- **Chat page header (client, not changed):** the client loads the full user list on every page. Non-admins now receive 403, so the chat page header can show a patient their own name. The fix is one line in the client, pending a team decision.
- **Out of scope:** `GET /api/appointments` still populates full user documents, including hashes, for logged-in users. That code belongs to the appointments owner (V1/V2) and has been reported to them.

---

## V4 – Socket.IO Room Authorization

### Vulnerable behaviour

In `server/socket/chatSocket.js`:

- **`join_room`** called `socket.join(appointmentId)` for any authenticated socket. The client-supplied appointment ID alone decided room membership.
- **`typing` and `stop_typing`** relayed `user_typing` into any room ID the client named.
- **Handshake:** only the JWT was verified. A deactivated account with an unexpired token could still connect.

The chat-history REST route and `send_message` already checked that the caller is the appointment's patient or doctor (`chatService.validateChatAccess`). The live-room path did not.

### Proof of concept

Script: `security-evidence/V4/poc-socket.js`. It uses `socket.io-client` against the real handler with three synthetic accounts: patient A, patient B and B's doctor. A emits `join_room` with B's appointment ID. Only event names and flags are recorded; message text is never stored.

| Observation | Before (`poc-before.json`) | After (`poc-after.json`) |
|---|---|---|
| A receives `room_joined` for B's room | yes | no (`join_error: Access denied`) |
| A receives the doctor's live `new_message` | yes | no |
| A receives B's `user_typing` | yes | no |
| B sees a spoofed typing indicator from A | yes | no |
| Socket without a token | rejected | rejected |
| Deactivated account with a still-valid token | **connected** | rejected |

### Security impact

- **Eavesdropping:** any registered user who knew or obtained an appointment ID could read another patient's live doctor consultation in real time. Those messages are confidential health information.
- **Spoofing:** the attacker could inject presence and typing signals into someone else's consultation.
- **Deactivated accounts:** a suspended account kept real-time access until its access token expired.

### CWE / OWASP mapping

| Mapping | Justification |
|---|---|
| **CWE-862** Missing Authorization | `join_room` and the typing events performed no authorization check. |
| **CWE-639** Authorization Bypass Through User-Controlled Key | The user-supplied room ID (appointment ID) determined access. |
| **OWASP Top 10 2021 A01** Broken Access Control | Access to other users' resources through a real-time channel. |

### Remediation

| File | Change |
|---|---|
| `server/socket/chatSocket.js` | **Handshake:** loads the user and rejects missing or deactivated accounts; `role` comes from the database (line 46), as in the HTTP `authMiddleware`. **Room ID:** `roomIdOf` accepts only a valid ObjectId string (line 73). **`join_room`:** runs the existing `validateChatAccess` rule (line 107) **before** `socket.join` (line 115), and emits `join_error` otherwise. **Typing:** `typing` and `stop_typing` are relayed only into rooms this socket actually joined (`joinedRoomOf`, line 181). `send_message` is unchanged. |
| `server/services/chatService.js` | Exports the existing `validateChatAccess` (line 171). The rule is reused, not duplicated. |

The chat architecture and client are unchanged, and no new server dependency was added.

### Before/after and test evidence

- **PoC:** see the table above.
- **Focused tests:** `server/tests/integration/security/v4-socket-authz.test.js`
  - Runs against a real Socket.IO server.
  - **17/17 pass** on the fix; **10 of the 17 fail** against the pre-fix handler. The 7 that pass cover behaviour that was already correct: token rejection, `send_message` denial and normal chat.
  - Coverage:
    - unauthenticated, forged-token and deactivated sockets are rejected;
    - A cannot join B's room, is never added to it, and receives none of its messages or typing events;
    - A's typing is dropped, and an unrelated doctor is denied;
    - malformed room IDs are rejected;
    - participants join, chat and see typing normally; there is no cross-room leakage, and `leave_room` works.
- **End-to-end:** in the real `server.js` with real login tokens, **all 10 socket checks pass**. This includes chat history over REST after live chat.
- **Existing chat test:** `server/tests/integration/doctor/chat.test.js` passes.

### Remaining limitations

- **Checked at join time only:** a socket that is already connected keeps its room if the account is later deactivated or the appointment is reassigned, until it leaves or disconnects.
- **Unchanged handshake behaviour:** the handshake still accepts a token in the query string and returns JWT error text.
- **Typing before joining:** a participant cannot send typing indicators before joining. The current client always joins first.
- **Admins and responders:** they cannot join chat rooms. This matches the existing chat rule.

---

## Demonstration sequence (about 5 minutes)

Preparation (off camera), from the repo root on `umair/v3-v4-auth-socket`:

```
git worktree add ../CareLine360-before e5f31a9
cd ../CareLine360-before/server && npm install && git checkout -- package-lock.json && cd -
cd server && npm install && git checkout -- package-lock.json && cd ..
npm install --prefix security-evidence/V4 --no-package-lock
```

Recording hygiene:
- Do not open or show any `.env` file (`server/.env`, `client/.env`).
- Do not show real accounts or tokens. The scripts use synthetic data only and print no tokens, hashes or message text.

**V3 (about 2.5 minutes)**

1. Show that the pre-fix routers had no authentication: `git show e5f31a9:server/routes/paymentRoutes.js`.
2. **Before:** `SERVER_DIR=../CareLine360-before/server node security-evidence/V3/capture-evidence.js demo-before`. All 14 lines show 200/201, and 8 show `LEAKS: …Hash`.
3. **After:** `node security-evidence/V3/capture-evidence.js demo-after`. All 14 lines show 401.
4. Show the fix: `git diff e5f31a9 -- server/routes server/controllers/userController.js server/services/paymentService.js`.
5. **Role and ownership rules:** `cd server && npx jest tests/integration/security/v3-auth-exposure.test.js --forceExit --verbose`. Expected: 32 passed.

**V4 (about 2.5 minutes)**

1. Show the pre-fix `join_room`: `git show e5f31a9:server/socket/chatSocket.js`, lines 74–85.
2. **Before:** `SERVER_DIR=../CareLine360-before/server node security-evidence/V4/poc-socket.js demo-before`. Expected: `attackerJoinConfirmed: true`, `attackerReceivedPrivateMessage: true`, `deactivatedUserSocket: "CONNECTED"`.
3. **After:** `node security-evidence/V4/poc-socket.js demo-after`. Expected: `join_error` only, both flags `false`, and the deactivated socket rejected.
4. **Tests:** `cd server && npx jest tests/integration/security/v4-socket-authz.test.js --forceExit --verbose`. Expected: 17 passed.
5. **Optional end-to-end:** `node security-evidence/e2e-v3-v4-check.js`. This runs the real `server.js` with real login, and expects `33/33 PASS`.

Clean up afterwards: `git worktree remove ../CareLine360-before`.

Note: the demo writes `v3-demo-*.json` and `poc-demo-*.json` next to the scripts. Delete them afterwards; the committed evidence files are the recorded baseline.
