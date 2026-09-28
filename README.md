# CareLine360 – Secure Software Development

SE4030 Secure Software Development – Assignment 1, **Group 60** (Sri Lanka Institute of Information Technology).

We took the existing CareLine360 MERN healthcare application, found security vulnerabilities in it, fixed them, and added Google sign-in using OAuth 2.0 / OpenID Connect.

| Item | Link |
|---|---|
| Original repository | https://github.com/clerin-codes/CareLine360-WebApp-MERN |
| Secured repository | https://github.com/humaizaffath/CareLine360-Secure |
| Integration branch | `integration-branch` (all team security work; merged into `main` for submission) |
| YouTube demonstration | https://youtu.be/RUGYF3S98M |

---

## 1. Project Overview

CareLine360 is a web platform for remote medical consultation and emergency assistance. It serves four roles:

- **Patients** book in-person, video or phone appointments, chat with their doctor in real time, upload medical documents, pay for consultations and raise SOS emergency cases with GPS location.
- **Doctors** manage availability, appointments, prescriptions and medical records, and chat with patients.
- **Responders** handle emergency cases and find the nearest hospital.
- **Administrators** manage users, doctors, hospitals and meeting links.

The application uses a React client, a Node.js/Express server and MongoDB. Users are identified with JWT authentication, and Socket.IO provides real-time chat. Because the application handles health data, identity data, location data and payments, access control and authentication are its most important security properties.

## 2. Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React 19, Vite 7, React Router 7, Tailwind CSS 4, Axios, Socket.IO client |
| Backend | Node.js, Express 5, Socket.IO 4, express-validator, express-rate-limit, Helmet, CORS |
| Database | MongoDB with Mongoose 9 |
| Authentication | JWT access and refresh tokens, bcryptjs, Google OpenID Connect (`google-auth-library`) with PKCE |
| Files and messaging | Cloudinary (file storage), Multer, PDFKit (receipts and prescriptions), Resend / Nodemailer (email), SMSLenz (SMS) |
| Testing | Jest, Supertest, mongodb-memory-server, Node.js built-in test runner (frontend PKCE tests) |

## 3. Group Members

| Member | Index Number | Security area | Contribution |
|---|---|---|---|
| Affath | IT23330146 | Appointment security | V1 – IDOR / Broken Object Level Authorization; V2 – Mass Assignment |
| Umair | IT23274716 | API and real-time access security | V3 – Missing Authentication and Sensitive Data Exposure; V4 – Socket.IO Room Authorization |
| Inaam | IT23231146 | Authentication and OAuth/OIDC security | V6 – User Enumeration and Weak OTP; V7 – Missing Rate Limiting on Account Reactivation; Google OAuth 2.0 / OpenID Connect sign-in |
| Bishru | IT22115102 | File upload and dependency security | V8 – Insecure File Upload; V10 – Vulnerable Dependencies |

Contributions are taken from the group's vulnerability document, the commit history of `integration-branch`, and the evidence in [`security-evidence/`](security-evidence/).

## 4. Original Repository

https://github.com/clerin-codes/CareLine360-WebApp-MERN

This is the unmodified CareLine360 application that this project started from. The last original commit included here is `e5a15e4` (12 Apr 2026).

## 5. Secured Repository

https://github.com/humaizaffath/CareLine360-Secure

- Each member worked on their own branch.
- All security work was merged into `integration-branch`, and from there into `main` for submission.
- Each security change can be traced to its commits and tests. Detailed evidence is in `security-evidence/`.

## 6. Security Vulnerabilities Addressed

The IDs follow the group's vulnerability plan. Only fixes that are implemented in this repository are listed. V5, V9 and V11 were identified but not fixed; see [Known Limitations](#11-known-limitations).

**Summary**

| ID | Vulnerability | OWASP Top 10 (2021) | CWE | Member |
|---|---|---|---|---|
| V1 | IDOR / Broken Object Level Authorization (appointments) | A01 Broken Access Control | CWE-639 | Affath |
| V2 | Mass Assignment (appointment create/update) | A08 Software and Data Integrity Failures | CWE-915 | Affath |
| V3 | Missing Authentication and Sensitive Data Exposure | A01 Broken Access Control; A07 Identification and Authentication Failures | CWE-306, CWE-200, CWE-639 | Umair |
| V4 | Socket.IO Room Authorization | A01 Broken Access Control | CWE-862, CWE-639 | Umair |
| V6 | User / Account Enumeration and Weak OTP | A07 Identification and Authentication Failures | CWE-203, CWE-204, CWE-338 | Inaam |
| V7 | Missing Rate Limiting on Account Reactivation | A07 Identification and Authentication Failures | CWE-307 | Inaam |
| V8 | Insecure File Upload | A04 Insecure Design | CWE-434 | Bishru |
| V10 | Vulnerable Dependencies | A06 Vulnerable and Outdated Components | CWE-1395 | Bishru |

### V1 – IDOR / Broken Object Level Authorization (Affath)

**OWASP A01:2021 · CWE-639**

- **Original issue:** the appointment service loaded appointments by ID without checking whether the logged-in user was allowed to access them. The same gap affected updating, cancelling, deleting, rescheduling and status changes. The appointment list trusted `patient` and `doctor` identifiers supplied by the client.
- **Why it was a security issue:** any logged-in user who knew an appointment ID could read, modify, cancel, delete or reschedule another patient's appointment. A client could also list other users' appointments by changing the list filters. Restrictions in the user interface gave no server-side protection.
- **Fix:**
  - The controller passes the authenticated user from the verified JWT (`req.user`) to the service.
  - The service checks that this user is a participant in the appointment before any operation.
  - Patients can only use their own appointments. Doctors can only use appointments assigned to them, and only the assigned doctor can change the status.
  - Lists are scoped by the caller's identity: patients see their own, doctors see their assigned ones, admins see all, and other roles are refused (`403`).
  - Unauthorized access returns the same `404` as a missing appointment, so appointment IDs cannot be probed.
- **Files:** `server/services/appointmentService.js`, `server/controllers/appointmentController.js`, and their unit tests.

### V2 – Mass Assignment (Affath)

**OWASP A08:2021 · CWE-915**

- **Original issue:** appointment creation and update passed the complete request body to the database.
- **Why it was a security issue:** a patient could include server-controlled properties such as `status`, `patient`, `meetingUrl`, `reminderSent`, `cancellationReason` or `rescheduleHistory`. For example, they could create an appointment that was already confirmed. Any new server-side field would also have become client-controlled.
- **Fix:**
  - Explicit allow-lists: `CREATE_FIELDS` and `UPDATE_FIELDS`.
  - A `pickFields()` helper copies only permitted properties before data reaches the database.
  - The patient identity always comes from the authenticated user, never from the request body.
  - `doctor` can be chosen when booking, but it isn't in `UPDATE_FIELDS`, so an existing appointment can't be reassigned to another doctor.
- **Files:** `server/services/appointmentService.js`, `server/controllers/appointmentController.js`, and their unit tests.

### V3 – Missing Authentication and Sensitive Data Exposure (Umair)

**OWASP A01:2021, A07:2021 · CWE-306, CWE-200, CWE-639**

- **Original issue:** `/api/users`, `/api/emergency` and `/api/payments` were mounted without authentication. The users API returned `refreshTokenHash`. Payment responses populated the full patient document, including `passwordHash` and `refreshTokenHash`.
- **Why it was a security issue:** without logging in, anyone could:
  - read users and emergency cases, including patient contact details and location;
  - create emergency cases for other patients and change their dispatch status;
  - read, create, verify or fail payments.

  Some responses also disclosed credential-derived hashes.
- **Fix:**
  - **Authentication and role rules on all three routers.** Admins can list users. Other users see only the limited doctor directory or their own record.
  - **Emergency cases.** Patients can raise an SOS only for themselves. Admins and responders handle case access and status.
  - **Payments.** A patient can pay only for their own appointment. Payment access is limited to its patient, the appointment's doctor or an admin.
  - **Safe response fields.** Responses use explicit field lists; populated patient data contains only `fullName`, `email` and `phone`.
  - **Server-set identity.** The patient and payer are taken from the authenticated caller.
- **Evidence:** [`security-evidence/V3`](security-evidence/V3/README.md) and [`UMAIR-V3-V4-REPORT.md`](security-evidence/UMAIR-V3-V4-REPORT.md).

### V4 – Socket.IO Room Authorization (Umair)

**OWASP A01:2021 · CWE-862, CWE-639**

- **Original issue:**
  - `join_room` joined whatever appointment room ID the client sent, without checking that the user was that appointment's patient or doctor.
  - `typing` and `stop_typing` were relayed to any room the client named.
  - A valid token for a deactivated account was accepted at the socket handshake.
- **Why it was a security issue:** any logged-in non-participant who knew an appointment ID could join a private consultation. They could receive live messages and typing indicators, and inject fake typing indicators. A deactivated user could still connect while their JWT remained valid.
- **Fix:**
  - **Room ID and access check.** `join_room` validates the appointment ID and runs the existing chat access check before `socket.join`.
  - **Typing events.** They are sent only to rooms the socket has joined.
  - **Handshake.** It loads the account, rejects missing or deactivated users, and reads the role from the database.
- **Evidence:** [`security-evidence/V4`](security-evidence/V4/README.md).

### V6 – User / Account Enumeration and Weak OTP (Inaam)

**OWASP A07:2021 · CWE-203, CWE-204, CWE-338**

- **Original issue:** the authentication and verification endpoints answered differently for existing and non-existing accounts: forgot-password, email verification, reactivation and login. OTPs were generated with `Math.random()`.
- **Why it was a security issue:** an attacker could find out whether an email or phone number is registered with a healthcare service. Predictable OTPs weakened email verification and password reset.
- **Fix:**
  - Sensitive authentication responses were made identical for existing and unknown accounts.
  - The password is checked before any account state (such as "deactivated") is revealed.
  - Six-digit OTPs are generated with `crypto.randomInt()`.
- **Evidence:** [`security-evidence/V6`](security-evidence/V6/README.md).

### V7 – Missing Rate Limiting on Account Reactivation (Inaam)

**OWASP A07:2021 · CWE-307**

- **Original issue:** `POST /api/auth/reactivate` checks a password but had no dedicated rate limiter.
- **Why it was a security issue:** repeated reactivation requests could be used for unlimited password guessing.
- **Fix:**
  - A dedicated reactivation limiter allows five attempts per IP address in fifteen minutes.
  - Later attempts are rejected with HTTP `429` before the password is checked.
- **Evidence:** [`security-evidence/V7`](security-evidence/V7/README.md).

### V8 – Insecure File Upload (Bishru)

**OWASP A04:2021 · CWE-434**

- **Original issue:** files are uploaded in three places:
  - patient medical documents: `POST /api/documents`;
  - patient avatar: `PATCH /api/patients/me/avatar`;
  - doctor avatar, sent as base64: `PUT /api/doctor/profile/avatar`.

  Each one decided whether a file was allowed using only client-supplied information: the request's `Content-Type`, or the `data:` prefix of the base64 string. Files were streamed straight to Cloudinary, so the server never examined their actual content.
- **Why it was a security issue:**
  - A logged-in user could upload an HTML page, plain text or another file labelled as a PDF or image.
  - That file would be stored under trusted Cloudinary URLs and listed as a medical document that doctors open, allowing phishing content to be delivered from the application's own storage.
  - Stored medical records could no longer be trusted.
- **Fix:**
  - Uploads are held in memory and validated on the server before anything is sent to Cloudinary.
  - The file type is detected from the file's magic bytes. A file is accepted only if the detected type is on the endpoint's allow-list, matches the declared MIME type, and matches the file extension. Otherwise the request is rejected with `400`.
  - Base64 doctor avatars are decoded and checked the same way.
  - Existing allow-lists, size limits, Cloudinary folders and transformations are preserved.
- **Evidence:** [`security-evidence/V8`](security-evidence/V8/README.md).

### V10 – Vulnerable Dependencies (Bishru)

**OWASP A06:2021 · CWE-1395**

- **Original issue:** `npm audit` on the server reported 28 known vulnerabilities (17 high, 9 moderate, 2 low). They were in direct dependencies (`nodemailer`, `cloudinary`, `multer-storage-cloudinary`, `multer`, `express-rate-limit`, `mongoose`) and in transitive dependencies of Express and Socket.IO.
- **Why it was a security issue:** attackers could exploit publicly documented issues without finding a flaw in CareLine360's own code:
  - resource exhaustion that makes the API or chat unavailable;
  - email header or SMTP command injection;
  - bypassing the login rate limit using IPv4-mapped IPv6 addresses.
- **Fix:**
  - Compatible updates with `npm audit fix` (not `--force`).
  - Reviewed upgrades: `nodemailer` to 9.1.1 and `cloudinary` to 2.x.
  - Removed the unused `multer-storage-cloudinary`.
  - Kept `mongoose` on a patched 9.7.x release for test-setup compatibility.
  - `npm audit` now reports 0 vulnerabilities, and the existing test results are unchanged.
- **Evidence:** [`security-evidence/V10`](security-evidence/V10/README.md).

**Additional fix found during the OAuth work (Inaam).** Refresh tokens were stored as `bcrypt(token)`, but bcrypt only reads the first 72 bytes, which are shared by all of a user's refresh tokens. An older token therefore still matched after a new login. Tokens are now stored as `bcrypt(SHA-256(token))` with a random `jti`, so a new login or password reset ends the previous session. See [`security-evidence/OAUTH`](security-evidence/OAUTH/README.md).

## 7. OAuth / OpenID Connect Feature

Patients can sign in with **Google** using **OpenID Connect** with the **Authorization Code flow and PKCE (S256)**. This was implemented by Inaam. Full details are in [`security-evidence/OAUTH/README.md`](security-evidence/OAUTH/README.md).

**Flow**

1. On the login page, the browser uses the Web Crypto API to generate a random `state`, a `nonce` and a PKCE `code_verifier`. These are stored in `sessionStorage` for this one sign-in attempt. The browser then redirects to Google with the `code_challenge` (SHA-256 of the verifier), `state`, `nonce` and scope `openid email profile`.
2. Google redirects back to `/auth/google/callback`.
   - The page checks that `state` matches, then uses and clears the stored transaction so it can't be reused.
   - A mismatched `state`, an error from Google or a missing code stops the flow before any API call.
3. The browser sends `{code, codeVerifier, redirectUri, nonce}` to `POST /api/auth/oauth/google`.
4. The backend:
   - checks the redirect URI against an exact allowlist;
   - exchanges the code with Google using the verifier and the **server-only client secret**;
   - verifies the ID token (signature, issuer, audience, expiry, `email_verified === true`, nonce).
5. The backend finds, links or creates a **patient** account and issues the normal CareLine360 JWT access and refresh tokens.

**Components**

| Side | Files |
|---|---|
| Backend | `server/services/googleAuthService.js`, `server/routes/authRoutes.js` (`POST /api/auth/oauth/google`), `server/controllers/authController.js`, `server/models/User.js` (`googleSub`), `server/services/authService.js` |
| Frontend | `client/src/auth/pkce.js`, `client/src/components/GoogleSignInButton.jsx`, `client/src/pages/GoogleCallback.jsx`, `client/src/pages/Login.jsx`, `client/src/App.jsx` |

**Security properties**

- The client secret exists only on the server. The browser has only the public client ID.
- PKCE, `state` and `nonce` protect against code interception, login CSRF and token replay.
- Identity comes only from the **verified** ID token (`sub`, `email`, `name`). Role and email are never taken from the request body.
- Google sign-in is **patient-only**. Doctor, admin and responder accounts with a matching email are refused and left unchanged.
- **Pre-account-takeover defence:** an existing unverified local account with the same email is linked, and its password and sessions are invalidated.
- Deactivated, pending, rejected or suspended accounts are refused with `403`, the same as password login.
- Google's access, refresh and ID tokens are never stored, returned or logged; only `googleSub` is stored.

**Standards:** RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security Best Current Practice), OpenID Connect Core 1.0.

## 8. Testing and Verification

The following methods were actually used. No OWASP ZAP or other external scanner results are claimed.

- **Automated security regression tests** (Jest, Supertest, in-memory MongoDB, synthetic users):
  - Each test sends the attack and expects it to be blocked, and also checks that legitimate use still works.
  - The evidence READMEs record that these tests fail on the pre-fix code and pass on the fix.
- **Proof-of-concept scripts** that run the same requests before and after each fix, with the outputs saved as evidence. No real credentials, tokens or personal data are recorded.
  - V3: `security-evidence/V3/capture-evidence.js`
  - V4: `security-evidence/V4/poc-socket.js`
  - V8: `security-evidence/V8/capture-evidence.js`
- **End-to-end checks** against the real `server.js` with real login tokens:
  - `security-evidence/e2e-v3-v4-check.js`
  - `security-evidence/V10/smoke-test.js`, which runs against local Cloudinary and SMTP stand-ins.
- **Dependency audit**: `npm audit` before and after V10.
- **Secret scan** of the frontend source and production build, to confirm the Google client secret never reaches the browser.
- **Regression comparison**: the full backend suite was run before and after each fix to confirm no new failures.

**Results** (run on 28 Sep 2026 against `integration-branch` at `d54a0f6`)

| Area | Command (from `server/` unless noted) | Result |
|---|---|---|
| V3, V4, V6, V7 and OAuth security suites | `npx jest tests/integration/security` | 123 / 123 passed (V3 32, V4 17, V6 19, V7 5, OAuth 50) |
| V8 upload security | `npx jest tests/unit/upload tests/integration/upload` | 23 / 23 passed |
| V1 and V2 appointment tests | `npx jest tests/unit/appointment/appointmentService.test.js tests/unit/appointment/appointmentController.test.js` | 82 / 82 passed (23 of them V1-specific). Both V2 mass-assignment tests pass. |
| V10 dependency audit | `npm audit` | found 0 vulnerabilities |
| OAuth PKCE (frontend) | `cd client && node --test tests/pkce.test.mjs` | 24 / 24 passed (includes the RFC 7636 test vector) |
| Full backend suite | `npm test` | 446 / 495 passed; all 49 failures predate the security work (see [Known Limitations](#11-known-limitations)) |

**V1 tests cover:**

- the owner and the assigned doctor can still access the appointment;
- another patient gets `404` on read, update, delete, cancel and reschedule, with no change saved;
- an unassigned doctor can't read, delete or change status;
- a spoofed list filter is overwritten;
- other roles get `403`.

**V2 tests cover:** server-controlled fields (`status`, `patient`, `meetingUrl`, `reminderSent`) are ignored on create, and `doctor`, `patient` and `status` can't be changed through an update.

## 9. Installation and Setup

**Prerequisites:**

- Node.js 20 or later (recommended)
- MongoDB (local or Atlas)
- Accounts for Cloudinary and Resend
- A Google Cloud OAuth client, for Google sign-in

```bash
git clone https://github.com/humaizaffath/CareLine360-Secure.git
cd CareLine360-Secure
```

### Backend

```bash
cd server
npm install
cp .env.example .env     # then fill in the values (see section 10)
npm run dev              # development (nodemon), http://localhost:1111
# or
npm start                # production
```

### Frontend

```bash
cd client
npm install
cp .env.example .env     # then fill in the values (see section 10)
npm run dev              # http://localhost:5173
npm run build            # production build
```

### Running the tests

```bash
cd server
npm test                                   # full backend suite
npx jest tests/integration/security        # V3, V4, V6, V7, OAuth
npx jest tests/unit/upload tests/integration/upload   # V8
npm run test:appointment                   # appointment module (V1, V2)
npm audit                                  # V10

cd ../client
node --test tests/pkce.test.mjs            # OAuth PKCE helpers
```

The tests use an in-memory MongoDB, and email, Cloudinary and Google are mocked. They need no `.env` values and contact no external service.

## 10. Environment Variables

Never commit `.env` files. Both are git-ignored, and each folder has a `.env.example` to copy. Only variable names are listed here.

**Server (`server/.env`)**

| Variable | Purpose |
|---|---|
| `PORT` | API port (default `1111`) |
| `MONGO_URI` | MongoDB connection string |
| `NODE_ENV` | `development` or `production` |
| `CLIENT_URL` | Frontend origin (CORS) |
| `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` | JWT signing secrets (long, random, different from each other) |
| `ACCESS_TOKEN_EXPIRES_IN`, `REFRESH_TOKEN_EXPIRES_IN` | Optional token lifetimes |
| `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` | File storage |
| `RESEND_API_KEY`, `EMAIL_FROM` | Email delivery |
| `EMAIL_OVERRIDE_TO` | Development only: send all email to one address |
| `GEMINI_API_KEY` | AI assistant |
| `SMSLENZ_USER_ID`, `SMSLENZ_API_KEY`, `SMSLENZ_SENDER_ID` | SMS notifications |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (public) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret. **Server only**: never put it in `client/` or in any `VITE_` variable. |
| `GOOGLE_REDIRECT_URIS` | Comma-separated exact allowlist of redirect URIs, e.g. `http://localhost:5173/auth/google/callback` |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Used by the admin seed script |

**Client (`client/.env`)**

| Variable | Purpose |
|---|---|
| `VITE_API_URL` | Backend API base URL, e.g. `http://localhost:1111/api` |
| `VITE_GROQ_API_KEY` | AI chat |
| `VITE_GOOGLE_CLIENT_ID` | Same public Google client ID as the server |
| `VITE_GOOGLE_REDIRECT_URI` | Must be one of `GOOGLE_REDIRECT_URIS` |

In Google Cloud Console, create an OAuth client of type **Web application**. Add `http://localhost:5173/auth/google/callback` (and the deployed URL) as an authorised redirect URI.

## 11. Known Limitations

**Planned but not fixed**

- **V5 – Internal Error Leakage.** The upload error handler in `server.js` still returns `err.message` with status `500`. It runs before the global error handler, so many client errors appear as `500` with the internal message. Payment errors are handled separately (V3).
- **V9 – Improper Input Validation / Regex.** Search endpoints (documents, patient doctor/hospital search, admin search) pass user input directly into MongoDB `$regex` without escaping it (ReDoS / regex injection).
- **V11 – Reactivation Bypass.** `reactivateAccount` sets `status = "ACTIVE"` whenever the password matches. A pending or rejected doctor, or an admin-suspended user, can therefore reactivate their own account. V7 limits how often this can be attempted but does not fix the logic.

**Residual risks of the fixes**

- **Appointments:** responses still populate the full patient and doctor `User` documents, including `passwordHash` and `refreshTokenHash`. After V1, only the two participants can see an appointment, but each still receives the other's hashes. The populated fields should be restricted.
- **V3:**
  - A patient can mark their own (simulated) payment as verified.
  - Any logged-in user can see doctors' email addresses.
- **V4:** authorization is checked when a socket joins a room. A socket that is already connected keeps its room until it disconnects, even if the account or appointment later changes.
- **V6:** `POST /register` still reveals when an email is already taken; this was accepted for usability. OTPs are stored as unsalted SHA-256.
- **V7:** the limit is per IP only, with in-memory counters. `trust proxy` is not configured for deployment behind a reverse proxy.
- **V8:** the magic-byte check proves the file type; it does not scan for malware.
- **V10:** only the server dependencies were in scope. Mongoose is held at 9.7.x because newer versions break the in-memory test setup. `npm audit` only covers known advisories, so it should be re-run before each release.
- **OAuth:**
  - Suspension is only rechecked at login, as with password login.
  - A linked user's email is not updated if it changes at Google.
  - The manual end-to-end walkthrough with a real Google client (consent screen, network trace) is listed as outstanding in the OAuth evidence.

**Test suites that were already failing.** In the full backend suite (`npm test`), 446 of 495 tests pass. 8 suites fail (49 tests): admin (unit and integration), patient (unit and integration), doctor controller, and the appointment model, integration and validator suites. These failures predate the security work; the V8 and V10 evidence records these suites failing before those changes. Causes include incomplete test fixtures (missing required fields), hard-coded dates that are now in the past, and a wrong import path. No security change introduced a new failure. The V1 change fixed one suite that was previously failing (appointment service).

## 12. Demonstration Video

https://youtu.be/RUGYF3S98M

---

The original CareLine360 application was developed by its original authors. This repository is a security-hardened copy produced for SE4030 coursework by Group 60.
