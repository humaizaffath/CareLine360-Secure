# V10 – Vulnerable Dependencies (server)

**Owner:** Vishru · **Branch:** `bishru/v8-v10_insecFile_FileDep`
**Mapping:** CWE-1395 (Dependency on Vulnerable Third-Party Component), CWE-1104 (Use of Unmaintained Third-Party Components) · OWASP Top 10 2021 A06 Vulnerable and Outdated Components

## Vulnerability

`npm audit` on `server/` reported **28 known vulnerabilities (17 high, 9 moderate, 2 low)** in packages the server installs (`npm-audit-before.txt` / `.json`). Affected component: `server/package.json` and `server/package-lock.json`.

The ones that matter most at runtime are in code that handles untrusted input on every request:

| Package (installed) | Used by | Example advisory | Risk |
|---|---|---|---|
| `nodemailer` 8.0.1 (10 advisories) | `services/emailService.js` (all appointment/auth emails) | SMTP/header injection via CRLF (CWE-93), `addressparser` O(n²) DoS, recipient-domain validation bypass, SSRF/file read via `raw` | Email header injection, mail sent to attacker domains, DoS |
| `cloudinary` 1.41.3 | `config/cloudinary.js`, all uploads | GHSA-g4mf-96x5-5m2c – argument injection via `&` in upload parameters (CWE-88) | Tampered upload parameters |
| `multer` 2.0.2 (8 advisories) | upload middleware (V8) | Crafted multipart field names / aborted uploads cause DoS (recursion, resource exhaustion, incomplete cleanup); file-size limit bypass via async `fileFilter` race (CWE-400/674/772/459/362) | Remote DoS of upload endpoints |
| `path-to-regexp` 8.3.0, `qs` 6.14.1, `body-parser` 2.2.2 | Express routing and body parsing | ReDoS / `arrayLimit` bypass (CWE-1333/400) | Remote DoS of the whole API |
| `ws` 8.18.3, `engine.io` 6.6.5, `socket.io-parser` 4.2.5 | Socket.IO chat | Memory exhaustion via unbounded binary attachments / tiny fragments; uninitialised memory disclosure | Remote DoS, memory disclosure |
| `express-rate-limit` 8.2.1, `ip-address` | Auth rate limiter | IPv4-mapped IPv6 addresses bypass per-client rate limiting on dual-stack servers (GHSA-46wh-pxpv-q5gq) | Brute-force protection on `/api/auth/*` weakened |
| `mongoose` 9.2.1 | All models | Prototype pollution via `__proto__` in update paths (CWE-1321) | Object tampering |
| `lodash`, `form-data`, `follow-redirects`, `uuid`, … | Transitive | Prototype pollution, CRLF, info leak | See audit JSON |

**Root cause:** these dependency versions had not been updated since known security fixes were published.

## Impact

An unauthenticated attacker can use public advisories to take the API or chat server down (ReDoS and memory exhaustion in express/qs/multer/ws/socket.io), inject headers into emails CareLine360 sends to patients, and weaken the login rate limiter. No bug in CareLine360's own code is needed.

## Fix

The assignment says not to use `npm audit fix --force` blindly, so the changes were made in steps:

1. **`npm audit fix` (no `--force`)** – semver-compatible updates only. 28 → 3 vulnerabilities. Only the lock file changed.
2. **mongoose pinned to `~9.7.2` (installed 9.7.4).** Step 1 moved mongoose to 9.10.2, which pulls MongoDB driver 7.6. That driver fails to connect inside Jest ("Missing required sub-document 'driver' in the client metadata document"), so every DB-backed test suite timed out. 9.7.4 is still ≥ the patched 9.7.2 and uses driver 7.2, which works.
3. **`nodemailer` 8.0.1 → `~9.1.1` (major).** 9.1.1 is the lowest version that fixes all 10 advisories. npm's suggestion was 10.0.10, a two-major jump. Breaking changes checked in the changelog:
   - 9.0 validates TLS certificates when fetching remote attachments or OAuth2 tokens. The app uses neither: it sends plain SMTP with `from/to/subject/html`.
   - 10.0 only drops Node < 20.
4. **`cloudinary` 1.41.3 → `^2.11.0` (major).** The 2.0 breaking changes (`secure: true` by default, analytics, dropping Node 6/8) don't affect the app, which only uses `v2.uploader.upload_stream` / `destroy` and `secure_url`.
5. **`multer-storage-cloudinary` removed.** It pins `cloudinary` to v1 and blocked the fix. After V8 it is no longer required anywhere, because `middleware/secureUpload.js` uploads the buffers itself.

`package.json` diff:

```
-    "cloudinary": "^1.41.3",
+    "cloudinary": "^2.11.0",
-    "mongoose": "^9.2.1",
+    "mongoose": "~9.7.2",
-    "multer-storage-cloudinary": "^4.0.0",
-    "nodemailer": "^8.0.1",
+    "nodemailer": "~9.1.1",
```

No application source files were changed for V10.

| Package | Before → After | Type |
|---|---|---|
| cloudinary | 1.41.3 → 2.11.0 | direct, major |
| nodemailer | 8.0.1 → 9.1.1 | direct, major |
| multer-storage-cloudinary | 4.0.0 → removed | direct |
| mongoose | 9.2.1 → 9.7.4 | direct |
| multer | 2.0.2 → 2.4.0 | direct |
| express-rate-limit | 8.2.1 → 8.7.0 | direct |
| resend | 6.10.0 → 6.30.0 (drops vulnerable `svix`/`uuid`) | direct |
| path-to-regexp | 8.3.0 → 8.4.2 | transitive (express) |
| qs | 6.14.1 → 6.16.0 | transitive (express) |
| body-parser | 2.2.2 → 2.3.0 | transitive (express) |
| ws | 8.18.3 → 8.21.3 | transitive (socket.io) |
| engine.io | 6.6.5 → 6.6.11 | transitive (socket.io) |
| socket.io-parser | 4.2.5 → 4.2.7 | transitive (socket.io) |
| socket.io-adapter | 2.5.6 → 2.5.8 | transitive (socket.io) |
| lodash | 4.17.23 → 4.18.1 | transitive |
| form-data | 4.0.5 → 4.0.6 | transitive |
| follow-redirects | 1.15.11 → 1.16.0 | transitive |
| ip-address | 10.0.1 → 10.7.2 | transitive (express-rate-limit) |
| brace-expansion, minimatch, picomatch, js-yaml, browserslist, baseline-browser-mapping, @babel/core, yauzl | patch updates | transitive, dev/test tooling (jest, nodemon, mongodb-memory-server) |

## Verification

**After:** `npm audit` → **found 0 vulnerabilities** (`npm-audit-after.txt` / `.json`).

**Application tests** (`test-results.txt`): full `npx jest` suite before and after gives the same PASS/FAIL result for every suite: 17 pass, 9 fail, 282/333 tests pass. The 9 failing suites (admin, appointment, patient, doctorController) were already failing before any V10 change.

**Smoke test** (`smoke-test.js`, output `smoke-test-results.json`): starts the real `server.js` with the upgraded packages against an in-memory MongoDB, a local Cloudinary upload-API stand-in and a local SMTP stand-in, so no real account is contacted. 10/10 checks pass:

| Check | Result |
|---|---|
| Server starts, connects to MongoDB, `GET /` = 200 | PASS |
| Register patient 201, login 200 with access token, `/api/auth/me` 200 with token / 401 without | PASS |
| Genuine PDF `POST /api/documents` → 201, sent to Cloudinary 2.x `/auto/upload` | PASS |
| Spoofed PDF → 400, never sent to Cloudinary (V8 still intact) | PASS |
| Genuine PNG avatar → 200, sent to Cloudinary 2.x `/image/upload` | PASS |
| `emailService.sendEmail` delivers over SMTP via nodemailer 9.1.1 | PASS |

Reproduce from the repo root after `npm install` in `server/`:

```
cd server && npm audit && npx jest --forceExit && cd ..
node security-evidence/V10/smoke-test.js
```

## Remaining limitations

- `mongoose` is held at `~9.7.x` because newer 9.8+ versions use MongoDB driver ≥ 7.5, which currently breaks the Jest in-memory test setup. Revisit when upgrading Jest or `mongodb-memory-server`. 9.7.4 has no known advisories.
- `nodemailer` is on 9.1.1, not the newest major (10.x). It has no known advisories. Moving to 10.x only needs Node ≥ 20.
- The smoke test uses local stand-ins for Cloudinary and SMTP. A real upload and email with the team's actual credentials was not part of this evidence.
- The client (`client/`) dependencies were not in V10's scope ("server dependency vulnerabilities").
- `npm audit` only covers publicly reported advisories. New ones will appear over time, so the audit should be re-run before submission.
