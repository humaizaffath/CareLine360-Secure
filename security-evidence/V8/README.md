# V8 – Insecure File Upload (content-type not verified)

**Owner:** Vishru · **Branch:** `bishru/v8-v10_insecFile_FileDep`
**Mapping:** CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-345 (Insufficient Verification of Data Authenticity), CWE-20 (Improper Input Validation) · OWASP Top 10 2021 A04 Insecure Design, A05 Security Misconfiguration

## Vulnerability

The server decided whether an uploaded file was allowed using only client-controlled metadata:

| Upload path | Endpoint | Code | Check before the fix |
|---|---|---|---|
| Patient medical documents | `POST /api/documents` (field `document`) | `server/middleware/documentUpload.js` | `file.mimetype` in allow-list (browser `Content-Type`) |
| Patient avatar | `PATCH /api/patients/me/avatar` (field `avatar`) | `server/middleware/upload.js` | `file.mimetype.startsWith("image/")` |
| Doctor avatar (base64 JSON) | `PUT /api/doctor/profile/avatar` (body `image`) → `doctorService.updateAvatarBase64` | `server/services/uploadService.js` `uploadBase64Image` | MIME taken from the `data:<mime>;base64,` prefix |

The `Content-Type`, the file name and the `data:` prefix are all chosen by the client. Both multipart paths used `multer-storage-cloudinary`, which streams the file straight to Cloudinary: `fileFilter` only receives metadata, so the actual bytes were never inspected before storage.

**Root cause:** the server trusted the file type the client claimed and never checked the file's real content.

## Impact

An authenticated user can store any content in CareLine360's Cloudinary account under trusted `res.cloudinary.com/<our cloud>/careline360/...` URLs, labelled as a medical PDF or a profile picture. These files are listed to the patient and opened by doctors reviewing records. This enables:
- HTML/phishing pages or arbitrary binaries (malware) hosted under the application's storage and delivered to clinicians as "documents".
- Content spoofing and loss of integrity of medical records (a "lab report" that is not a PDF).
- Storage abuse of the organisation's cloud account.

## Proof of concept

`capture-evidence.js` mounts the real `documentRoutes` and `patientRoutes` (same upload error handler as `server.js`) on an in-memory MongoDB. It authenticates as a fixed test patient and replaces the Cloudinary uploader with a stub that records whether an upload was attempted, so nothing reaches the real account. Payloads are harmless (plain text, static HTML) and generated in memory.

Example request (V8-1), equivalent to:

```
curl -X POST http://localhost:5000/api/documents \
  -H "Authorization: Bearer <patient access token>" \
  -F "document=@fake.txt;type=application/pdf;filename=report.pdf"
```

where `fake.txt` contains `PoC: this is plain text, not a PDF document.`

| Case | Upload | Before fix | After fix |
|---|---|---|---|
| V8-1 | Plain text as `report.pdf` / `application/pdf` | **201**, stored on Cloudinary | **400** "File content does not match an allowed file type", not uploaded |
| V8-2 | HTML page as `invoice.pdf` / `application/pdf` | **201**, stored | **400**, not uploaded |
| V8-3 | PNG bytes declared as `lab-result.pdf` / `application/pdf` | **201**, stored | **400** "File content does not match the declared file type", not uploaded |
| V8-4 | HTML page as patient avatar `avatar.png` / `image/png` | **200**, avatar set | **400**, not uploaded |
| V8-5 | HTML as doctor base64 avatar `data:image/png;base64,...` | accepted, stored | rejected (400), not uploaded |
| CTRL-1 | Genuine PDF document | 201 | 201 |
| CTRL-2 | Genuine PNG patient avatar | 200 | 200 |
| CTRL-3 | Genuine PNG doctor base64 avatar | accepted | accepted |

- `v8-baseline.json`: requests/responses on the original upload code
- `v8-after-fix.json`: the same requests after the fix
- `test-results.txt`: output of the V8 jest suites
- Reproduce with `node security-evidence/V8/capture-evidence.js <label>` from the repo root, after `npm install` in `server/`. The baseline was captured by temporarily restoring the original `documentUpload.js`, `upload.js` and `uploadService.js`.

## Fix

The server now checks the file's real content (its "magic bytes") before anything is sent to Cloudinary.

- `server/utils/fileSignature.js` (new): `detectMime(buffer)` identifies the file from its leading bytes. `validateFile()` accepts the file only if **all** of these hold:
  1. the detected type is on the endpoint's allow-list;
  2. the detected type equals the declared `Content-Type`;
  3. the file extension belongs to the detected type.
- `server/middleware/secureUpload.js` (new): multer now uses `memoryStorage()`. The flow is metadata pre-check → `validateFile` → `uploadBuffer` to Cloudinary. It fills `req.file` with the same fields `multer-storage-cloudinary` provided (`path`, `filename`, `resource_type`, `format`, `version`), so controllers and routes are unchanged. Validation failures return 400 with a generic message.
- `server/middleware/documentUpload.js`, `server/middleware/upload.js`: use `createSecureUpload`. Size limits, Cloudinary folders and the avatar transformation are unchanged. Avatars are limited to jpg/png/webp, matching the existing Cloudinary `allowed_formats`.
- `server/services/uploadService.js`: new `uploadBuffer()`. `uploadBase64Image()` now checks that the decoded bytes are an allowed image and match the `data:` MIME.
- Cloudinary still generates the `public_id`; the user's filename is never used as the storage key.

| Type | Magic bytes | Extensions | Documents | Patient avatar | Doctor avatar |
|---|---|---|---|---|---|
| PDF | `25 50 44 46 2D` (`%PDF-`) | .pdf | ✓ | | |
| JPEG | `FF D8 FF` | .jpg .jpeg | ✓ | ✓ | ✓ |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | .png | ✓ | ✓ | ✓ |
| WEBP | `RIFF....WEBP` | .webp | ✓ | ✓ | ✓ |
| GIF | `GIF87a` / `GIF89a` | .gif | | | ✓ |
| DOC | `D0 CF 11 E0 A1 B1 1A E1` | .doc | ✓ | | |
| DOCX | `50 4B 03 04` (ZIP) + `word/` part | .docx | ✓ | | |

## Tests

```
cd server
npx jest tests/unit/upload tests/integration/upload --forceExit
```

- `tests/unit/upload/fileSignature.test.js`: detection of each genuine type; rejection of text-as-PDF, HTML-as-PNG, PNG declared as PDF, wrong extension, non-allow-listed type, generic ZIP as DOCX, empty input; base64 avatar rejection and success.
- `tests/integration/upload/upload.security.test.js`: real routes with Cloudinary mocked. Spoofed document and avatar uploads return 400, Cloudinary is never called and no `Document` is saved. Genuine PDF and PNG uploads still succeed.
- Result: 23/23 passing (`test-results.txt`). The rest of the server suite has the same results with and without this change. The 9 failing admin/appointment/patient suites fail on the unmodified branch too.

## Remaining limitations

- A signature check proves the file *is* the claimed format; it is not malware scanning or content sanitisation. A valid PDF can still contain malicious content, which would need AV scanning such as ClamAV.
- The DOCX check is container-level (a ZIP with a `word/` part), not a full OOXML parse.
- `multer-storage-cloudinary` is no longer used but is still in `package.json`. Removing it, and upgrading `cloudinary` to v2, is part of V10 so that dependency changes stay in one place.
