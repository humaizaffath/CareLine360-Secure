const path = require("path");
// V8 evidence capture: sends controlled uploads whose declared type/extension does NOT
// match their real content to every affected upload path (routes mounted as in server.js)
// and records whether the file was accepted and handed to Cloudinary.
// Usage (from repo root, after `npm install` in server/): node security-evidence/V8/capture-evidence.js <label>
// Writes v8-<label>.json next to this file. Uses an in-memory MongoDB, a fixed test patient
// and a stubbed Cloudinary uploader — nothing is sent to the real Cloudinary account.
// Payloads are harmless (plain text / static HTML) and generated in memory, never written to disk.
// SERVER_DIR lets the same script run against another checkout (e.g. the pre-fix commit).
const S = process.env.SERVER_DIR ? path.resolve(process.env.SERVER_DIR) : path.resolve(__dirname, "../../server");
const r = (p) => require(`${S}/${p}`);
const mongoose = r("node_modules/mongoose");
const express = r("node_modules/express");
const request = r("node_modules/supertest");
const { MongoMemoryServer } = r("node_modules/mongodb-memory-server");
const { Writable } = require("stream");
const fs = require("fs");

// ── Stub Cloudinary: record every upload attempt instead of sending it ─────────
const cloudinary = r("config/cloudinary");
let uploads = [];
cloudinary.uploader.upload_stream = (opts, cb) => {
  const chunks = [];
  const w = new Writable({ write(c, e, next) { chunks.push(c); next(); } });
  w.on("finish", () => {
    const bytes = Buffer.concat(chunks);
    uploads.push({ folder: opts.folder, bytes: bytes.length });
    cb(null, {
      secure_url: `https://res.cloudinary.com/<cloud>/${opts.folder}/stored-file`,
      public_id: `${opts.folder}/stored-file`,
      resource_type: opts.resource_type === "auto" ? "image" : opts.resource_type || "image",
      format: "bin",
      version: 1,
      bytes: bytes.length,
    });
  });
  return w;
};

// ── Stub auth: every request is the same authenticated test patient ─────────────
let currentUserId;
const authPath = require.resolve(`${S}/middleware/auth`);
require.cache[authPath] = {
  id: authPath, filename: authPath, loaded: true,
  exports: {
    authMiddleware: (req, res, next) => { req.user = { userId: currentUserId, role: "patient" }; next(); },
    roleMiddleware: () => (req, res, next) => next(),
  },
};

const Patient = r("models/Patient");
const Document = r("models/Document");
const { uploadBase64Image } = r("services/uploadService");

// ── Payloads (generated in memory) ────────────────────────────────────────────
const TEXT = Buffer.from("PoC: this is plain text, not a PDF document.\n");
const HTML = Buffer.from("<!doctype html><html><body><h1>PoC: HTML page, not a real file</h1></body></html>\n");
const PDF = Buffer.from("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n");
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4a00000000049454e44ae426082", "hex");

const CASES = [
  { id: "V8-1", desc: "Plain text uploaded as a PDF document", kind: "http", method: "post", url: "/api/documents", field: "document", buf: TEXT, filename: "report.pdf", type: "application/pdf", malicious: true },
  { id: "V8-2", desc: "HTML page uploaded as a PDF document", kind: "http", method: "post", url: "/api/documents", field: "document", buf: HTML, filename: "invoice.pdf", type: "application/pdf", malicious: true },
  { id: "V8-3", desc: "PNG image bytes declared as a PDF document", kind: "http", method: "post", url: "/api/documents", field: "document", buf: PNG, filename: "lab-result.pdf", type: "application/pdf", malicious: true },
  { id: "V8-4", desc: "HTML page uploaded as the patient avatar (image/png)", kind: "http", method: "patch", url: "/api/patients/me/avatar", field: "avatar", buf: HTML, filename: "avatar.png", type: "image/png", malicious: true },
  { id: "V8-5", desc: "HTML page sent as doctor base64 avatar (data:image/png)", kind: "base64", buf: HTML, type: "image/png", malicious: true },
  { id: "CTRL-1", desc: "Control: genuine PDF document", kind: "http", method: "post", url: "/api/documents", field: "document", buf: PDF, filename: "report.pdf", type: "application/pdf", malicious: false },
  { id: "CTRL-2", desc: "Control: genuine PNG patient avatar", kind: "http", method: "patch", url: "/api/patients/me/avatar", field: "avatar", buf: PNG, filename: "avatar.png", type: "image/png", malicious: false },
  { id: "CTRL-3", desc: "Control: genuine PNG doctor base64 avatar", kind: "base64", buf: PNG, type: "image/png", malicious: false },
];

const summarize = (body) => {
  if (!body || typeof body !== "object") return body;
  const out = { message: body.message };
  if (body.document) {
    const d = body.document;
    out.document = { fileName: d.fileName, mimeType: d.mimeType, fileUrl: d.fileUrl };
  }
  if (body.avatarUrl) out.avatarUrl = body.avatarUrl;
  return out;
};

(async () => {
  const label = process.argv[2] || "run";
  const mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
  const origLog = console.log;
  console.log = () => {}; // silence controller debug logging

  const app = express();
  app.use(express.json({ limit: "5mb" }));
  app.use("/api/patients", r("routes/patientRoutes"));
  app.use("/api/documents", r("routes/documentRoutes"));
  // Same upload error handler as server.js
  app.use((err, req, res, next) => {
    if (err?.message?.includes("Only image files allowed")) return res.status(400).json({ message: "Only image files allowed" });
    if (err?.message?.includes("Only PDF, images, DOC, DOCX allowed")) return res.status(400).json({ message: "Only PDF, images, DOC, DOCX allowed" });
    if (err?.code === "LIMIT_FILE_SIZE") return res.status(400).json({ message: "File too large" });
    return res.status(500).json({ message: err.message || "Internal server error" });
  });

  const results = [];
  for (const c of CASES) {
    currentUserId = new mongoose.Types.ObjectId();
    await Patient.create({ userId: currentUserId, patientId: `P-${c.id}`, fullName: "Evidence Patient" });
    uploads = [];

    const req = { declaredContentType: c.type, actualFirstBytesHex: c.buf.subarray(0, 8).toString("hex"), actualFirstBytesText: c.buf.subarray(0, 16).toString("latin1").replace(/[^\x20-\x7e]/g, ".") };
    let status, body;
    if (c.kind === "http") {
      Object.assign(req, { method: c.method.toUpperCase(), url: c.url, field: c.field, filename: c.filename });
      const res = await request(app)[c.method](c.url).attach(c.field, c.buf, { filename: c.filename, contentType: c.type });
      status = res.status;
      body = summarize(res.body);
    } else {
      Object.assign(req, { call: "uploadBase64Image (doctor PATCH avatar, base64 body)", dataUriPrefix: `data:${c.type};base64,` });
      try {
        const out = await uploadBase64Image(`data:${c.type};base64,${c.buf.toString("base64")}`, { folder: "careline360/avatars" });
        status = "accepted"; body = { url: out.url };
      } catch (e) {
        status = "rejected (service returns 400)"; body = { message: e.message };
      }
    }

    const storedDocs = await Document.countDocuments({ userId: currentUserId });
    results.push({
      id: c.id, description: c.desc, maliciousUpload: c.malicious, request: req,
      response: { status, body },
      uploadedToCloudinary: uploads.length > 0,
      documentRecordsSaved: storedDocs,
    });
    await Patient.deleteMany({});
    await Document.deleteMany({});
  }

  console.log = origLog;
  const out = path.join(__dirname, `v8-${label}.json`);
  fs.writeFileSync(out, JSON.stringify({ label, capturedAt: new Date().toISOString(), results }, null, 2) + "\n");

  console.log(`\nV8 evidence (${label}) -> ${path.relative(process.cwd(), out)}\n`);
  console.table(results.map((x) => ({ id: x.id, malicious: x.maliciousUpload, status: x.response.status, uploadedToCloudinary: x.uploadedToCloudinary, message: (x.response.body && x.response.body.message) || "" })));

  await mongoose.disconnect();
  await mongo.stop();
})().catch((e) => { console.error(e); process.exit(1); });
