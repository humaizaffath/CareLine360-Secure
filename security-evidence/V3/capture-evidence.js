const path = require("path");
// V3 evidence capture: sends controlled requests WITHOUT an access token to every
// affected endpoint (mounted exactly as in server.js) and prints redacted results.
// Usage (from repo root, after `npm install` in server/): node security-evidence/V3/capture-evidence.js <label>
// Writes v3-<label>.json next to this file. Uses synthetic data in an in-memory MongoDB.
// SERVER_DIR lets the same script run against another checkout (e.g. the pre-fix commit).
const S = process.env.SERVER_DIR ? path.resolve(process.env.SERVER_DIR) : path.resolve(__dirname, "../../server");
const r = (p) => require(`${S}/${p}`);
const mongoose = r("node_modules/mongoose");
const express = r("node_modules/express");
const request = r("node_modules/supertest");
const { MongoMemoryServer } = r("node_modules/mongodb-memory-server");
const fs = require("fs");

process.env.JWT_ACCESS_SECRET = "evidence-only-secret";
const User = r("models/User");
const Appointment = r("models/Appointment");
const Payment = r("models/Payment");
const EmergencyCase = r("models/EmergencyCase");

const HASH_KEYS = new Set(["passwordHash", "refreshTokenHash"]);
const PII_KEYS = new Set(["email", "phone", "fullName", "name", "description", "responderName"]);
const LOC_KEYS = new Set(["latitude", "longitude", "lat", "lng"]);
const redact = (v, k) => {
  if (k && HASH_KEYS.has(k)) return "[REDACTED-SECRET-HASH]";
  if (k && PII_KEYS.has(k)) return "[REDACTED-PII]";
  if (k && LOC_KEYS.has(k)) return "[REDACTED-LOCATION]";
  if (Array.isArray(v)) return v.map((x) => redact(x));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([kk, vv]) => [kk, redact(vv, kk)]));
  if (typeof v === "string" && /^[a-f0-9]{24}$/i.test(v)) return "<objectId>";
  if (typeof v === "string" && /^TXN-/.test(v)) return "<transactionRef>";
  return v;
};
const secretsPresent = (body) => {
  const s = JSON.stringify(body || {});
  return ["passwordHash", "refreshTokenHash"].filter((k) => s.includes(`"${k}"`));
};

(async () => {
  const label = process.argv[2] || "run";
  const mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());

  const app = express();
  app.use(express.json());
  app.use("/api/users", r("routes/userRoutes"));
  app.use("/api/emergency", r("routes/emergencyRoutes"));
  app.use("/api/payments", r("routes/paymentRoutes"));
  app.use(r("middleware/errorHandler"));

  // Synthetic fixture data only.
  const mk = (email, role) => User.create({ email, role, fullName: `Test ${role}`, phone: `+9477000${Math.floor(1000 + Math.random() * 8999)}`,
    passwordHash: "$2b$10$synthetic-password-hash", refreshTokenHash: "$2b$10$synthetic-refresh-hash" });
  const patient = await mk("victim.patient@example.test", "patient");
  const doctor = await mk("doctor@example.test", "doctor");
  const appt = await Appointment.create({ patient: patient._id, doctor: doctor._id, date: new Date("2026-10-01"), time: "10:00", consultationType: "video", status: "confirmed" });
  const appt2 = await Appointment.create({ patient: patient._id, doctor: doctor._id, date: new Date("2026-10-02"), time: "11:00", consultationType: "video" });
  const pay = await Payment.create({ appointment: appt._id, patient: patient._id, amount: 2500 });
  const payVerified = await Payment.create({ appointment: appt2._id, patient: patient._id, amount: 2500, status: "verified", transactionRef: "TXN-EVIDENCE" });
  const em = await EmergencyCase.create({ patient: patient._id, description: "synthetic emergency", latitude: 6.9, longitude: 79.8 });
  const appt3 = await Appointment.create({ patient: patient._id, doctor: doctor._id, date: new Date("2026-10-03"), time: "12:00", consultationType: "video" });

  const cases = [
    ["GET", "/api/users", null, "/api/users"],
    ["GET", "/api/users?role=doctor", null, "/api/users?role=doctor"],
    ["GET", `/api/users/${patient._id}`, null, "/api/users/:id"],
    ["GET", "/api/emergency", null, "/api/emergency"],
    ["GET", `/api/emergency/${em._id}`, null, "/api/emergency/:id"],
    ["GET", `/api/emergency/${em._id}/nearest-hospital`, null, "/api/emergency/:id/nearest-hospital"],
    ["POST", "/api/emergency", { patient: String(patient._id), description: "forged SOS", latitude: 1, longitude: 1 }, "/api/emergency"],
    ["PATCH", `/api/emergency/${em._id}/status`, { status: "RESOLVED", responderName: "unauthenticated" }, "/api/emergency/:id/status"],
    ["GET", `/api/payments/${pay._id}`, null, "/api/payments/:id"],
    ["GET", `/api/payments/appointment/${appt._id}`, null, "/api/payments/appointment/:appointmentId"],
    ["POST", "/api/payments", { appointment: String(appt3._id), patient: String(patient._id), amount: 1 }, "/api/payments"],
    ["PATCH", `/api/payments/${pay._id}/fail`, null, "/api/payments/:id/fail"],
    ["GET", `/api/payments/${payVerified._id}/receipt`, null, "/api/payments/:id/receipt"],
  ];
  // verify runs on a separate pending payment so /fail above has something to act on
  const pay2 = await Payment.create({ appointment: (await Appointment.create({ patient: patient._id, doctor: doctor._id, date: new Date("2026-10-04"), time: "13:00", consultationType: "video" }))._id, patient: patient._id, amount: 10 });
  cases.push(["PATCH", `/api/payments/${pay2._id}/verify`, null, "/api/payments/:id/verify"]);

  const out = [];
  for (const [method, url, body, route] of cases) {
    let req = request(app)[method.toLowerCase()](url); // deliberately NO Authorization header
    if (body) req = req.send(body);
    const res = await req;
    const isPdf = (res.headers["content-type"] || "").includes("pdf");
    const rec = {
      route: `${method} ${route}`,
      request: { method, path: route, authorization: "none", body: body ? redact(body) : undefined },
      status: res.status,
      secretFieldsInResponse: isPdf ? [] : secretsPresent(res.body),
      response: isPdf ? `<PDF receipt, ${res.body?.length || res.text?.length || "n"} bytes, content-type application/pdf>` : redact(res.body),
    };
    out.push(rec);
    console.log(`${rec.status}  ${rec.route}${rec.secretFieldsInResponse.length ? "  LEAKS: " + rec.secretFieldsInResponse.join(",") : ""}`);
  }
  fs.writeFileSync(path.join(__dirname, `v3-${label}.json`), JSON.stringify(out, null, 2));
  await mongoose.disconnect(); await mongo.stop(); process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
