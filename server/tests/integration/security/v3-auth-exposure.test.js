/**
 * V3 – Missing authentication / sensitive data exposure
 * (CWE-306, CWE-200; OWASP A01:2021 Broken Access Control)
 *
 * Covers /api/users, /api/emergency and /api/payments:
 *  - no token            -> 401
 *  - allowed role/owner  -> 2xx
 *  - disallowed role     -> 403
 *  - successful responses never contain passwordHash / refreshTokenHash
 */
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const jwt = require("jsonwebtoken");

const User = require("../../../models/User");
const Appointment = require("../../../models/Appointment");
const Payment = require("../../../models/Payment");
const EmergencyCase = require("../../../models/EmergencyCase");
const userRoutes = require("../../../routes/userRoutes");
const emergencyRoutes = require("../../../routes/emergencyRoutes");
const paymentRoutes = require("../../../routes/paymentRoutes");
const errorHandler = require("../../../middleware/errorHandler");

jest.mock("../../../config/cloudinary", () => ({
  uploader: {
    upload_stream: jest.fn((opts, cb) => {
      const { Writable } = require("stream");
      const w = new Writable({ write(chunk, enc, next) { next(); } });
      w.on("finish", () => cb(null, { secure_url: "https://example.test/r.pdf", public_id: "r" }));
      return w;
    }),
  },
}));

const SECRET_FIELDS = ["passwordHash", "refreshTokenHash"];

let mongoServer, app;
let admin, responder, patientA, patientB, doctor, otherDoctor;
let apptA, apptB, paymentA, emergencyA;

const tokenFor = (user) =>
  jwt.sign({ userId: user._id.toString(), role: user.role }, process.env.JWT_ACCESS_SECRET);

// supertest request with an optional Bearer token
const call = (method, url, user) => {
  const req = request(app)[method](url);
  return user ? req.set("Authorization", `Bearer ${tokenFor(user)}`) : req;
};

const expectNoSecrets = (body) => {
  const json = JSON.stringify(body);
  for (const field of SECRET_FIELDS) expect(json).not.toContain(`"${field}"`);
};

const makeUser = (role, email) =>
  User.create({
    role,
    email,
    fullName: `Test ${role}`,
    phone: `+9477${Math.floor(1000000 + Math.random() * 8999999)}`,
    passwordHash: "$2b$10$test-password-hash",
    refreshTokenHash: "$2b$10$test-refresh-hash",
  });

const makeAppointment = (patient, doc, day) =>
  Appointment.create({
    patient: patient._id,
    doctor: doc._id,
    date: new Date(`2026-10-${String(day).padStart(2, "0")}`),
    time: "10:00",
    consultationType: "video",
    status: "confirmed",
  });

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";

  // Mounted as in server.js, including its upload error handler that runs
  // before errorHandler and answers any error it receives with 500.
  app = express();
  app.use(express.json());
  app.use("/api/emergency", emergencyRoutes);
  app.use("/api/users", userRoutes);
  app.use("/api/payments", paymentRoutes);
  app.use((err, req, res, next) => res.status(500).json({ message: err.message || "Internal server error" }));
  app.use(errorHandler);

  admin = await makeUser("admin", "admin@v3.test");
  responder = await makeUser("responder", "responder@v3.test");
  patientA = await makeUser("patient", "patient.a@v3.test");
  patientB = await makeUser("patient", "patient.b@v3.test");
  doctor = await makeUser("doctor", "doctor@v3.test");
  otherDoctor = await makeUser("doctor", "other.doctor@v3.test");
}, 30000);

beforeEach(async () => {
  apptA = await makeAppointment(patientA, doctor, 1);
  apptB = await makeAppointment(patientB, otherDoctor, 2);
  paymentA = await Payment.create({ appointment: apptA._id, patient: patientA._id, amount: 3500 });
  emergencyA = await EmergencyCase.create({ patient: patientA._id, description: "test sos", latitude: 6.9, longitude: 79.8 });
});

afterEach(async () => {
  await Promise.all([Appointment.deleteMany({}), Payment.deleteMany({}), EmergencyCase.deleteMany({})]);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// ─── Unauthenticated access is denied everywhere ─────────────────────────────

describe("V3: requests without an access token are rejected", () => {
  const cases = () => [
    ["get", "/api/users"],
    ["get", "/api/users?role=doctor"],
    ["get", `/api/users/${patientA._id}`],
    ["get", "/api/emergency"],
    ["get", `/api/emergency/${emergencyA._id}`],
    ["get", `/api/emergency/${emergencyA._id}/nearest-hospital`],
    ["post", "/api/emergency", { patient: String(patientA._id), description: "forged", latitude: 1, longitude: 1 }],
    ["patch", `/api/emergency/${emergencyA._id}/status`, { status: "RESOLVED" }],
    ["post", "/api/payments", { appointment: String(apptA._id), patient: String(patientA._id), amount: 1 }],
    ["get", `/api/payments/${paymentA._id}`],
    ["get", `/api/payments/appointment/${apptA._id}`],
    ["patch", `/api/payments/${paymentA._id}/verify`],
    ["patch", `/api/payments/${paymentA._id}/fail`],
    ["get", `/api/payments/${paymentA._id}/receipt`],
  ];

  it("returns 401 and no data for every affected endpoint", async () => {
    for (const [method, url, body] of cases()) {
      let req = call(method, url);
      if (body) req = req.send(body);
      const res = await req;
      expect({ route: `${method.toUpperCase()} ${url}`, status: res.status }).toEqual({
        route: `${method.toUpperCase()} ${url}`,
        status: 401,
      });
      expect(res.body.data).toBeUndefined();
    }
  });

  it("does not change state when unauthenticated", async () => {
    await call("patch", `/api/emergency/${emergencyA._id}/status`).send({ status: "RESOLVED" });
    await call("patch", `/api/payments/${paymentA._id}/verify`);
    await call("post", "/api/emergency").send({ patient: String(patientA._id), description: "x", latitude: 1, longitude: 1 });

    expect((await EmergencyCase.findById(emergencyA._id)).status).toBe("PENDING");
    expect((await Payment.findById(paymentA._id)).status).toBe("pending");
    expect(await EmergencyCase.countDocuments()).toBe(1);
  });
});

// ─── /api/users ──────────────────────────────────────────────────────────────

describe("V3: /api/users", () => {
  it("admin can list all users without secret fields", async () => {
    const res = await call("get", "/api/users", admin).expect(200);
    expect(res.body.data).toHaveLength(6);
    expectNoSecrets(res.body);
  });

  it("patient can list doctors (booking flow) with public fields only", async () => {
    const res = await call("get", "/api/users?role=doctor", patientA).expect(200);
    expect(res.body.data).toHaveLength(2);
    for (const u of res.body.data) {
      expect(u.role).toBe("doctor");
      expect(Object.keys(u).sort()).toEqual(["_id", "email", "fullName", "role"]);
    }
    expectNoSecrets(res.body);
  });

  it.each([
    ["patient listing all users", "/api/users", () => patientA],
    ["patient listing patients", "/api/users?role=patient", () => patientA],
    ["doctor listing all users", "/api/users", () => doctor],
    ["responder listing admins", "/api/users?role=admin", () => responder],
  ])("denies %s (403)", async (_label, url, who) => {
    const res = await call("get", url, who()).expect(403);
    expect(res.body.data).toBeUndefined();
  });

  it("rejects a non-string / unknown role filter (400)", async () => {
    await call("get", "/api/users?role=doctor&role=admin", admin).expect(400);
    await call("get", "/api/users?role=superuser", admin).expect(400);
  });

  it("user can read their own record without secret fields", async () => {
    const res = await call("get", `/api/users/${patientA._id}`, patientA).expect(200);
    expect(res.body.data._id).toBe(patientA._id.toString());
    expectNoSecrets(res.body);
  });

  it("user cannot read another user's record (403)", async () => {
    await call("get", `/api/users/${patientB._id}`, patientA).expect(403);
    await call("get", `/api/users/${patientA._id}`, doctor).expect(403);
  });

  it("admin can read any user without secret fields", async () => {
    const res = await call("get", `/api/users/${doctor._id}`, admin).expect(200);
    expect(res.body.data.email).toBe("doctor@v3.test");
    expectNoSecrets(res.body);
  });
});

// ─── /api/emergency ──────────────────────────────────────────────────────────

describe("V3: /api/emergency", () => {
  it("patient can raise an SOS; it is always recorded against the caller", async () => {
    const res = await call("post", "/api/emergency", patientA)
      .send({ patient: String(patientB._id), description: "help", latitude: 6.9, longitude: 79.8, status: "RESOLVED" })
      .expect(201);
    expect(res.body.data.patient).toBe(patientA._id.toString());
    expect(res.body.data.status).toBe("PENDING");
    expectNoSecrets(res.body);
  });

  it.each([["doctor", () => doctor], ["responder", () => responder], ["admin", () => admin]])(
    "denies SOS creation for %s (403)",
    async (_role, who) => {
      await call("post", "/api/emergency", who())
        .send({ patient: String(patientA._id), description: "x", latitude: 1, longitude: 1 })
        .expect(403);
    }
  );

  it.each([["admin", () => admin], ["responder", () => responder]])(
    "%s can monitor emergencies without secret fields",
    async (_role, who) => {
      const list = await call("get", "/api/emergency", who()).expect(200);
      expect(list.body.data).toHaveLength(1);
      expectNoSecrets(list.body);

      const one = await call("get", `/api/emergency/${emergencyA._id}`, who()).expect(200);
      expectNoSecrets(one.body);

      await call("get", `/api/emergency/${emergencyA._id}/nearest-hospital`, who()).expect(200);
    }
  );

  it("responder can update emergency status", async () => {
    const res = await call("patch", `/api/emergency/${emergencyA._id}/status`, responder)
      .send({ status: "DISPATCHED" })
      .expect(200);
    expect(res.body.data.status).toBe("DISPATCHED");
  });

  it.each([["patient", () => patientA], ["doctor", () => doctor]])(
    "denies %s access to monitoring/dispatch routes (403)",
    async (_role, who) => {
      await call("get", "/api/emergency", who()).expect(403);
      await call("get", `/api/emergency/${emergencyA._id}`, who()).expect(403);
      await call("get", `/api/emergency/${emergencyA._id}/nearest-hospital`, who()).expect(403);
      await call("patch", `/api/emergency/${emergencyA._id}/status`, who()).send({ status: "RESOLVED" }).expect(403);
      expect((await EmergencyCase.findById(emergencyA._id)).status).toBe("PENDING");
    }
  );
});

// ─── /api/payments ───────────────────────────────────────────────────────────

describe("V3: /api/payments", () => {
  it("owning patient can read their payment; patient data has no secrets", async () => {
    const res = await call("get", `/api/payments/${paymentA._id}`, patientA).expect(200);
    expect(Object.keys(res.body.data.patient).sort()).toEqual(["_id", "email", "fullName", "phone"]);
    expectNoSecrets(res.body);

    const byAppt = await call("get", `/api/payments/appointment/${apptA._id}`, patientA).expect(200);
    expectNoSecrets(byAppt.body);
  });

  it.each([["appointment's doctor", () => doctor], ["admin", () => admin]])(
    "%s can read the payment without secret fields",
    async (_label, who) => {
      const res = await call("get", `/api/payments/${paymentA._id}`, who()).expect(200);
      expectNoSecrets(res.body);
    }
  );

  it.each([
    ["another patient", () => patientB],
    ["an unrelated doctor", () => otherDoctor],
    ["a responder (role not allowed)", () => responder],
  ])("denies %s (403)", async (_label, who) => {
    await call("get", `/api/payments/${paymentA._id}`, who()).expect(403);
    await call("get", `/api/payments/appointment/${apptA._id}`, who()).expect(403);
    await call("get", `/api/payments/${paymentA._id}/receipt`, who()).expect(403);
    await call("patch", `/api/payments/${paymentA._id}/verify`, who()).expect(403);
    await call("patch", `/api/payments/${paymentA._id}/fail`, who()).expect(403);
    expect((await Payment.findById(paymentA._id)).status).toBe("pending");
  });

  it("patient can create a payment for their own appointment; payer is the caller", async () => {
    await Payment.deleteMany({});
    const res = await call("post", "/api/payments", patientA)
      .send({ appointment: String(apptA._id), patient: String(patientB._id), amount: 3500, status: "verified" })
      .expect(201);
    expect(res.body.data.patient._id).toBe(patientA._id.toString());
    expect(res.body.data.status).toBe("pending");
    expectNoSecrets(res.body);
  });

  it("patient cannot create a payment for another patient's appointment (403)", async () => {
    await call("post", "/api/payments", patientA)
      .send({ appointment: String(apptB._id), patient: String(patientA._id), amount: 1 })
      .expect(403);
    expect(await Payment.countDocuments({ appointment: apptB._id })).toBe(0);
  });

  it("doctor cannot create payments (403)", async () => {
    await Payment.deleteMany({});
    await call("post", "/api/payments", doctor)
      .send({ appointment: String(apptA._id), patient: String(patientA._id), amount: 1 })
      .expect(403);
  });

  it("appointment's doctor can verify; response has no secret fields", async () => {
    const res = await call("patch", `/api/payments/${paymentA._id}/verify`, doctor).expect(200);
    expect(res.body.data.status).toBe("verified");
    expectNoSecrets(res.body);
  });

  it("owning patient can download the receipt of a verified payment", async () => {
    await Payment.updateOne({ _id: paymentA._id }, { status: "verified", transactionRef: "TXN-TEST" });
    const res = await call("get", `/api/payments/${paymentA._id}/receipt`, patientA).expect(200);
    expect(res.headers["content-type"]).toContain("application/pdf");
  });
});
