/**
 * V6 – User enumeration and weak OTP
 * (CWE-203 Observable Discrepancy, CWE-204 Observable Response Discrepancy,
 *  CWE-338 Use of Cryptographically Weak PRNG; OWASP A07:2021)
 *
 * Each enumeration test sends the same request for a known and an unknown
 * account and expects the outward response (status + body) to be identical.
 * The OTP tests expect generateOtp() not to depend on Math.random() and to
 * keep producing six-digit codes.
 *
 * Email is mocked and MongoDB is in-memory: no real email, no shared database.
 */
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");

jest.mock("../../../services/emailService", () => ({ sendEmail: jest.fn() }));

const User = require("../../../models/User");
const Patient = require("../../../models/Patient");
const authRoutes = require("../../../routes/authRoutes");
const { generateOtp } = require("../../../utils/otp");

const KNOWN_EMAIL = "known.patient@v6.test";
const UNKNOWN_EMAIL = "nobody@v6.test";
const PASSWORD = "Correct#Pass1";
const WRONG_PASSWORD = "Wrong#Pass1";

let mongoServer, app;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "test-refresh-secret";

  // Mounted as in server.js
  app = express();
  app.use(express.json());
  app.use("/api/auth", authRoutes);

  // A self-deactivated patient: the account state /reactivate is meant for
  const user = await User.create({
    role: "patient",
    email: KNOWN_EMAIL,
    fullName: "Known Patient",
    passwordHash: await bcrypt.hash(PASSWORD, 10),
    isActive: false,
    status: "SUSPENDED",
  });
  await Patient.create({ userId: user._id, patientId: "PAT-V60001", fullName: "Known Patient", isDeleted: true });
}, 30000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Status and body are what an attacker can observe
const outward = (res) => ({ status: res.status, body: res.body });

// ─── Account enumeration ─────────────────────────────────────────────────────

describe("V6: account enumeration", () => {
  it("POST /api/auth/password/forgot answers the same for known and unknown accounts", async () => {
    const known = await request(app).post("/api/auth/password/forgot").send({ identifier: KNOWN_EMAIL });
    const unknown = await request(app).post("/api/auth/password/forgot").send({ identifier: UNKNOWN_EMAIL });

    expect(outward(unknown)).toEqual(outward(known));
  });

  it("POST /api/auth/reactivate answers the same for a known account and an unknown account with a wrong password", async () => {
    const known = await request(app)
      .post("/api/auth/reactivate")
      .send({ identifier: KNOWN_EMAIL, password: WRONG_PASSWORD });
    const unknown = await request(app)
      .post("/api/auth/reactivate")
      .send({ identifier: UNKNOWN_EMAIL, password: WRONG_PASSWORD });

    expect(outward(unknown)).toEqual(outward(known));
  });
});

// ─── Weak OTP ────────────────────────────────────────────────────────────────

describe("V6: OTP generation", () => {
  it("generateOtp() does not use Math.random()", () => {
    const spy = jest.spyOn(Math, "random").mockReturnValue(0.5);

    const otp = generateOtp();

    // With Math.random pinned to 0.5, a Math.random-based OTP is always "550000"
    expect({ mathRandomCalls: spy.mock.calls.length, otp }).toEqual({
      mathRandomCalls: 0,
      otp: expect.not.stringMatching(/^550000$/),
    });
  });

  it("positive control: generateOtp() always returns a six-digit code", () => {
    for (let i = 0; i < 1000; i++) {
      expect(generateOtp()).toMatch(/^\d{6}$/);
    }
  });
});
