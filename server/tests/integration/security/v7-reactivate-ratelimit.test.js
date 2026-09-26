/**
 * V7 – Missing rate limiting on account reactivation
 * (CWE-307 Improper Restriction of Excessive Authentication Attempts;
 *  OWASP A07:2021)
 *
 * POST /api/auth/reactivate checks a password with bcrypt, like /login, so it
 * can be used to guess passwords. The security tests send repeated
 * wrong-password requests and expect the dedicated reactivation limiter
 * (5 requests per 15 minutes per IP) to answer 429. /login, which has its own
 * limiter, is the control.
 *
 * Every scenario uses its own client IP (X-Forwarded-For with trust proxy 1),
 * so the per-IP in-memory rate-limit counters cannot leak from one scenario
 * into another.
 *
 * MongoDB is in-memory with synthetic users; no external service is used.
 */
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");

const User = require("../../../models/User");
const Patient = require("../../../models/Patient");
const authRoutes = require("../../../routes/authRoutes");
const patientRoutes = require("../../../routes/patientRoutes");

const TARGET_EMAIL = "target.patient@v7.test";
const CONTROL_EMAIL = "control.patient@v7.test";
const LEGIT_EMAIL = "legit.patient@v7.test";
const UNKNOWN_EMAIL = "nobody@v7.test";
const PASSWORD = "Correct#Pass1";
const WRONG_PASSWORD = "Wrong#Pass1";

const REACTIVATE_LIMIT = 5;
const ATTEMPTS = 10;
const LOGIN_LIMIT = 30;
const LIMITED_BODY = { message: "Too many reactivation attempts, try again later" };

const IP = {
  reactivateAttack: "203.0.113.10",
  blockedCorrectPassword: "203.0.113.11",
  v6Responses: "203.0.113.12",
  loginControl: "203.0.113.20",
  legitimate: "203.0.113.30",
};

let mongoServer, app;

const makePatient = async (email, fields, n) => {
  const user = await User.create({
    role: "patient",
    email,
    fullName: `Patient ${n}`,
    passwordHash: await bcrypt.hash(PASSWORD, 10),
    isVerified: true,
    ...fields,
  });
  await Patient.create({ userId: user._id, patientId: `PAT-V7000${n}`, fullName: `Patient ${n}` });
  return user;
};

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "test-refresh-secret";

  // Mounted as in server.js; one trusted proxy hop so each scenario can set its client IP
  app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use("/api/auth", authRoutes);
  app.use("/api/patients", patientRoutes);

  // Self-deactivated patient, as left by PATCH /api/patients/me/deactivate
  await makePatient(TARGET_EMAIL, { isActive: false, status: "SUSPENDED" }, 1);
  await makePatient(CONTROL_EMAIL, {}, 2);
  await makePatient(LEGIT_EMAIL, {}, 3);
}, 30000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

const post = (ip, url, body) => request(app).post(url).set("X-Forwarded-For", ip).send(body);

// Sends the same request n times and returns the responses in order
const repeat = async (n, ip, url, body) => {
  const responses = [];
  for (let i = 0; i < n; i++) responses.push(await post(ip, url, body));
  return responses;
};

// "401 x5, 429 x5" style summary of a status sequence
const summarize = (statuses) =>
  statuses
    .reduce((runs, s) => {
      const last = runs.at(-1);
      if (last && last.status === s) last.count++;
      else runs.push({ status: s, count: 1 });
      return runs;
    }, [])
    .map((r) => `${r.status} x${r.count}`)
    .join(", ");

// ─── Security expectation ────────────────────────────────────────────────────

describe("V7: /reactivate brute-force protection", () => {
  it(`repeated wrong-password POST /api/auth/reactivate is eventually answered with 429 (within ${ATTEMPTS} attempts)`, async () => {
    const responses = await repeat(ATTEMPTS, IP.reactivateAttack, "/api/auth/reactivate", {
      identifier: TARGET_EMAIL,
      password: WRONG_PASSWORD,
    });
    const statuses = responses.map((r) => r.status);
    console.log(`/reactivate status sequence (${ATTEMPTS} wrong-password requests): ${summarize(statuses)}`);
    console.log(`/reactivate statuses in order: ${statuses.join(" ")}`);

    expect(statuses).toContain(429);

    // First REACTIVATE_LIMIT answers are normal wrong-password 401s, every later one is 429
    expect(statuses).toEqual([
      ...Array(REACTIVATE_LIMIT).fill(401),
      ...Array(ATTEMPTS - REACTIVATE_LIMIT).fill(429),
    ]);

    // Generic JSON message and standard (not legacy) rate-limit headers
    const limited = responses[REACTIVATE_LIMIT];
    expect(limited.body).toEqual(LIMITED_BODY);
    expect(limited.headers["ratelimit-policy"]).toBeDefined();
    expect(limited.headers["ratelimit"]).toBeDefined();
    expect(limited.headers["x-ratelimit-limit"]).toBeUndefined();

    // The account was never reactivated by guessing
    expect((await User.findOne({ email: TARGET_EMAIL })).isActive).toBe(false);
  }, 60000);

  it("once limited, even the correct password is blocked and the account stays deactivated", async () => {
    const ip = IP.blockedCorrectPassword;
    await repeat(REACTIVATE_LIMIT, ip, "/api/auth/reactivate", { identifier: TARGET_EMAIL, password: WRONG_PASSWORD });

    const res = await post(ip, "/api/auth/reactivate", { identifier: TARGET_EMAIL, password: PASSWORD });

    expect(res.status).toBe(429);
    expect(res.body).toEqual(LIMITED_BODY);
    expect((await User.findOne({ email: TARGET_EMAIL })).isActive).toBe(false);
  });

  it("V6 still holds before the limit: known + wrong password and unknown account both get 401 'Invalid credentials'", async () => {
    const ip = IP.v6Responses;
    const known = await post(ip, "/api/auth/reactivate", { identifier: TARGET_EMAIL, password: WRONG_PASSWORD });
    const unknown = await post(ip, "/api/auth/reactivate", { identifier: UNKNOWN_EMAIL, password: WRONG_PASSWORD });

    expect({ status: known.status, body: known.body }).toEqual({ status: 401, body: { message: "Invalid credentials" } });
    expect({ status: unknown.status, body: unknown.body }).toEqual({ status: 401, body: { message: "Invalid credentials" } });
  });
});

// ─── Control: the existing /login limiter ────────────────────────────────────

describe("V7 control: /login is already rate-limited", () => {
  it(`POST /api/auth/login returns 429 after ${LOGIN_LIMIT} wrong-password attempts`, async () => {
    const responses = await repeat(LOGIN_LIMIT + 1, IP.loginControl, "/api/auth/login", {
      identifier: CONTROL_EMAIL,
      password: WRONG_PASSWORD,
    });
    const statuses = responses.map((r) => r.status);
    console.log(`/login status sequence (${LOGIN_LIMIT + 1} wrong-password requests): ${summarize(statuses)}`);

    expect(statuses.slice(0, LOGIN_LIMIT)).toEqual(Array(LOGIN_LIMIT).fill(401));
    expect(statuses[LOGIN_LIMIT]).toBe(429);
    expect(responses[LOGIN_LIMIT].body).toEqual({ message: "Too many attempts, try again later" });
  }, 60000);
});

// ─── Positive: legitimate reactivation ───────────────────────────────────────

describe("V7 positive: legitimate reactivation still works", () => {
  it("a self-deactivated patient reactivates with the correct password and can log in again", async () => {
    const ip = IP.legitimate;

    const firstLogin = await post(ip, "/api/auth/login", { identifier: LEGIT_EMAIL, password: PASSWORD });
    expect(firstLogin.status).toBe(200);

    const deactivate = await request(app)
      .patch("/api/patients/me/deactivate")
      .set("X-Forwarded-For", ip)
      .set("Authorization", `Bearer ${firstLogin.body.accessToken}`);
    expect(deactivate.status).toBe(200);

    const blocked = await post(ip, "/api/auth/login", { identifier: LEGIT_EMAIL, password: PASSWORD });
    expect(blocked.status).toBe(403);
    expect(blocked.body.message).toBe("Account is deactivated");

    const reactivate = await post(ip, "/api/auth/reactivate", { identifier: LEGIT_EMAIL, password: PASSWORD });
    expect(reactivate.status).toBe(200);
    expect(reactivate.body.message).toBe("Account reactivated successfully");

    const user = await User.findOne({ email: LEGIT_EMAIL });
    expect(user.isActive).toBe(true);
    expect(user.status).toBe("ACTIVE");
    expect((await Patient.findOne({ userId: user._id })).isDeleted).toBe(false);

    const loginAgain = await post(ip, "/api/auth/login", { identifier: LEGIT_EMAIL, password: PASSWORD });
    expect(loginAgain.status).toBe(200);
    expect(loginAgain.body.accessToken).toBeDefined();
  });
});
