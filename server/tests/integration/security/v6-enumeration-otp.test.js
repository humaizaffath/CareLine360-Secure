/**
 * V6 – User enumeration and weak OTP
 * (CWE-203 Observable Discrepancy, CWE-204 Observable Response Discrepancy,
 *  CWE-338 Use of Cryptographically Weak PRNG; OWASP A07:2021)
 *
 * Enumeration tests send the same request for a known and an unknown account
 * and expect the outward response (status + body) to be identical. OTP tests
 * expect generateOtp() to use a CSPRNG and keep producing six-digit codes.
 * Positive tests check that the real reset / verify / login flows still work.
 *
 * Email is mocked and MongoDB is in-memory: no real email, no shared database.
 */
const crypto = require("crypto");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");

jest.mock("../../../services/emailService", () => ({ sendEmail: jest.fn() }));

const { sendEmail } = require("../../../services/emailService");
const User = require("../../../models/User");
const Patient = require("../../../models/Patient");
const Otp = require("../../../models/Otp");
const authRoutes = require("../../../routes/authRoutes");
const { generateOtp, hashOtp } = require("../../../utils/otp");

const ACTIVE_EMAIL = "active.patient@v6.test";
const UNVERIFIED_EMAIL = "unverified.patient@v6.test";
const DEACTIVATED_EMAIL = "deactivated.patient@v6.test";
const RESET_EMAIL = "reset.patient@v6.test";
const UNKNOWN_EMAIL = "nobody@v6.test";
const PASSWORD = "Correct#Pass1";
const WRONG_PASSWORD = "Wrong#Pass1";
const NEW_PASSWORD = "Brand#NewPass2";

let mongoServer, app;

const makePatient = async (email, fields, n) => {
  const user = await User.create({
    role: "patient",
    email,
    fullName: `Patient ${n}`,
    passwordHash: await bcrypt.hash(PASSWORD, 10),
    ...fields,
  });
  await Patient.create({ userId: user._id, patientId: `PAT-V6000${n}`, fullName: `Patient ${n}` });
  return user;
};

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "test-refresh-secret";

  // Mounted as in server.js
  app = express();
  app.use(express.json());
  app.use("/api/auth", authRoutes);

  await makePatient(ACTIVE_EMAIL, { isVerified: true }, 1);
  await makePatient(UNVERIFIED_EMAIL, { isVerified: false }, 2);
  // Self-deactivated patient: the account state /reactivate is meant for
  await makePatient(DEACTIVATED_EMAIL, { isVerified: true, isActive: false, status: "SUSPENDED" }, 3);
  await makePatient(RESET_EMAIL, { isVerified: true }, 4);
}, 30000);

afterEach(async () => {
  await Otp.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

const post = (url, body) => request(app).post(`/api/auth${url}`).send(body);

// Status and body are what an attacker can observe
const outward = (res) => ({ status: res.status, body: res.body });

// The OTP is only delivered by email; read it from the mocked sendEmail call
const otpFromLastEmail = () => sendEmail.mock.calls.at(-1)[0].html.match(/>(\d{6})</)[1];

// ─── Account enumeration ─────────────────────────────────────────────────────

describe("V6: account enumeration", () => {
  it("POST /password/forgot answers the same for known and unknown accounts", async () => {
    const known = await post("/password/forgot", { identifier: ACTIVE_EMAIL });
    const unknown = await post("/password/forgot", { identifier: UNKNOWN_EMAIL });

    expect(outward(unknown)).toEqual(outward(known));
  });

  it("POST /reactivate answers the same 401 for a known account with a wrong password and an unknown account", async () => {
    const known = await post("/reactivate", { identifier: DEACTIVATED_EMAIL, password: WRONG_PASSWORD });
    const unknown = await post("/reactivate", { identifier: UNKNOWN_EMAIL, password: WRONG_PASSWORD });

    expect(outward(unknown)).toEqual(outward(known));
    expect(unknown.status).toBe(401);
    expect(unknown.body.message).toBe("Invalid credentials");
  });

  it("POST /password/reset for an unknown account does not reveal 'User not found'", async () => {
    const body = { otp: "123456", newPassword: NEW_PASSWORD };
    const known = await post("/password/reset", { identifier: ACTIVE_EMAIL, ...body });
    const unknown = await post("/password/reset", { identifier: UNKNOWN_EMAIL, ...body });

    expect(unknown.body.message).not.toMatch(/user not found/i);
    expect(outward(unknown)).toEqual(outward(known));
  });

  it("POST /email/verify-otp for an unknown account does not reveal 'User not found'", async () => {
    const known = await post("/email/verify-otp", { identifier: UNVERIFIED_EMAIL, otp: "123456" });
    const unknown = await post("/email/verify-otp", { identifier: UNKNOWN_EMAIL, otp: "123456" });

    expect(unknown.body.message).not.toMatch(/user not found/i);
    expect(outward(unknown)).toEqual(outward(known));
  });

  it("POST /email/send-verify-otp answers the same for unknown, unverified and already-verified accounts", async () => {
    const unverified = await post("/email/send-verify-otp", { identifier: UNVERIFIED_EMAIL });
    const verified = await post("/email/send-verify-otp", { identifier: ACTIVE_EMAIL });
    const unknown = await post("/email/send-verify-otp", { identifier: UNKNOWN_EMAIL });

    expect(outward(unknown)).toEqual(outward(unverified));
    expect(outward(verified)).toEqual(outward(unverified));
  });

  it("POST /login with a wrong password returns the same 401 for a deactivated account and an unknown account", async () => {
    const deactivated = await post("/login", { identifier: DEACTIVATED_EMAIL, password: WRONG_PASSWORD });
    const unknown = await post("/login", { identifier: UNKNOWN_EMAIL, password: WRONG_PASSWORD });

    expect(deactivated.status).toBe(401);
    expect(outward(unknown)).toEqual(outward(deactivated));
  });

  it("POST /login reveals deactivation (403) only after the correct password", async () => {
    const res = await post("/login", { identifier: DEACTIVATED_EMAIL, password: PASSWORD });

    expect(res.status).toBe(403);
    expect(res.body.message).toBe("Account is deactivated");
    expect(res.body.accessToken).toBeUndefined();
  });
});

// ─── Forgot-password side effects ────────────────────────────────────────────

describe("V6: forgot-password side effects", () => {
  it("creates a hashed 10-minute OTP with attemptsLeft = 5 and emails it for an existing account", async () => {
    const before = Date.now();
    await post("/password/forgot", { identifier: ACTIVE_EMAIL });

    const user = await User.findOne({ email: ACTIVE_EMAIL });
    const records = await Otp.find({ userId: user._id, purpose: "PASSWORD_RESET" });
    expect(records).toHaveLength(1);
    expect(records[0].attemptsLeft).toBe(5);
    expect(records[0].expiresAt.getTime() - before).toBeGreaterThanOrEqual(10 * 60 * 1000 - 1000);
    expect(records[0].expiresAt.getTime() - before).toBeLessThanOrEqual(10 * 60 * 1000 + 5000);

    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(sendEmail.mock.calls[0][0].to).toBe(ACTIVE_EMAIL);
    const otp = otpFromLastEmail();
    expect(records[0].otpHash).toBe(hashOtp(otp));
    expect(records[0].otpHash).not.toBe(otp);
  });

  it("creates no OTP and sends no email for an unknown account", async () => {
    await post("/password/forgot", { identifier: UNKNOWN_EMAIL });

    expect(await Otp.countDocuments({})).toBe(0);
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it("a failing email send is handled and does not cause an unhandled rejection", async () => {
    const unhandled = jest.fn();
    process.on("unhandledRejection", unhandled);
    sendEmail.mockRejectedValueOnce(null);

    const res = await post("/password/forgot", { identifier: ACTIVE_EMAIL });
    await new Promise((resolve) => setImmediate(resolve));
    process.off("unhandledRejection", unhandled);

    expect(res.status).toBe(200);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(unhandled).not.toHaveBeenCalled();
  });
});

describe("V6: password check", () => {
  it("rejects a non-string password even when it wraps the correct one", async () => {
    const res = await post("/reactivate", { identifier: DEACTIVATED_EMAIL, password: [PASSWORD] });

    expect(res.status).toBe(401);
    expect((await User.findOne({ email: DEACTIVATED_EMAIL })).isActive).toBe(false);
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

  it("generateOtp() draws from crypto.randomInt over the full 000000-999999 range", () => {
    const spy = jest.spyOn(crypto, "randomInt");

    generateOtp();

    expect(spy).toHaveBeenCalledWith(0, 1000000);
  });

  it("positive: leading zeros are kept", () => {
    jest.spyOn(crypto, "randomInt").mockReturnValue(42);

    expect(generateOtp()).toBe("000042");
  });

  it("positive: 1000 generated OTPs all match /^\\d{6}$/", () => {
    for (let i = 0; i < 1000; i++) {
      expect(generateOtp()).toMatch(/^\d{6}$/);
    }
  });
});

// ─── Legitimate flows still work ─────────────────────────────────────────────

describe("V6: positive flows", () => {
  it("forgot password → emailed OTP → reset → login with the new password", async () => {
    await post("/password/forgot", { identifier: RESET_EMAIL });
    const otp = otpFromLastEmail();

    const reset = await post("/password/reset", { identifier: RESET_EMAIL, otp, newPassword: NEW_PASSWORD });
    expect(reset.status).toBe(200);
    expect(await Otp.countDocuments({})).toBe(0);

    const oldLogin = await post("/login", { identifier: RESET_EMAIL, password: PASSWORD });
    expect(oldLogin.status).toBe(401);

    const newLogin = await post("/login", { identifier: RESET_EMAIL, password: NEW_PASSWORD });
    expect(newLogin.status).toBe(200);
    expect(newLogin.body.accessToken).toBeDefined();
  });

  it("send verify OTP → emailed OTP → verify marks the account verified", async () => {
    await post("/email/send-verify-otp", { identifier: UNVERIFIED_EMAIL });
    const otp = otpFromLastEmail();

    const res = await post("/email/verify-otp", { identifier: UNVERIFIED_EMAIL, otp });

    expect(res.status).toBe(200);
    expect((await User.findOne({ email: UNVERIFIED_EMAIL })).isVerified).toBe(true);
  });

  it("wrong OTPs still exhaust attemptsLeft and then return 429", async () => {
    await post("/password/forgot", { identifier: ACTIVE_EMAIL });
    const otp = otpFromLastEmail();
    const wrong = otp === "000000" ? "111111" : "000000";

    const statuses = [];
    for (let i = 0; i < 6; i++) {
      const res = await post("/password/reset", { identifier: ACTIVE_EMAIL, otp: wrong, newPassword: NEW_PASSWORD });
      statuses.push(res.status);
    }

    expect(statuses).toEqual([400, 400, 400, 400, 400, 429]);
  });

  it("reactivate with the correct password restores a deactivated account, then login succeeds", async () => {
    const res = await post("/reactivate", { identifier: DEACTIVATED_EMAIL, password: PASSWORD });
    expect(res.status).toBe(200);

    const login = await post("/login", { identifier: DEACTIVATED_EMAIL, password: PASSWORD });
    expect(login.status).toBe(200);
  });
});
