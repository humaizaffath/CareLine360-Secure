/**
 * Google OpenID Connect sign-in (Authorization Code + PKCE) – backend
 * (OWASP A07:2021 Identification and Authentication Failures; CWE-287,
 *  CWE-346, CWE-269)
 *
 * Only Google's network edges are replaced:
 *  - OAuth2Client.getToken (the code exchange) returns a locally signed ID token
 *  - OAuth2Client.getFederatedSignonCertsAsync (Google's public keys) returns
 *    the matching test public key
 * google-auth-library's real verifyIdToken still checks signature, issuer,
 * audience and expiry; the service checks email_verified and nonce.
 *
 * Each request uses its own client IP so the shared in-memory authLimiter never
 * interferes. MongoDB is in-memory with synthetic users; nothing reaches Google.
 */
const crypto = require("crypto");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const User = require("../../../models/User");
const Patient = require("../../../models/Patient");
const authRoutes = require("../../../routes/authRoutes");

const CLIENT_ID = "careline-test.apps.googleusercontent.com";
const CLIENT_SECRET = "test-google-client-secret-DO-NOT-LEAK";
const REDIRECT_URI = "http://localhost:5173/auth/google/callback";
const KID = "test-signing-key";
const NONCE = "n0nce-Value-For-Test-1234567890";
const CODE = "4/0Atest-authorization-code";
const GOOGLE_ACCESS_TOKEN = "ya29.test-google-access-token";
const PASSWORD = "Correct#Pass1";

const googleKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const attackerKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = (key) => key.export({ type: "pkcs1", format: "pem" });

let mongoServer, app, getTokenSpy;
let ipCounter = 0;
const logs = [];

// ─── Helpers ─────────────────────────────────────────────────────────────────

const verifier = () => crypto.randomBytes(32).toString("base64url"); // 43 chars

const signIdToken = (overrides = {}, { privateKey = googleKeys.privateKey } = {}) => {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    sub: "google-sub-default",
    email: "default@gmail.test",
    email_verified: true,
    name: "Google User",
    nonce: NONCE,
    iat: now,
    exp: now + 3600,
    ...overrides,
  };
  for (const key of Object.keys(claims)) if (claims[key] === undefined) delete claims[key];
  return jwt.sign(claims, pem(privateKey), { algorithm: "RS256", keyid: KID });
};

// What Google's token endpoint returns for this test
const googleReturns = (claims, options) => {
  getTokenSpy.mockResolvedValue({
    tokens: { id_token: signIdToken(claims, options), access_token: GOOGLE_ACCESS_TOKEN, token_type: "Bearer" },
    res: null,
  });
};

const googleRejects = (error) => {
  const err = new Error(`request failed: ${error}`);
  err.response = { status: 400, data: { error, error_description: "Bad Request" } };
  getTokenSpy.mockRejectedValue(err);
};

const signIn = (body = {}) =>
  request(app)
    .post("/api/auth/oauth/google")
    .set("X-Forwarded-For", `198.51.100.${++ipCounter % 250}`)
    .send({ code: CODE, codeVerifier: verifier(), redirectUri: REDIRECT_URI, nonce: NONCE, ...body });

const call = (method, url) => request(app)[method](url).set("X-Forwarded-For", `192.0.2.${++ipCounter % 250}`);

const makeUser = async (fields) =>
  User.create({
    fullName: "Local User",
    passwordHash: await bcrypt.hash(PASSWORD, 10),
    isVerified: true,
    ...fields,
  });

const snapshot = async (id) => {
  const u = await User.findById(id).lean();
  return { googleSub: u.googleSub, passwordHash: u.passwordHash, isVerified: u.isVerified, refreshTokenHash: u.refreshTokenHash, status: u.status, isActive: u.isActive, role: u.role };
};

const expectNoSession = (res) => {
  expect(res.body.accessToken).toBeUndefined();
  expect(res.body.refreshToken).toBeUndefined();
};

// ─── Setup ───────────────────────────────────────────────────────────────────

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  await User.init(); // build unique indexes (email, phone, googleSub)

  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";
  process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "test-refresh-secret";
  process.env.GOOGLE_CLIENT_ID = CLIENT_ID;
  process.env.GOOGLE_CLIENT_SECRET = CLIENT_SECRET;
  process.env.GOOGLE_REDIRECT_URIS = `${REDIRECT_URI}, https://careline360.example/auth/google/callback`;

  app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use("/api/auth", authRoutes);
}, 30000);

beforeEach(() => {
  // jest.config restoreMocks resets spies before every test, so set them per test
  getTokenSpy = jest.spyOn(OAuth2Client.prototype, "getToken");
  googleReturns({});
  jest
    .spyOn(OAuth2Client.prototype, "getFederatedSignonCertsAsync")
    .mockResolvedValue({ certs: { [KID]: pem(googleKeys.publicKey) }, format: "PEM" });

  for (const level of ["log", "info", "warn", "error"]) {
    jest.spyOn(console, level).mockImplementation((...args) => logs.push(args.map(String).join(" ")));
  }
});

afterEach(async () => {
  await Promise.all([User.deleteMany({}), Patient.deleteMany({})]);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// ─── O-1 New Google user ─────────────────────────────────────────────────────

describe("O-1 new Google user", () => {
  it("creates one ACTIVE, verified patient with a Patient profile and returns a CareLine session", async () => {
    googleReturns({ sub: "sub-new-1", email: "New.Patient@Gmail.test", name: "New Patient" });

    const res = await signIn();

    expect(res.status).toBe(200);
    expect(Object.keys(res.body).sort()).toEqual(["accessToken", "message", "refreshToken", "user"]);
    expect(res.body.user).toMatchObject({ role: "patient", email: "new.patient@gmail.test", fullName: "New Patient", isVerified: true });

    const users = await User.find({});
    expect(users).toHaveLength(1);
    expect(users[0]).toMatchObject({ role: "patient", status: "ACTIVE", isActive: true, isVerified: true, googleSub: "sub-new-1" });

    const profiles = await Patient.find({ userId: users[0]._id });
    expect(profiles).toHaveLength(1);
    expect(profiles[0].patientId).toMatch(/^PAT-\d{6}$/);
    expect(profiles[0].fullName).toBe("New Patient");

    // The access token is a normal CareLine token
    const me = await call("get", "/api/auth/me").set("Authorization", `Bearer ${res.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user).toMatchObject({ role: "patient", status: "ACTIVE" });
  });

  it("exchanges the code server-side with the PKCE verifier and the allowlisted redirect URI", async () => {
    const codeVerifier = verifier();

    await signIn({ codeVerifier });

    expect(getTokenSpy).toHaveBeenCalledTimes(1);
    expect(getTokenSpy).toHaveBeenCalledWith({ code: CODE, codeVerifier, redirect_uri: REDIRECT_URI });
  });

  it("signing in again with the same Google account reuses the user and profile", async () => {
    googleReturns({ sub: "sub-repeat", email: "repeat@gmail.test" });

    const first = await signIn();
    const second = await signIn();

    expect(second.status).toBe(200);
    expect(second.body.user.id).toBe(first.body.user.id);
    expect(await User.countDocuments({})).toBe(1);
    expect(await Patient.countDocuments({})).toBe(1);
  });

  it("falls back to the email name when Google sends no name", async () => {
    googleReturns({ sub: "sub-noname", email: "jane.doe@gmail.test", name: undefined });

    const res = await signIn();

    expect(res.status).toBe(200);
    expect(res.body.user.fullName).toBe("jane.doe");
  });
});

// ─── O-2 Existing verified local patient ─────────────────────────────────────

describe("O-2 existing verified local patient", () => {
  it("links the Google account to the same user and keeps the local password working", async () => {
    const local = await makeUser({ role: "patient", email: "verified@gmail.test" });
    const before = await snapshot(local._id);
    googleReturns({ sub: "sub-verified", email: "verified@gmail.test" });

    const res = await signIn();

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(String(local._id));
    expect(await User.countDocuments({})).toBe(1);

    const after = await snapshot(local._id);
    expect(after.googleSub).toBe("sub-verified");
    expect(after.passwordHash).toBe(before.passwordHash);

    const login = await call("post", "/api/auth/login").send({ identifier: "verified@gmail.test", password: PASSWORD });
    expect(login.status).toBe(200);
  });
});

// ─── O-3 Refresh with an OAuth-issued refresh token ──────────────────────────

describe("O-3 OAuth-issued refresh token", () => {
  it("works with /auth/refresh and stops working after logout", async () => {
    googleReturns({ sub: "sub-refresh", email: "refresh@gmail.test" });
    const { body } = await signIn();

    const refreshed = await call("post", "/api/auth/refresh").send({ refreshToken: body.refreshToken });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.accessToken).toBeDefined();

    const logout = await call("post", "/api/auth/logout").set("Authorization", `Bearer ${body.accessToken}`);
    expect(logout.status).toBe(200);

    const afterLogout = await call("post", "/api/auth/refresh").send({ refreshToken: body.refreshToken });
    expect(afterLogout.status).toBe(401);
  });
});

// ─── O-5 Code exchange failure ───────────────────────────────────────────────

describe("O-5 code exchange failure (wrong PKCE verifier, replayed or expired code)", () => {
  it.each(["invalid_grant", "invalid_request", "unauthorized_client"])(
    "Google answering %s gives a generic 401 and creates nothing",
    async (error) => {
      googleRejects(error);

      const res = await signIn();

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ message: "Google sign-in failed" });
      expectNoSession(res);
      expect(await User.countDocuments({})).toBe(0);
    }
  );

  it("a token response without an ID token gives a generic 401", async () => {
    getTokenSpy.mockResolvedValue({ tokens: { access_token: GOOGLE_ACCESS_TOKEN }, res: null });

    const res = await signIn();

    expect(res.status).toBe(401);
    expect(await User.countDocuments({})).toBe(0);
  });
});

// ─── O-6 Invalid ID token ────────────────────────────────────────────────────

describe("O-6 invalid ID token", () => {
  const now = () => Math.floor(Date.now() / 1000);

  it.each([
    ["wrong audience", { aud: "someone-else.apps.googleusercontent.com" }],
    ["wrong issuer", { iss: "https://evil.example" }],
    ["expired", { iat: now() - 7200, exp: now() - 3600 }],
    ["email_verified false", { email_verified: false }],
    ["email_verified missing", { email_verified: undefined }],
    ["email_verified as the string 'true'", { email_verified: "true" }],
    ["nonce mismatch", { nonce: "a-different-nonce-from-another-login" }],
    ["nonce missing", { nonce: undefined }],
    ["no email", { email: undefined }],
  ])("%s → 401, nothing created", async (_label, claims) => {
    googleReturns({ sub: "sub-invalid", email: "invalid@gmail.test", ...claims });

    const res = await signIn();

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: "Google sign-in failed" });
    expectNoSession(res);
    expect(await User.countDocuments({})).toBe(0);
  });

  it("signature from a key that is not Google's → 401, nothing created", async () => {
    googleReturns({ sub: "sub-forged", email: "forged@gmail.test" }, { privateKey: attackerKeys.privateKey });

    const res = await signIn();

    expect(res.status).toBe(401);
    expect(await User.countDocuments({})).toBe(0);
  });

  it("the nonce is checked against the one sent by this browser", async () => {
    googleReturns({ sub: "sub-nonce", email: "nonce@gmail.test", nonce: NONCE });

    const res = await signIn({ nonce: "another-browser-session-nonce-123" });

    expect(res.status).toBe(401);
  });
});

// ─── O-7 Account state ───────────────────────────────────────────────────────

describe("O-7 Google sign-in does not bypass account state", () => {
  it.each([
    ["deactivated (isActive=false)", { isActive: false, status: "SUSPENDED" }, "Account is deactivated"],
    ["PENDING", { status: "PENDING" }, "Account is not active. Please contact admin."],
    ["REJECTED", { status: "REJECTED" }, "Account is not active. Please contact admin."],
    ["SUSPENDED", { status: "SUSPENDED" }, "Account is not active. Please contact admin."],
  ])("existing %s patient → 403, not linked, not modified", async (_label, state, message) => {
    const local = await makeUser({ role: "patient", email: "blocked@gmail.test", isVerified: false, ...state });
    const before = await snapshot(local._id);
    googleReturns({ sub: "sub-blocked", email: "blocked@gmail.test" });

    const res = await signIn();

    expect(res.status).toBe(403);
    expect(res.body.message).toBe(message);
    expectNoSession(res);
    expect(await snapshot(local._id)).toEqual(before);
  });

  it("an already-linked patient who is later suspended → 403", async () => {
    await makeUser({ role: "patient", email: "linked@gmail.test", googleSub: "sub-linked", status: "SUSPENDED" });
    googleReturns({ sub: "sub-linked", email: "linked@gmail.test" });

    const res = await signIn();

    expect(res.status).toBe(403);
    expectNoSession(res);
  });
});

// ─── O-8 Safe linking and role security ──────────────────────────────────────

describe("O-8 safe linking and role security", () => {
  it("email already linked to a different Google account → 409, nothing changed", async () => {
    const local = await makeUser({ role: "patient", email: "taken@gmail.test", googleSub: "sub-original" });
    const before = await snapshot(local._id);
    googleReturns({ sub: "sub-intruder", email: "taken@gmail.test" });

    const res = await signIn();

    expect(res.status).toBe(409);
    expectNoSession(res);
    expect(await snapshot(local._id)).toEqual(before);
  });

  it("unverified local patient: linked, marked verified, old password and old session invalidated", async () => {
    // Someone registered this email without proving they own it, and has a session
    const local = await makeUser({ role: "patient", email: "prehijack@gmail.test", isVerified: false });
    const oldLogin = await call("post", "/api/auth/login").send({ identifier: "prehijack@gmail.test", password: PASSWORD });
    expect(oldLogin.status).toBe(200);
    googleReturns({ sub: "sub-real-owner", email: "prehijack@gmail.test" });

    const res = await signIn();

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(String(local._id));
    expect(await User.countDocuments({})).toBe(1);
    const after = await User.findById(local._id);
    expect(after).toMatchObject({ googleSub: "sub-real-owner", isVerified: true });

    const passwordLogin = await call("post", "/api/auth/login").send({ identifier: "prehijack@gmail.test", password: PASSWORD });
    expect(passwordLogin.status).toBe(401);

    const oldRefresh = await call("post", "/api/auth/refresh").send({ refreshToken: oldLogin.body.refreshToken });
    expect(oldRefresh.status).toBe(401);

    const newRefresh = await call("post", "/api/auth/refresh").send({ refreshToken: res.body.refreshToken });
    expect(newRefresh.status).toBe(200);
  });

  it("session integrity: a new login ends the previous refresh session (bcrypt 72-byte prefix)", async () => {
    await makeUser({ role: "patient", email: "twosessions@gmail.test" });
    const login = () => call("post", "/api/auth/login").send({ identifier: "twosessions@gmail.test", password: PASSWORD });

    const first = await login();
    const second = await login();

    expect(first.body.refreshToken).not.toBe(second.body.refreshToken);
    expect((await call("post", "/api/auth/refresh").send({ refreshToken: first.body.refreshToken })).status).toBe(401);
    expect((await call("post", "/api/auth/refresh").send({ refreshToken: second.body.refreshToken })).status).toBe(200);
  });

  it("role, email and name in the request body are ignored", async () => {
    googleReturns({ sub: "sub-escalate", email: "escalate@gmail.test", name: "Real Name" });

    const res = await signIn({ role: "admin", email: "admin@careline.test", name: "Admin", status: "ACTIVE" });

    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ role: "patient", email: "escalate@gmail.test", fullName: "Real Name" });
    expect(await User.countDocuments({ role: { $ne: "patient" } })).toBe(0);
  });

  it.each(["doctor", "admin", "responder"])(
    "existing %s with the same email → 403, not linked, not modified",
    async (role) => {
      const local = await makeUser({ role, email: `${role}@careline.test` });
      const before = await snapshot(local._id);
      googleReturns({ sub: `sub-${role}`, email: `${role}@careline.test` });

      const res = await signIn();

      expect(res.status).toBe(403);
      expect(res.body.message).toBe("Google sign-in is only available for patient accounts");
      expectNoSession(res);
      expect(await snapshot(local._id)).toEqual(before);
    }
  );

  it("a non-patient account that somehow has a googleSub still cannot sign in with Google", async () => {
    await makeUser({ role: "admin", email: "linked.admin@careline.test", googleSub: "sub-admin-linked" });
    googleReturns({ sub: "sub-admin-linked", email: "linked.admin@careline.test" });

    const res = await signIn();

    expect(res.status).toBe(403);
    expectNoSession(res);
  });
});

// ─── O-10 Input validation ───────────────────────────────────────────────────

describe("O-10 request validation", () => {
  it.each([
    ["missing code", { code: undefined }],
    ["empty code", { code: "" }],
    ["code not a string", { code: { $gt: "" } }],
    ["codeVerifier too short", { codeVerifier: "short" }],
    ["codeVerifier with invalid characters", { codeVerifier: `${"a".repeat(42)}!` }],
    ["codeVerifier too long", { codeVerifier: "a".repeat(129) }],
    ["missing redirectUri", { redirectUri: undefined }],
    ["missing nonce", { nonce: undefined }],
    ["nonce too short", { nonce: "short" }],
  ])("%s → 400 and Google is not called", async (_label, body) => {
    const res = await signIn(body);

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Invalid Google sign-in request");
    expect(JSON.stringify(res.body)).not.toContain(CODE);
    expect(getTokenSpy).not.toHaveBeenCalled();
  });

  it.each([
    ["an unlisted origin", "https://evil.example/auth/google/callback"],
    ["a prefix of an allowed URI", "http://localhost:5173/auth/google"],
    ["an allowed URI with extra path", `${REDIRECT_URI}/extra`],
    ["an allowed URI with a query", `${REDIRECT_URI}?next=/admin`],
  ])("redirectUri that is %s → 400 and Google is not called", async (_label, redirectUri) => {
    const res = await signIn({ redirectUri });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: "Redirect URI not allowed" });
    expect(getTokenSpy).not.toHaveBeenCalled();
  });

  it("the second configured redirect URI is accepted", async () => {
    const res = await signIn({ redirectUri: "https://careline360.example/auth/google/callback" });

    expect(res.status).toBe(200);
  });
});

// ─── O-9 (backend part) Nothing from Google leaks ────────────────────────────

describe("O-9 backend: no Google secret, code or token leaks", () => {
  it("responses and stored users never contain Google tokens or the client secret", async () => {
    googleReturns({ sub: "sub-leak", email: "leak@gmail.test" });
    const idToken = signIdToken({ sub: "sub-leak", email: "leak@gmail.test" });

    const res = await signIn();
    const stored = JSON.stringify(await User.find({}).lean());

    for (const secret of [CLIENT_SECRET, GOOGLE_ACCESS_TOKEN, CODE, idToken.split(".")[2]]) {
      expect(JSON.stringify(res.body)).not.toContain(secret);
      expect(stored).not.toContain(secret);
    }
  });

  it("nothing logged during this whole file contains the secret, the code or a Google token", () => {
    const logged = logs.join("\n");

    expect(logged).toContain("Google sign-in rejected: invalid_grant"); // the rejections were logged
    for (const secret of [CLIENT_SECRET, GOOGLE_ACCESS_TOKEN, CODE, "eyJ"]) {
      expect(logged).not.toContain(secret);
    }
  });
});
