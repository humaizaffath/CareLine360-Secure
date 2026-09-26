const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const Patient = require("../models/Patient");
const { getNextPatientId, accountStateError, issueSession } = require("./authService");

// Google sign-in: OpenID Connect Authorization Code flow with PKCE (S256).
// The browser sends the authorization code and its PKCE verifier; the code is
// exchanged here with the client secret, the ID token is verified, and the
// CareLine360 user is found, linked or created. Google sign-in is for patient
// accounts only and never bypasses the account-state rules of password login.

const SIGN_IN_FAILED = { status: 401, data: { message: "Google sign-in failed" } };
const NOT_CONFIGURED = { status: 503, data: { message: "Google sign-in is not available" } };
const REDIRECT_NOT_ALLOWED = { status: 400, data: { message: "Redirect URI not allowed" } };
const PATIENTS_ONLY = { status: 403, data: { message: "Google sign-in is only available for patient accounts" } };
const LINKED_TO_OTHER_GOOGLE = { status: 409, data: { message: "This account is linked to a different Google account" } };

const allowedRedirectUris = () =>
  (process.env.GOOGLE_REDIRECT_URIS || "")
    .split(",")
    .map((uri) => uri.trim())
    .filter(Boolean);

// One client per configuration so Google's signing certificates stay cached
let cachedClient = null;
const getClient = () => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;

  if (!cachedClient || cachedClient.clientId !== clientId || cachedClient.clientSecret !== clientSecret) {
    cachedClient = { clientId, clientSecret, oauth: new OAuth2Client({ clientId, clientSecret }) };
  }
  return cachedClient;
};

// Only a short OAuth error code (e.g. "invalid_grant") is ever logged: library
// error messages can contain the full ID token.
const safeErrorCode = (e) => {
  const code = e?.response?.data?.error;
  return typeof code === "string" && /^[a-z_]{1,64}$/.test(code) ? code : "verification_failed";
};

// Exchanges the code (with the PKCE verifier) and verifies the ID token.
// Returns the verified identity, or null if anything does not check out.
const verifyGoogleIdentity = async (client, { code, codeVerifier, redirectUri, nonce }) => {
  try {
    const { tokens } = await client.oauth.getToken({ code, codeVerifier, redirect_uri: redirectUri });
    if (!tokens?.id_token) return null;

    // Checks signature (Google's published keys), issuer, audience and expiry
    const ticket = await client.oauth.verifyIdToken({ idToken: tokens.id_token, audience: client.clientId });
    const claims = ticket.getPayload();

    if (claims?.email_verified !== true) return null;
    if (typeof claims.nonce !== "string" || claims.nonce !== nonce) return null;
    if (typeof claims.sub !== "string" || !claims.sub || typeof claims.email !== "string" || !claims.email) return null;

    return { sub: claims.sub, email: claims.email.trim().toLowerCase(), name: claims.name };
  } catch (e) {
    console.warn("Google sign-in rejected:", safeErrorCode(e));
    return null;
  }
};

// bcrypt hash of a random value nobody knows: the account has no usable local password
const unusablePasswordHash = () => bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10);

const displayName = ({ name, email }) => {
  const clean = typeof name === "string" ? name.trim().slice(0, 100) : "";
  return clean || email.split("@")[0];
};

// A. Already linked to this Google account
const signInLinkedUser = async (user) => {
  if (user.role !== "patient") return PATIENTS_ONLY;

  const blocked = accountStateError(user);
  if (blocked) return blocked;

  return issueSession(user);
};

// B. Local account with the same verified email: link it, never modify an ineligible account
const linkExistingUser = async (user, identity) => {
  if (user.role !== "patient") return PATIENTS_ONLY;
  if (user.googleSub && user.googleSub !== identity.sub) return LINKED_TO_OTHER_GOOGLE;

  const blocked = accountStateError(user);
  if (blocked) return blocked;

  user.googleSub = identity.sub;

  if (!user.isVerified) {
    // Nobody proved ownership of this email before: whoever registered it may
    // not be its owner, so their password and sessions stop working.
    user.isVerified = true;
    user.passwordHash = await unusablePasswordHash();
    user.refreshTokenHash = undefined;
  }

  return issueSession(user);
};

// C. New Google user: always a patient
const createGoogleUser = async (identity) => {
  const fullName = displayName(identity);

  const user = await User.create({
    role: "patient",
    status: "ACTIVE",
    isActive: true,
    isVerified: true,
    googleSub: identity.sub,
    email: identity.email,
    fullName,
    passwordHash: await unusablePasswordHash(),
  });

  try {
    const patientId = await getNextPatientId();
    await Patient.create({ userId: user._id, patientId, fullName });
  } catch (e) {
    await User.deleteOne({ _id: user._id });
    throw e;
  }

  return issueSession(user);
};

const mapGoogleIdentity = async (identity) => {
  const linked = await User.findOne({ googleSub: identity.sub });
  if (linked) return signInLinkedUser(linked);

  const existing = await User.findOne({ email: identity.email });
  if (existing) return linkExistingUser(existing, identity);

  return createGoogleUser(identity);
};

const signInWithGoogle = async ({ code, codeVerifier, redirectUri, nonce }) => {
  if (!allowedRedirectUris().includes(redirectUri)) return REDIRECT_NOT_ALLOWED;

  const client = getClient();
  if (!client) return NOT_CONFIGURED;

  const identity = await verifyGoogleIdentity(client, { code, codeVerifier, redirectUri, nonce });
  if (!identity) return SIGN_IN_FAILED;

  try {
    return await mapGoogleIdentity(identity);
  } catch (e) {
    // Two first sign-ins racing on the same googleSub/email: the unique index
    // rejects the second write, which then finds the first one's user
    if (e?.code === 11000) return mapGoogleIdentity(identity);
    throw e;
  }
};

module.exports = { signInWithGoogle };
