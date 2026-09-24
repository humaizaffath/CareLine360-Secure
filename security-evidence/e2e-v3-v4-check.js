// V3 + V4 end-to-end check against the real server.js process (Umair).
// Usage (repo root): npm install --prefix security-evidence/V4 --no-package-lock
//                    node security-evidence/e2e-v3-v4-check.js
// Writes e2e-v3-v4-results.json next to this file.
// Synthetic users in an in-memory MongoDB; real login; real HTTP + socket.io-client.
const path = require("path");
const { spawn } = require("child_process");
const REPO = path.resolve(__dirname, "..");
const S = `${REPO}/server`;
const r = (p) => require(`${S}/${p}`);
const mongoose = r("node_modules/mongoose");
const bcrypt = r("node_modules/bcryptjs");
const { MongoMemoryServer } = r("node_modules/mongodb-memory-server");
const { io: ioc } = require(`${REPO}/security-evidence/V4/node_modules/socket.io-client`);
const User = r("models/User");
const Appointment = r("models/Appointment");
const EmergencyCase = r("models/EmergencyCase");

const PORT = 5000 + Math.floor(Math.random() * 1000);
const BASE = `http://localhost:${PORT}`;
const PW = "E2e-Passw0rd!";
const rows = [];
const check = (id, testCase, expected, actual, pass) => rows.push({ id, testCase, expected, actual, result: pass ? "PASS" : "FAIL" });
const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
const hasSecret = (body) => /"(passwordHash|refreshTokenHash)"/.test(JSON.stringify(body || {}));

async function http(method, url, token, body) {
  const res = await fetch(BASE + url, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const type = res.headers.get("content-type") || "";
  const data = type.includes("json") ? await res.json() : { _raw: type, bytes: (await res.arrayBuffer()).byteLength };
  return { status: res.status, body: data, type };
}

(async () => {
  const mongo = await MongoMemoryServer.create();
  const uri = mongo.getUri();
  await mongoose.connect(uri);
  const hash = await bcrypt.hash(PW, 10);
  const mk = (role, email) => User.create({ role, email, fullName: `E2E ${role} ${email.split("@")[0]}`, phone: `+9470${Math.floor(1e6 + Math.random() * 8e6)}`, passwordHash: hash, status: "ACTIVE", isVerified: true });
  const u = {
    admin: await mk("admin", "admin@e2e.invalid"),
    responder: await mk("responder", "responder@e2e.invalid"),
    patientA: await mk("patient", "patient-a@e2e.invalid"),
    patientB: await mk("patient", "patient-b@e2e.invalid"),
    doctorB: await mk("doctor", "doctor-b@e2e.invalid"),
    otherDoctor: await mk("doctor", "doctor-x@e2e.invalid"),
  };
  const appt = (p, d, day) => Appointment.create({ patient: p._id, doctor: d._id, date: new Date(`2026-11-${day}`), time: "10:00", consultationType: "video", status: "confirmed" });
  const apptB = await appt(u.patientB, u.doctorB, "10");
  await appt(u.patientA, u.otherDoctor, "11");
  const emB = await EmergencyCase.create({ patient: u.patientB._id, description: "e2e sos", latitude: 6.9, longitude: 79.86 });

  // Start the real server.js
  // cwd = scratchpad (no .env) so dotenv cannot override the in-memory DB/port
  // with the developer's real server/.env.
  const server = spawn(process.execPath, [`${S}/server.js`], {
    cwd: require("os").tmpdir(), // no .env here
    env: { ...process.env, MONGO_URI: uri, PORT: String(PORT), JWT_ACCESS_SECRET: "e2e-access-secret", JWT_REFRESH_SECRET: "e2e-refresh-secret", NODE_ENV: "development", CLIENT_URL: "http://localhost:5173" },
  });
  let serverOut = "";
  server.stdout.on("data", (d) => (serverOut += d));
  server.stderr.on("data", (d) => (serverOut += d));
  // Abort immediately if dotenv injected anything (would mean a real .env was loaded).
  for (let i = 0; i < 100 && !serverOut.includes("running on port"); i++) {
    if (/injecting env \((?!0\))\d+\)/.test(serverOut)) { server.kill(); throw new Error("a .env file was loaded; aborting to protect real config"); }
    await wait(200);
  }
  if (!serverOut.includes(`MongoDB Connected: 127.0.0.1`) ) { for (let i = 0; i < 25 && !serverOut.includes("MongoDB Connected"); i++) await wait(200); }
  if (!serverOut.includes("MongoDB Connected: 127.0.0.1")) { server.kill(); throw new Error("server not connected to the in-memory DB:\n" + serverOut); }
  if (!serverOut.includes("running on port")) throw new Error("server did not start:\n" + serverOut);

  // Real login for every user (also writes a real refreshTokenHash to the DB)
  const t = {};
  for (const [k, user] of Object.entries(u)) {
    const res = await http("POST", "/api/auth/login", null, { identifier: user.email, password: PW });
    if (res.status !== 200) throw new Error(`login ${k} failed ${res.status} ${JSON.stringify(res.body)}`);
    t[k] = res.body.accessToken;
  }
  const dbHasRefreshHash = !!(await User.findById(u.patientB._id).select("refreshTokenHash")).refreshTokenHash;
  check("S0", "Precondition: real login stored refreshTokenHash in DB", "present", dbHasRefreshHash ? "present" : "absent", dbHasRefreshHash);

  let res;
  // ── V3 users ──
  res = await http("GET", "/api/users");
  check("U1", "GET /api/users, no token", "401", res.status, res.status === 401);
  res = await http("GET", "/api/users", t.admin);
  check("U2", "GET /api/users as admin (ManageUsers/UserContext)", "200, 6 users, no hashes", `${res.status}, ${res.body.data?.length} users, hashes=${hasSecret(res.body)}`, res.status === 200 && res.body.data?.length === 6 && !hasSecret(res.body));
  res = await http("GET", "/api/users?role=doctor", t.patientA);
  const keys = [...new Set((res.body.data || []).flatMap(Object.keys))].sort().join(",");
  check("U3", "GET /api/users?role=doctor as patient (booking page)", "200, 2 doctors, keys _id,email,fullName,role", `${res.status}, ${res.body.data?.length} doctors, keys ${keys}`, res.status === 200 && res.body.data?.length === 2 && keys === "_id,email,fullName,role");
  res = await http("GET", "/api/users", t.patientA);
  check("U4", "GET /api/users (all) as patient", "403", res.status, res.status === 403);
  res = await http("GET", `/api/users/${u.patientA._id}`, t.patientA);
  check("U5", "GET /api/users/:self as patient", "200, no hashes", `${res.status}, hashes=${hasSecret(res.body)}`, res.status === 200 && !hasSecret(res.body));
  res = await http("GET", `/api/users/${u.patientB._id}`, t.patientA);
  check("U6", "GET /api/users/:other as patient", "403", res.status, res.status === 403);
  res = await http("GET", "/api/auth/me", t.patientA);
  check("U7", "GET /api/auth/me (regression)", "200", res.status, res.status === 200);

  // ── V3 emergency ──
  res = await http("GET", "/api/emergency");
  check("E1", "GET /api/emergency, no token", "401", res.status, res.status === 401);
  res = await http("POST", "/api/emergency", t.patientA, { patient: String(u.patientB._id), description: "SOS emergency triggered from patient app", latitude: 6.91, longitude: 79.85 });
  check("E2", "POST /api/emergency as patient (SOS button body, spoofed patient id)", "201, recorded for caller", `${res.status}, patient=${res.body.data?.patient === String(u.patientA._id) ? "caller" : "other"}`, res.status === 201 && res.body.data?.patient === String(u.patientA._id));
  res = await http("GET", "/api/emergency", t.responder);
  const e0 = res.body.data?.[0] || {};
  check("E3", "GET /api/emergency as responder (monitoring page fields)", "200, patient.fullName/phone present, no hashes", `${res.status}, ${res.body.data?.length} cases, fullName=${!!e0.patient?.fullName}, phone=${!!e0.patient?.phone}, hashes=${hasSecret(res.body)}`, res.status === 200 && !!e0.patient?.fullName && !!e0.patient?.phone && !hasSecret(res.body));
  res = await http("PATCH", `/api/emergency/${emB._id}/status`, t.admin, { status: "DISPATCHED" });
  check("E4", "PATCH /api/emergency/:id/status as admin", "200, DISPATCHED", `${res.status}, ${res.body.data?.status}`, res.status === 200 && res.body.data?.status === "DISPATCHED");
  res = await http("GET", `/api/emergency/${emB._id}/nearest-hospital`, t.responder);
  check("E5", "GET nearest-hospital as responder (EmergencyMap)", "200", res.status, res.status === 200 && !!res.body.nearestHospital);
  res = await http("GET", "/api/emergency", t.patientA);
  check("E6", "GET /api/emergency as patient", "403", res.status, res.status === 403);
  res = await http("PATCH", `/api/emergency/${emB._id}/status`, t.doctorB, { status: "RESOLVED" });
  check("E7", "PATCH status as doctor", "403", res.status, res.status === 403);

  // ── V3 payments (PaymentPage flow: create → verify) ──
  res = await http("POST", "/api/payments", null, { appointment: String(apptB._id), patient: String(u.patientB._id), amount: 3500 });
  check("P1", "POST /api/payments, no token", "401", res.status, res.status === 401);
  res = await http("POST", "/api/payments", t.patientB, { appointment: String(apptB._id), patient: String(u.patientB._id), amount: 3500, currency: "LKR", method: "card" });
  const payId = res.body.data?._id;
  check("P2", "POST /api/payments as owning patient (PaymentPage body)", "201, pending, no hashes", `${res.status}, ${res.body.data?.status}, hashes=${hasSecret(res.body)}`, res.status === 201 && res.body.data?.status === "pending" && !hasSecret(res.body));
  res = await http("PATCH", `/api/payments/${payId}/verify`, t.patientB);
  check("P3", "PATCH verify as owning patient (PaymentPage)", "200, verified, transactionRef set, no hashes", `${res.status}, ${res.body.data?.status}, ref=${!!res.body.data?.transactionRef}, hashes=${hasSecret(res.body)}`, res.status === 200 && res.body.data?.status === "verified" && !!res.body.data?.transactionRef && !hasSecret(res.body));
  res = await http("GET", `/api/payments/appointment/${apptB._id}`, t.patientB);
  const pd = res.body.data || {};
  const clientFields = ["_id", "amount", "method", "status", "transactionRef", "verifiedAt"].every((k) => pd[k] !== undefined);
  check("P4", "GET payment by appointment as patient (AppointmentDetail fields)", "200, client fields present, no hashes", `${res.status}, fields=${clientFields}, hashes=${hasSecret(res.body)}`, res.status === 200 && clientFields && !hasSecret(res.body));
  res = await http("GET", `/api/payments/appointment/${apptB._id}`, t.doctorB);
  check("P5", "GET payment by appointment as appointment's doctor", "200, no hashes", `${res.status}, hashes=${hasSecret(res.body)}`, res.status === 200 && !hasSecret(res.body));
  res = await http("GET", `/api/payments/${payId}`, t.patientA);
  check("P6", "GET another patient's payment", "403", res.status, res.status === 403);
  res = await http("GET", `/api/payments/${payId}`, t.responder);
  check("P7", "GET payment as responder", "403", res.status, res.status === 403);
  res = await http("GET", `/api/payments/${payId}/receipt`, t.patientB);
  check("P8", "GET receipt as owning patient", "200 application/pdf", `${res.status} ${res.type}`, res.status === 200 && res.type.includes("pdf"));

  // ── V4 sockets ──
  const connect = (token) => new Promise((ok) => {
    const s = ioc(BASE, { auth: token ? { token } : {}, transports: ["websocket"], reconnection: false });
    const got = [];
    ["room_joined", "join_error", "new_message", "user_typing", "send_error"].forEach((ev) => s.on(ev, (d) => got.push({ ev, d })));
    s.on("connect", () => ok({ s, got, ok: true }));
    s.on("connect_error", (e) => { s.close(); ok({ s, got, ok: false, err: e.message }); });
  });
  const room = String(apptB._id);
  const none = await connect(null);
  check("S1", "Socket connect without token", "rejected", none.ok ? "connected" : `rejected (${none.err})`, !none.ok);
  const A = await connect(t.patientA), B = await connect(t.patientB), D = await connect(t.doctorB);
  B.s.emit("join_room", { appointmentId: room }); D.s.emit("join_room", { appointmentId: room });
  A.s.emit("join_room", { appointmentId: room });
  await wait(500);
  const n = (c, ev) => c.got.filter((g) => g.ev === ev).length;
  check("S2", "Participants (patient B, doctor) join_room", "room_joined for both", `B=${n(B, "room_joined")}, D=${n(D, "room_joined")}`, n(B, "room_joined") === 1 && n(D, "room_joined") === 1);
  check("S3", "Patient A join_room on B's appointment", "join_error, no room_joined", `join_error=${n(A, "join_error")}, room_joined=${n(A, "room_joined")}`, n(A, "join_error") === 1 && n(A, "room_joined") === 0);
  B.s.emit("send_message", { appointmentId: room, message: "e2e hello" });
  D.s.emit("typing", { appointmentId: room, isTyping: true });
  await wait(500);
  A.s.emit("typing", { appointmentId: room, isTyping: true });
  A.s.emit("send_message", { appointmentId: room, message: "e2e injected" });
  await wait(500);
  check("S4", "Authorized send_message delivered to room", "B and D receive new_message", `B=${n(B, "new_message")}, D=${n(D, "new_message")}`, n(B, "new_message") === 1 && n(D, "new_message") === 1);
  const bTypingFromD = B.got.some((g) => g.ev === "user_typing" && g.d.userId === String(u.doctorB._id));
  check("S5", "Authorized typing relayed", "B receives doctor's user_typing", `received=${bTypingFromD}`, bTypingFromD);
  check("S6", "Attacker receives room events", "0 new_message, 0 user_typing", `new_message=${n(A, "new_message")}, user_typing=${n(A, "user_typing")}`, n(A, "new_message") === 0 && n(A, "user_typing") === 0);
  const bTypingFromA = B.got.some((g) => g.ev === "user_typing" && g.d.userId === String(u.patientA._id));
  check("S7", "Attacker typing injected into B's room", "not delivered", bTypingFromA ? "delivered" : "not delivered", !bTypingFromA);
  check("S8", "Attacker send_message to B's room", "send_error, not delivered", `send_error=${n(A, "send_error")}, B new_message=${n(B, "new_message")}`, n(A, "send_error") === 1 && n(B, "new_message") === 1);
  res = await http("GET", `/api/chat/${room}`, t.doctorB);
  check("S9", "Chat history via REST as doctor after live chat", "200, 1 message", `${res.status}, ${res.body.messages?.length} message(s)`, res.status === 200 && res.body.messages?.length === 1);
  await User.updateOne({ _id: u.patientA._id }, { isActive: false });
  const inactive = await connect(t.patientA);
  check("S10", "Socket connect as deactivated user (token still valid)", "rejected", inactive.ok ? "connected" : `rejected (${inactive.err})`, !inactive.ok);

  [A, B, D].forEach((c) => c.s.close());
  server.kill();
  await mongoose.disconnect(); await mongo.stop();
  require("fs").writeFileSync(path.join(__dirname, "e2e-v3-v4-results.json"), JSON.stringify(rows, null, 2));
  console.log(JSON.stringify(rows, null, 1));
  console.log(`\n${rows.filter((x) => x.result === "PASS").length}/${rows.length} PASS`);
  const errLines = serverOut.split("\n").filter((l) => /APP ERROR|Unhandled|TypeError|ReferenceError/.test(l));
  console.log("server error lines:", errLines.length ? errLines.slice(0, 10) : "none");
  process.exit(0);
})().catch((e) => { console.error("E2E ABORTED:", e.message); process.exit(1); });
