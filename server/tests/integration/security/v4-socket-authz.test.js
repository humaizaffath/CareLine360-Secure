/**
 * V4 – Socket.IO room authorization
 * (CWE-862 Missing Authorization, CWE-639; OWASP A01:2021 Broken Access Control)
 *
 * Runs the real chat socket handler on a real Socket.IO server and checks:
 *  - unauthenticated / invalid / deactivated sockets are rejected
 *  - a user cannot join another user's appointment room or see its live events
 *  - appointment participants can still join and chat normally
 *
 * Clients speak the Socket.IO v5 / Engine.IO v4 wire protocol over `ws`
 * (already installed as a dependency of socket.io), so no new package is needed.
 */
const http = require("http");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const { Server } = require("socket.io");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");

const User = require("../../../models/User");
const Appointment = require("../../../models/Appointment");
const ChatMessage = require("../../../models/ChatMessage");
const { registerSocketHandlers } = require("../../../socket/chatSocket");

let mongoServer, httpServer, io, wsUrl;
let patientA, patientB, doctorB, otherDoctor, roomB, roomA;
const openClients = [];

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tokenFor = (user) =>
  jwt.sign({ userId: user._id.toString(), role: user.role }, process.env.JWT_ACCESS_SECRET);

/**
 * Minimal Socket.IO client. Resolves once the server accepts the connection,
 * rejects with the server's connect_error message otherwise.
 */
const connect = (auth) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(`${wsUrl}/socket.io/?EIO=4&transport=websocket`);
    const waiters = {};
    const client = {
      received: [],
      emit: (event, payload) => ws.send(`42${JSON.stringify([event, payload])}`),
      next: (event, timeoutMs = 2000) =>
        new Promise((res, rej) => {
          const timer = setTimeout(() => rej(new Error(`timed out waiting for "${event}"`)), timeoutMs);
          (waiters[event] = waiters[event] || []).push((data) => { clearTimeout(timer); res(data); });
        }),
      eventsNamed: (event) => client.received.filter((e) => e.event === event),
      close: () => ws.close(),
    };
    openClients.push(client);

    ws.on("message", (raw) => {
      const msg = raw.toString();
      if (msg[0] === "0") return ws.send(`40${auth ? JSON.stringify(auth) : ""}`); // open -> CONNECT (with auth)
      if (msg === "2") return ws.send("3"); // ping -> pong
      if (msg.startsWith("40")) return resolve(client); // CONNECT ack
      if (msg.startsWith("44")) { // CONNECT_ERROR
        ws.close();
        return reject(new Error(JSON.parse(msg.slice(2)).message));
      }
      if (msg.startsWith("42")) { // EVENT
        const [event, data] = JSON.parse(msg.slice(2));
        client.received.push({ event, data });
        (waiters[event] || []).splice(0).forEach((fn) => fn(data));
      }
    });
    ws.on("error", reject);
  });

const connectAs = (user) => connect({ token: tokenFor(user) });

const makeUser = (role, email) => User.create({ role, email, passwordHash: "test-hash" });

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";

  patientA = await makeUser("patient", "patient.a@v4.test");
  patientB = await makeUser("patient", "patient.b@v4.test");
  doctorB = await makeUser("doctor", "doctor.b@v4.test");
  otherDoctor = await makeUser("doctor", "other.doctor@v4.test");

  const appt = (patient, doctor) =>
    Appointment.create({
      patient: patient._id,
      doctor: doctor._id,
      date: new Date("2026-10-01"),
      time: "10:00",
      consultationType: "video",
      status: "confirmed",
    });
  roomB = String((await appt(patientB, doctorB))._id);
  roomA = String((await appt(patientA, otherDoctor))._id);

  httpServer = http.createServer();
  io = new Server(httpServer);
  registerSocketHandlers(io);
  await new Promise((resolve) => httpServer.listen(0, resolve));
  wsUrl = `ws://localhost:${httpServer.address().port}`;
}, 30000);

beforeEach(() => {
  // The handler logs every event; keep test output readable.
  jest.spyOn(console, "log").mockImplementation(() => {});
  jest.spyOn(console, "warn").mockImplementation(() => {});
  jest.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(async () => {
  openClients.splice(0).forEach((c) => c.close());
  await User.updateMany({}, { isActive: true });
  await ChatMessage.deleteMany({});
  await wait(50);
});

afterAll(async () => {
  io.close();
  await new Promise((resolve) => httpServer.close(resolve));
  await mongoose.disconnect();
  await mongoServer.stop();
});

// ─── Socket authentication ──────────────────────────────────────────────────

describe("V4: socket authentication", () => {
  it("rejects a socket without a token", async () => {
    await expect(connect()).rejects.toThrow("Authentication error: no token");
  });

  it("rejects a socket with an invalid token", async () => {
    await expect(connect({ token: "not-a-jwt" })).rejects.toThrow(/Authentication error/);
    const forged = jwt.sign({ userId: patientA._id.toString(), role: "patient" }, "wrong-secret");
    await expect(connect({ token: forged })).rejects.toThrow(/Authentication error/);
  });

  it("rejects a deactivated user even with a still-valid token", async () => {
    await User.updateOne({ _id: patientA._id }, { isActive: false });
    await expect(connectAs(patientA)).rejects.toThrow("account is deactivated");
  });

  it("accepts an active user with a valid token", async () => {
    await expect(connectAs(patientA)).resolves.toBeDefined();
  });
});

// ─── Unauthorized room access ───────────────────────────────────────────────

describe("V4: a user cannot join another user's room", () => {
  let attacker, owner, doctor;

  beforeEach(async () => {
    [attacker, owner, doctor] = await Promise.all([connectAs(patientA), connectAs(patientB), connectAs(doctorB)]);
    owner.emit("join_room", { appointmentId: roomB });
    doctor.emit("join_room", { appointmentId: roomB });
    await Promise.all([owner.next("room_joined"), doctor.next("room_joined")]);
  });

  it("denies join_room with join_error and never adds the socket to the room", async () => {
    attacker.emit("join_room", { appointmentId: roomB });
    const err = await attacker.next("join_error");

    expect(err).toEqual({ appointmentId: roomB, message: "Access denied" });
    expect(attacker.eventsNamed("room_joined")).toHaveLength(0);
    expect(await io.in(roomB).fetchSockets()).toHaveLength(2); // only patient B and doctor B
  });

  it("does not deliver the room's messages or typing events to the attacker", async () => {
    attacker.emit("join_room", { appointmentId: roomB });
    await attacker.next("join_error");

    doctor.emit("send_message", { appointmentId: roomB, message: "private note" });
    await owner.next("new_message");
    owner.emit("typing", { appointmentId: roomB, isTyping: true });
    await doctor.next("user_typing");
    await wait(100);

    expect(attacker.eventsNamed("new_message")).toHaveLength(0);
    expect(attacker.eventsNamed("user_typing")).toHaveLength(0);
  });

  it("drops typing/stop_typing the attacker sends into the room", async () => {
    attacker.emit("join_room", { appointmentId: roomB });
    await attacker.next("join_error");
    attacker.emit("typing", { appointmentId: roomB, isTyping: true });
    attacker.emit("stop_typing", { appointmentId: roomB });
    await wait(100);

    // Control event from a legitimate participant proves delivery is working.
    doctor.emit("typing", { appointmentId: roomB, isTyping: true });
    await owner.next("user_typing");

    const fromAttacker = owner.eventsNamed("user_typing").filter((e) => e.data.userId === patientA._id.toString());
    expect(fromAttacker).toHaveLength(0);
  });

  it("still rejects send_message from the attacker (existing rule preserved)", async () => {
    attacker.emit("send_message", { appointmentId: roomB, message: "injected" });
    expect(await attacker.next("send_error")).toEqual({ message: "Access denied" });
    expect(await ChatMessage.countDocuments({ appointmentId: roomB })).toBe(0);
  });

  it("denies a doctor who is not on the appointment", async () => {
    const intruder = await connectAs(otherDoctor);
    intruder.emit("join_room", { appointmentId: roomB });
    expect((await intruder.next("join_error")).message).toBe("Access denied");
  });

  it.each([
    ["a non-ObjectId string", { appointmentId: "not-an-id" }],
    ["an operator object", { appointmentId: { $ne: null } }],
    ["a missing appointmentId", {}],
    ["no payload", undefined],
  ])("rejects join_room with %s", async (_label, payload) => {
    attacker.emit("join_room", payload);
    expect((await attacker.next("join_error")).message).toBe("Invalid appointment id");
    expect(await io.in(roomB).fetchSockets()).toHaveLength(2);
  });
});

// ─── Legitimate participants ────────────────────────────────────────────────

describe("V4: appointment participants can join and chat normally", () => {
  it("patient and doctor join, exchange messages and typing indicators", async () => {
    const [patient, doctor] = await Promise.all([connectAs(patientB), connectAs(doctorB)]);

    patient.emit("join_room", { appointmentId: roomB });
    doctor.emit("join_room", { appointmentId: roomB });
    expect(await patient.next("room_joined")).toEqual({ appointmentId: roomB });
    expect(await doctor.next("room_joined")).toEqual({ appointmentId: roomB });

    patient.emit("send_message", { appointmentId: roomB, message: "hello doctor" });
    const [atDoctor, atPatient] = await Promise.all([doctor.next("new_message"), patient.next("new_message")]);
    expect(atDoctor.message).toBe("hello doctor");
    expect(atPatient._id).toBe(atDoctor._id);
    expect(await ChatMessage.countDocuments({ appointmentId: roomB })).toBe(1);

    doctor.emit("typing", { appointmentId: roomB, isTyping: true });
    expect(await patient.next("user_typing")).toMatchObject({ userId: doctorB._id.toString(), role: "doctor", isTyping: true });
    doctor.emit("stop_typing", { appointmentId: roomB });
    expect(await patient.next("user_typing")).toMatchObject({ isTyping: false });
  });

  it("each user only reaches their own room", async () => {
    const [a, b] = await Promise.all([connectAs(patientA), connectAs(patientB)]);
    a.emit("join_room", { appointmentId: roomA });
    b.emit("join_room", { appointmentId: roomB });
    await Promise.all([a.next("room_joined"), b.next("room_joined")]);

    b.emit("send_message", { appointmentId: roomB, message: "for room B only" });
    await b.next("new_message");
    await wait(100);
    expect(a.eventsNamed("new_message")).toHaveLength(0);
  });

  it("does not relay typing from a participant who has not joined the room yet", async () => {
    const [patient, doctor] = await Promise.all([connectAs(patientB), connectAs(doctorB)]);
    patient.emit("join_room", { appointmentId: roomB });
    await patient.next("room_joined");

    doctor.emit("typing", { appointmentId: roomB, isTyping: true }); // doctor never joined
    await wait(150);
    expect(patient.eventsNamed("user_typing")).toHaveLength(0);
  });

  it("stops receiving room events after leave_room", async () => {
    const [patient, doctor] = await Promise.all([connectAs(patientB), connectAs(doctorB)]);
    patient.emit("join_room", { appointmentId: roomB });
    doctor.emit("join_room", { appointmentId: roomB });
    await Promise.all([patient.next("room_joined"), doctor.next("room_joined")]);

    patient.emit("leave_room", { appointmentId: roomB });
    await wait(100);
    doctor.emit("send_message", { appointmentId: roomB, message: "after leave" });
    await doctor.next("new_message");
    await wait(100);
    expect(patient.eventsNamed("new_message")).toHaveLength(0);
  });
});
