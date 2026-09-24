const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");
const jwt = require("jsonwebtoken");

const User = require("../../../models/User");
const Appointment = require("../../../models/Appointment");
const Payment = require("../../../models/Payment");
const Doctor = require("../../../models/Doctor");
const paymentRoutes = require("../../../routes/paymentRoutes");
const errorHandler = require("../../../middleware/errorHandler");

// Mock Cloudinary (non-fatal upload)
jest.mock("../../../config/cloudinary", () => ({
  uploader: {
    upload_stream: jest.fn((opts, cb) => {
      const stream = require("stream");
      const writable = new stream.Writable({
        write(chunk, enc, next) { next(); },
      });
      writable.on("finish", () => {
        cb(null, { secure_url: "https://cloudinary.com/receipt.pdf", public_id: "test_receipt" });
      });
      return writable;
    }),
  },
}));

let mongoServer;
let app;
let patient, doctor, doctorProfile;
let asPatient; // supertest client authenticated as the paying patient

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "test-access-secret";

  app = express();
  app.use(express.json());
  app.use("/api/payments", paymentRoutes);
  app.use(errorHandler);

  patient = await User.create({
    fullName: "Test Patient",
    email: "patient@test.com",
    role: "patient",
    passwordHash: "hashedpassword123",
  });
  doctor = await User.create({
    fullName: "Test Doctor",
    email: "doctor@test.com",
    role: "doctor",
    passwordHash: "hashedpassword123",
  });

  doctorProfile = await Doctor.create({
    userId: doctor._id,
    doctorId: "DOC-000001",
    fullName: "Test Doctor",
    specialization: "General",
  });

  const token = jwt.sign({ userId: patient._id.toString(), role: "patient" }, process.env.JWT_ACCESS_SECRET);
  asPatient = { get: (url) => request(app).get(url).set("Authorization", `Bearer ${token}`) };
}, 30000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

afterEach(async () => {
  await Appointment.deleteMany({});
  await Payment.deleteMany({});
});

describe("Payment Receipt Integration", () => {
  it("GET /:id/receipt - should generate and return a PDF for verified payment", async () => {
    const appointment = await Appointment.create({
      patient: patient._id,
      doctor: doctor._id,
      date: new Date("2026-03-01"),
      time: "10:00",
      consultationType: "video",
      status: "completed",
    });

    const payment = await Payment.create({
      appointment: appointment._id,
      patient: patient._id,
      amount: 3500,
      currency: "LKR",
      method: "card",
      status: "verified",
      transactionRef: "TXN-TEST-123",
      verifiedAt: new Date(),
    });

    const res = await asPatient
      .get(`/api/payments/${payment._id}/receipt`);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/pdf");
    expect(res.body).toBeDefined();
  });

  it("GET /:id/receipt - should reject for unverified payment", async () => {
    const appointment = await Appointment.create({
      patient: patient._id,
      doctor: doctor._id,
      date: new Date("2026-03-01"),
      time: "10:00",
      consultationType: "video",
      status: "completed",
    });

    const payment = await Payment.create({
      appointment: appointment._id,
      patient: patient._id,
      amount: 3500,
      currency: "LKR",
      method: "card",
      status: "pending",
    });

    const res = await asPatient
      .get(`/api/payments/${payment._id}/receipt`);

    expect(res.status).toBe(400);
  });
});
