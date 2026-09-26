/**
 * V8 - Insecure File Upload (CWE-434) - Integration tests
 * Spoofed files must be rejected BEFORE reaching Cloudinary; genuine files still upload.
 */
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const express = require("express");
const request = require("supertest");

let mockUserId;
jest.mock("../../../middleware/auth", () => ({
  authMiddleware: (req, res, next) => {
    req.user = { userId: mockUserId, role: "patient" };
    next();
  },
  roleMiddleware: () => (req, res, next) => next(),
}));

jest.mock("../../../config/cloudinary", () => ({
  uploader: {
    upload_stream: jest.fn((opts, cb) => {
      const stream = require("stream");
      const writable = new stream.Writable({ write(chunk, enc, next) { next(); } });
      writable.on("finish", () =>
        cb(null, {
          secure_url: `https://res.cloudinary.com/test/${opts.folder}/file`,
          public_id: `${opts.folder}/file_id`,
          resource_type: opts.resource_type === "auto" ? "image" : opts.resource_type,
          format: "pdf",
          version: 1,
        })
      );
      return writable;
    }),
    destroy: jest.fn(),
  },
}));

const cloudinary = require("../../../config/cloudinary");
const Document = require("../../../models/Document");
const Patient = require("../../../models/Patient");
const documentRoutes = require("../../../routes/documentRoutes");
const patientRoutes = require("../../../routes/patientRoutes");
const errorHandler = require("../../../middleware/errorHandler");

const PDF = Buffer.from("%PDF-1.4\n%test\n");
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
const TEXT = Buffer.from("plain text pretending to be a PDF");
const HTML = Buffer.from("<html><body>not an image</body></html>");

let mongoServer;
let app;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());

  app = express();
  app.use(express.json());
  app.use("/api/documents", documentRoutes);
  app.use("/api/patients", patientRoutes);
  app.use(errorHandler);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  mockUserId = new mongoose.Types.ObjectId();
  await Patient.create({ userId: mockUserId, patientId: `P-${Date.now()}`, fullName: "Test Patient" });
});

afterEach(async () => {
  await Document.deleteMany({});
  await Patient.deleteMany({});
});

describe("V8 POST /api/documents", () => {
  test("rejects a text file spoofed as application/pdf and does not upload it", async () => {
    const res = await request(app)
      .post("/api/documents")
      .attach("document", TEXT, { filename: "report.pdf", contentType: "application/pdf" });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/does not match/);
    expect(cloudinary.uploader.upload_stream).not.toHaveBeenCalled();
    expect(await Document.countDocuments()).toBe(0);
  });

  test("rejects a PNG spoofed as a PDF", async () => {
    const res = await request(app)
      .post("/api/documents")
      .attach("document", PNG, { filename: "report.pdf", contentType: "application/pdf" });

    expect(res.status).toBe(400);
    expect(cloudinary.uploader.upload_stream).not.toHaveBeenCalled();
  });

  test("accepts a genuine PDF", async () => {
    const res = await request(app)
      .post("/api/documents")
      .field("title", "Lab report")
      .attach("document", PDF, { filename: "report.pdf", contentType: "application/pdf" });

    expect(res.status).toBe(201);
    expect(cloudinary.uploader.upload_stream).toHaveBeenCalledTimes(1);
    expect(res.body.document.fileUrl).toContain("careline360/documents");
    expect(res.body.document.mimeType).toBe("application/pdf");
  });
});

describe("V8 PATCH /api/patients/me/avatar", () => {
  test("rejects HTML spoofed as image/png", async () => {
    const res = await request(app)
      .patch("/api/patients/me/avatar")
      .attach("avatar", HTML, { filename: "avatar.png", contentType: "image/png" });

    expect(res.status).toBe(400);
    expect(cloudinary.uploader.upload_stream).not.toHaveBeenCalled();
    const patient = await Patient.findOne({ userId: mockUserId });
    expect(patient.avatarUrl).toBeFalsy();
  });

  test("accepts a genuine PNG avatar", async () => {
    const res = await request(app)
      .patch("/api/patients/me/avatar")
      .attach("avatar", PNG, { filename: "avatar.png", contentType: "image/png" });

    expect(res.status).toBe(200);
    expect(res.body.avatarUrl).toContain("careline360/avatars");
  });
});
