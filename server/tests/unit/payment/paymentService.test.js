const mongoose = require("mongoose");

jest.mock("../../../models/Payment");
jest.mock("../../../models/Appointment");

const Payment = require("../../../models/Payment");
const Appointment = require("../../../models/Appointment");
const paymentService = require("../../../services/paymentService");
const { PAYMENT_POPULATE } = paymentService;

const oid = () => new mongoose.Types.ObjectId();
const admin = { userId: oid(), role: "admin" };

// Appointment.findById(...).select(...) resolves to `doc`
const mockAppointmentLookup = (doc) => {
  Appointment.findById.mockReturnValue({ select: jest.fn().mockResolvedValue(doc) });
};

describe("Payment Service", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("never populates patient secrets", () => {
    const patientPopulate = PAYMENT_POPULATE.find((p) => p.path === "patient");
    expect(patientPopulate.select).toBe("fullName email phone");
    expect(patientPopulate.select).not.toMatch(/passwordHash|refreshTokenHash/);
  });

  // ─── createPayment ─────────────────────────────────────────────────

  describe("createPayment", () => {
    it("should create a payment when none exists", async () => {
      const patient = { userId: oid(), role: "patient" };
      const mockPayment = {
        _id: oid(),
        appointment: oid(),
        patient: patient.userId,
        amount: 3500,
        status: "pending",
        populate: jest.fn().mockReturnThis(),
      };

      mockAppointmentLookup({ patient: patient.userId });
      Payment.findOne.mockResolvedValue(null);
      Payment.create.mockResolvedValue(mockPayment);

      const result = await paymentService.createPayment(
        { appointment: mockPayment.appointment, patient: mockPayment.patient, amount: 3500 },
        patient
      );

      expect(result.amount).toBe(3500);
      expect(result.status).toBe("pending");
      expect(Payment.create).toHaveBeenCalled();
    });

    it("should throw 409 if payment already exists", async () => {
      const patient = { userId: oid(), role: "patient" };
      mockAppointmentLookup({ patient: patient.userId });
      Payment.findOne.mockResolvedValue({ _id: "existing" });

      await expect(
        paymentService.createPayment({ appointment: oid() }, patient)
      ).rejects.toMatchObject({
        statusCode: 409,
        message: expect.stringContaining("already exists"),
      });
    });

    it("should call populate after creation", async () => {
      const patient = { userId: oid(), role: "patient" };
      const mockPayment = {
        _id: oid(),
        amount: 100,
        status: "pending",
        populate: jest.fn().mockReturnThis(),
      };

      mockAppointmentLookup({ patient: patient.userId });
      Payment.findOne.mockResolvedValue(null);
      Payment.create.mockResolvedValue(mockPayment);

      await paymentService.createPayment({ appointment: oid(), patient: patient.userId, amount: 100 }, patient);

      expect(mockPayment.populate).toHaveBeenCalledWith(PAYMENT_POPULATE);
    });

    it("should set the payer to the caller and ignore client-supplied patient/status", async () => {
      const patient = { userId: oid(), role: "patient" };
      mockAppointmentLookup({ patient: patient.userId });
      Payment.findOne.mockResolvedValue(null);
      Payment.create.mockResolvedValue({ populate: jest.fn().mockReturnThis() });

      await paymentService.createPayment(
        { appointment: oid(), patient: oid(), amount: 50, status: "verified", transactionRef: "TXN-FAKE" },
        patient
      );

      const created = Payment.create.mock.calls[0][0];
      expect(created.patient).toBe(patient.userId);
      expect(created).not.toHaveProperty("status");
      expect(created).not.toHaveProperty("transactionRef");
    });

    it("should reject 403 when paying for another patient's appointment", async () => {
      mockAppointmentLookup({ patient: oid() });

      await expect(
        paymentService.createPayment({ appointment: oid(), amount: 10 }, { userId: oid(), role: "patient" })
      ).rejects.toMatchObject({ statusCode: 403 });
      expect(Payment.create).not.toHaveBeenCalled();
    });

    it("should reject 404 when the appointment does not exist", async () => {
      mockAppointmentLookup(null);

      await expect(
        paymentService.createPayment({ appointment: oid(), amount: 10 }, { userId: oid(), role: "patient" })
      ).rejects.toMatchObject({ statusCode: 404 });
    });
  });

  // ─── getPaymentById ─────────────────────────────────────────────────

  describe("getPaymentById", () => {
    it("should return a populated payment when found", async () => {
      const mockPayment = {
        _id: oid(),
        amount: 75,
        status: "pending",
        appointment: { _id: "appt1" },
        patient: { fullName: "Alice" },
      };

      Payment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPayment),
      });

      const result = await paymentService.getPaymentById(mockPayment._id, admin);

      expect(result).toEqual(mockPayment);
      expect(result.amount).toBe(75);
    });

    it("should throw 404 when payment not found", async () => {
      Payment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(null),
      });

      await expect(
        paymentService.getPaymentById(oid(), admin)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Payment not found",
      });
    });

    it("should allow the owning patient", async () => {
      const patientId = oid();
      const mockPayment = { _id: oid(), patient: { _id: patientId }, appointment: { doctor: oid() } };
      Payment.findById.mockReturnValue({ populate: jest.fn().mockResolvedValue(mockPayment) });

      await expect(
        paymentService.getPaymentById(mockPayment._id, { userId: patientId, role: "patient" })
      ).resolves.toBe(mockPayment);
    });

    it("should allow the appointment's doctor", async () => {
      const doctorId = oid();
      const mockPayment = { _id: oid(), patient: { _id: oid() }, appointment: { doctor: doctorId } };
      Payment.findById.mockReturnValue({ populate: jest.fn().mockResolvedValue(mockPayment) });

      await expect(
        paymentService.getPaymentById(mockPayment._id, { userId: doctorId, role: "doctor" })
      ).resolves.toBe(mockPayment);
    });

    it.each([
      ["another patient", { role: "patient" }],
      ["an unrelated doctor", { role: "doctor" }],
      ["a responder", { role: "responder" }],
    ])("should reject 403 for %s", async (_label, who) => {
      const mockPayment = { _id: oid(), patient: { _id: oid() }, appointment: { doctor: oid() } };
      Payment.findById.mockReturnValue({ populate: jest.fn().mockResolvedValue(mockPayment) });

      await expect(
        paymentService.getPaymentById(mockPayment._id, { userId: oid(), ...who })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it("should deny by default when no user is supplied", async () => {
      const mockPayment = { _id: oid(), patient: { _id: oid() }, appointment: { doctor: oid() } };
      Payment.findById.mockReturnValue({ populate: jest.fn().mockResolvedValue(mockPayment) });

      await expect(paymentService.getPaymentById(mockPayment._id)).rejects.toMatchObject({ statusCode: 403 });
    });
  });

  // ─── getPaymentByAppointment ────────────────────────────────────────

  describe("getPaymentByAppointment", () => {
    it("should return payment for a given appointment", async () => {
      const appointmentId = oid();
      const mockPayment = {
        _id: oid(),
        appointment: appointmentId,
        amount: 60,
      };

      Payment.findOne.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPayment),
      });

      const result = await paymentService.getPaymentByAppointment(appointmentId, admin);

      expect(result.appointment).toEqual(appointmentId);
    });

    it("should throw 404 when no payment found for appointment", async () => {
      Payment.findOne.mockReturnValue({
        populate: jest.fn().mockResolvedValue(null),
      });

      await expect(
        paymentService.getPaymentByAppointment(oid(), admin)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Payment not found for this appointment",
      });
    });

    it("should reject 403 for a patient who does not own the payment", async () => {
      const mockPayment = { _id: oid(), patient: { _id: oid() }, appointment: { doctor: oid() } };
      Payment.findOne.mockReturnValue({ populate: jest.fn().mockResolvedValue(mockPayment) });

      await expect(
        paymentService.getPaymentByAppointment(oid(), { userId: oid(), role: "patient" })
      ).rejects.toMatchObject({ statusCode: 403 });
    });
  });

  // ─── verifyPayment ──────────────────────────────────────────────────

  describe("verifyPayment", () => {
    it("should verify a pending payment", async () => {
      const mockPayment = {
        _id: oid(),
        status: "pending",
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Payment.findById.mockResolvedValue(mockPayment);

      const result = await paymentService.verifyPayment(mockPayment._id, admin);
      expect(result.status).toBe("verified");
      expect(result.transactionRef).toBeDefined();
      expect(result.transactionRef).toMatch(/^TXN-/);
      expect(result.verifiedAt).toBeDefined();
    });

    it("should reject verifying non-pending payment", async () => {
      const mockPayment = {
        _id: oid(),
        status: "verified",
      };

      Payment.findById.mockResolvedValue(mockPayment);

      await expect(
        paymentService.verifyPayment(mockPayment._id, admin)
      ).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("not in pending"),
      });
    });

    it("should throw 404 when payment not found", async () => {
      Payment.findById.mockResolvedValue(null);

      await expect(
        paymentService.verifyPayment(oid(), admin)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Payment not found",
      });
    });

    it("should call save and populate after verification", async () => {
      const mockPayment = {
        _id: oid(),
        status: "pending",
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Payment.findById.mockResolvedValue(mockPayment);

      await paymentService.verifyPayment(mockPayment._id, admin);

      expect(mockPayment.save).toHaveBeenCalled();
      expect(mockPayment.populate).toHaveBeenCalledWith(PAYMENT_POPULATE);
    });

    it("should reject verifying a failed payment", async () => {
      const mockPayment = {
        _id: oid(),
        status: "failed",
      };

      Payment.findById.mockResolvedValue(mockPayment);

      await expect(
        paymentService.verifyPayment(mockPayment._id, admin)
      ).rejects.toMatchObject({
        statusCode: 400,
      });
    });

    it("should let the appointment's doctor verify (looked up from the appointment)", async () => {
      const doctorId = oid();
      const mockPayment = {
        _id: oid(),
        status: "pending",
        patient: oid(),
        appointment: oid(),
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };
      Payment.findById.mockResolvedValue(mockPayment);
      mockAppointmentLookup({ doctor: doctorId });

      const result = await paymentService.verifyPayment(mockPayment._id, { userId: doctorId, role: "doctor" });
      expect(result.status).toBe("verified");
    });

    it("should reject 403 and not modify a payment the caller cannot access", async () => {
      const mockPayment = {
        _id: oid(),
        status: "pending",
        patient: oid(),
        appointment: oid(),
        save: jest.fn(),
      };
      Payment.findById.mockResolvedValue(mockPayment);

      await expect(
        paymentService.verifyPayment(mockPayment._id, { userId: oid(), role: "patient" })
      ).rejects.toMatchObject({ statusCode: 403 });
      expect(mockPayment.status).toBe("pending");
      expect(mockPayment.save).not.toHaveBeenCalled();
    });
  });

  // ─── failPayment ────────────────────────────────────────────────────

  describe("failPayment", () => {
    it("should fail a pending payment", async () => {
      const mockPayment = {
        _id: oid(),
        status: "pending",
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Payment.findById.mockResolvedValue(mockPayment);

      const result = await paymentService.failPayment(mockPayment._id, admin);
      expect(result.status).toBe("failed");
    });

    it("should throw 404 when payment not found", async () => {
      Payment.findById.mockResolvedValue(null);

      await expect(
        paymentService.failPayment(oid(), admin)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Payment not found",
      });
    });

    it("should reject failing a non-pending payment", async () => {
      const mockPayment = {
        _id: oid(),
        status: "verified",
      };

      Payment.findById.mockResolvedValue(mockPayment);

      await expect(
        paymentService.failPayment(mockPayment._id, admin)
      ).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("not in pending"),
      });
    });

    it("should call save and populate after failing", async () => {
      const mockPayment = {
        _id: oid(),
        status: "pending",
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Payment.findById.mockResolvedValue(mockPayment);

      await paymentService.failPayment(mockPayment._id, admin);

      expect(mockPayment.save).toHaveBeenCalled();
      expect(mockPayment.populate).toHaveBeenCalledWith(PAYMENT_POPULATE);
    });

    it("should reject 403 for a caller who cannot access the payment", async () => {
      const mockPayment = { _id: oid(), status: "pending", patient: oid(), appointment: oid(), save: jest.fn() };
      Payment.findById.mockResolvedValue(mockPayment);
      mockAppointmentLookup({ doctor: oid() });

      await expect(
        paymentService.failPayment(mockPayment._id, { userId: oid(), role: "doctor" })
      ).rejects.toMatchObject({ statusCode: 403 });
      expect(mockPayment.save).not.toHaveBeenCalled();
    });
  });
});
