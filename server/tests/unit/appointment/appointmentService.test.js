const mongoose = require("mongoose");

// Mock the models and email service before requiring the service
jest.mock("../../../models/Appointment");
jest.mock("../../../models/User");
jest.mock("../../../services/emailService", () => ({
  sendAppointmentCreated: jest.fn(),
  sendAppointmentConfirmed: jest.fn(),
  sendAppointmentRescheduled: jest.fn(),
  sendAppointmentCancelled: jest.fn(),
}));

const Appointment = require("../../../models/Appointment");
const emailService = require("../../../services/emailService");
const appointmentService = require("../../../services/appointmentService");

// SECURITY (V1): identities used for ownership checks. The "user" objects mirror
// req.user as set by authMiddleware from the verified JWT.
const PATIENT_ID = new mongoose.Types.ObjectId();
const DOCTOR_ID = new mongoose.Types.ObjectId();
const patientUser = { userId: PATIENT_ID, role: "patient" };
const doctorUser = { userId: DOCTOR_ID, role: "doctor" };
const adminUser = { userId: new mongoose.Types.ObjectId(), role: "admin" };
const otherPatientUser = { userId: new mongoose.Types.ObjectId(), role: "patient" };
const otherDoctorUser = { userId: new mongoose.Types.ObjectId(), role: "doctor" };

describe("Appointment Service", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  // ─── createAppointment ──────────────────────────────────────────────

  describe("createAppointment", () => {
    const mockPopulatedAppointment = {
      _id: new mongoose.Types.ObjectId(),
      patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
      doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
      date: new Date("2026-03-01"),
      time: "10:00",
      status: "pending",
      consultationType: "video",
    };

    it("should create an appointment when no double booking exists", async () => {
      Appointment.findOne.mockResolvedValue(null);
      Appointment.create.mockResolvedValue(mockPopulatedAppointment);
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPopulatedAppointment),
      });

      const result = await appointmentService.createAppointment({
        patient: new mongoose.Types.ObjectId(),
        doctor: new mongoose.Types.ObjectId(),
        date: "2026-03-01",
        time: "10:00",
        consultationType: "video",
      });

      expect(result).toBeDefined();
      expect(Appointment.create).toHaveBeenCalled();
    });

    it("should throw 409 when double booking detected", async () => {
      Appointment.findOne.mockResolvedValue({ _id: "existing" });

      await expect(
        appointmentService.createAppointment({
          doctor: new mongoose.Types.ObjectId(),
          date: "2026-03-01",
          time: "10:00",
        })
      ).rejects.toMatchObject({
        message: expect.stringContaining("already has an appointment"),
        statusCode: 409,
      });
    });

    it("should call email notification after creation", async () => {
      Appointment.findOne.mockResolvedValue(null);
      Appointment.create.mockResolvedValue(mockPopulatedAppointment);
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPopulatedAppointment),
      });

      await appointmentService.createAppointment({
        patient: new mongoose.Types.ObjectId(),
        doctor: new mongoose.Types.ObjectId(),
        date: "2026-03-01",
        time: "10:00",
        consultationType: "video",
      });

      expect(emailService.sendAppointmentCreated).toHaveBeenCalledWith(
        mockPopulatedAppointment,
        mockPopulatedAppointment.patient,
        mockPopulatedAppointment.doctor
      );
    });

    it("should handle email failure gracefully", async () => {
      Appointment.findOne.mockResolvedValue(null);
      Appointment.create.mockResolvedValue(mockPopulatedAppointment);
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPopulatedAppointment),
      });
      emailService.sendAppointmentCreated.mockRejectedValue(new Error("SMTP down"));

      const result = await appointmentService.createAppointment({
        patient: new mongoose.Types.ObjectId(),
        doctor: new mongoose.Types.ObjectId(),
        date: "2026-03-01",
        time: "10:00",
        consultationType: "video",
      });

      expect(result).toBeDefined();
    });

    it("should ignore server-controlled fields in the body (mass assignment)", async () => {
      Appointment.findOne.mockResolvedValue(null);
      Appointment.create.mockResolvedValue(mockPopulatedAppointment);
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPopulatedAppointment),
      });
      const patientId = new mongoose.Types.ObjectId();

      await appointmentService.createAppointment(
        {
          patient: new mongoose.Types.ObjectId(),
          doctor: new mongoose.Types.ObjectId(),
          date: "2026-03-01",
          time: "10:00",
          consultationType: "video",
          status: "confirmed",
          reminderSent: true,
          meetingUrl: "https://evil.example/x",
        },
        patientId
      );

      const saved = Appointment.create.mock.calls[0][0];
      expect(saved.patient).toBe(patientId);
      expect(saved).not.toHaveProperty("status");
      expect(saved).not.toHaveProperty("reminderSent");
      expect(saved).not.toHaveProperty("meetingUrl");
    });
  });

  // ─── getAppointments ────────────────────────────────────────────────

  describe("getAppointments", () => {
    const mockChain = (appointments, total) => {
      Appointment.countDocuments.mockResolvedValue(total);
      Appointment.find.mockReturnValue({
        populate: jest.fn().mockReturnValue({
          sort: jest.fn().mockReturnValue({
            skip: jest.fn().mockReturnValue({
              limit: jest.fn().mockResolvedValue(appointments),
            }),
          }),
        }),
      });
    };

    it("should return appointments with default pagination", async () => {
      mockChain([{ _id: "a1" }], 1);

      const result = await appointmentService.getAppointments({}, adminUser);

      expect(result.appointments).toHaveLength(1);
      expect(result.pagination).toEqual({
        total: 1,
        page: 1,
        limit: 10,
        pages: 1,
      });
    });

    it("should filter by single status", async () => {
      mockChain([], 0);

      await appointmentService.getAppointments({ status: "confirmed" }, adminUser);

      expect(Appointment.find).toHaveBeenCalled();
    });

    it("should filter by multiple statuses (comma-separated)", async () => {
      mockChain([], 0);

      await appointmentService.getAppointments({ status: "pending,confirmed" }, adminUser);

      expect(Appointment.find).toHaveBeenCalled();
    });

    it("should filter by doctor", async () => {
      const doctorId = new mongoose.Types.ObjectId();
      mockChain([], 0);

      await appointmentService.getAppointments({ doctor: doctorId }, adminUser);

      expect(Appointment.find).toHaveBeenCalled();
    });

    it("should filter by patient", async () => {
      const patientId = new mongoose.Types.ObjectId();
      mockChain([], 0);

      await appointmentService.getAppointments({ patient: patientId }, adminUser);

      expect(Appointment.find).toHaveBeenCalled();
    });

    it("should filter by date range", async () => {
      mockChain([], 0);

      await appointmentService.getAppointments({
        dateFrom: "2026-01-01",
        dateTo: "2026-12-31",
      }, adminUser);

      expect(Appointment.find).toHaveBeenCalled();
    });

    it("should apply custom pagination", async () => {
      mockChain([{ _id: "a1" }], 25);

      const result = await appointmentService.getAppointments({ page: 2, limit: 5 }, adminUser);

      expect(result.pagination.page).toBe(2);
      expect(result.pagination.limit).toBe(5);
      expect(result.pagination.pages).toBe(5);
    });

    it("should return empty results when no matches", async () => {
      mockChain([], 0);

      const result = await appointmentService.getAppointments({ status: "completed" }, adminUser);

      expect(result.appointments).toHaveLength(0);
      expect(result.pagination.total).toBe(0);
    });
  });

  // ─── getAppointmentById ─────────────────────────────────────────────

  describe("getAppointmentById", () => {
    it("should return populated appointment when found", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        patient: { _id: PATIENT_ID, fullName: "Alice" },
        doctor: { fullName: "Dr. Sarah" },
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue(mockAppt) }),
      });

      const result = await appointmentService.getAppointmentById(mockAppt._id, patientUser);

      expect(result).toEqual(mockAppt);
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue(null) }),
      });

      await expect(
        appointmentService.getAppointmentById(new mongoose.Types.ObjectId(), patientUser)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Appointment not found",
      });
    });
  });

  // ─── updateAppointment ──────────────────────────────────────────────

  describe("updateAppointment", () => {
    it("should update a pending appointment", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        doctor: new mongoose.Types.ObjectId(),
        patient: PATIENT_ID,
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Appointment.findById.mockResolvedValue(mockAppt);

      const result = await appointmentService.updateAppointment(mockAppt._id, {
        symptoms: "Updated symptoms",
      }, patientUser);

      expect(mockAppt.save).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it("should not let the body change doctor, patient or status (mass assignment)", async () => {
      const originalDoctor = new mongoose.Types.ObjectId();
      const originalPatient = new mongoose.Types.ObjectId();
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        doctor: originalDoctor,
        patient: originalPatient,
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };
      Appointment.findById.mockResolvedValue(mockAppt);

      await appointmentService.updateAppointment(mockAppt._id, {
        symptoms: "Headache",
        status: "confirmed",
        doctor: new mongoose.Types.ObjectId(),
        patient: new mongoose.Types.ObjectId(),
        meetingUrl: "https://evil.example/x",
      }, { userId: originalPatient, role: "patient" });

      expect(mockAppt.symptoms).toBe("Headache");
      expect(mockAppt.status).toBe("pending");
      expect(mockAppt.doctor).toBe(originalDoctor);
      expect(mockAppt.patient).toBe(originalPatient);
      expect(mockAppt.meetingUrl).toBeUndefined();
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockResolvedValue(null);

      await expect(
        appointmentService.updateAppointment(new mongoose.Types.ObjectId(), {}, patientUser)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Appointment not found",
      });
    });

    it("should throw 400 when appointment is not pending", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        patient: PATIENT_ID,
      };
      Appointment.findById.mockResolvedValue(mockAppt);

      await expect(
        appointmentService.updateAppointment(mockAppt._id, { symptoms: "x" }, patientUser)
      ).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("pending"),
      });
    });

    it("should throw 409 on double booking when date/time changes", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        doctor: new mongoose.Types.ObjectId(),
        patient: PATIENT_ID,
        save: jest.fn(),
        populate: jest.fn().mockReturnThis(),
      };

      Appointment.findById.mockResolvedValue(mockAppt);
      Appointment.findOne.mockResolvedValue({ _id: "existing" });

      await expect(
        appointmentService.updateAppointment(mockAppt._id, {
          date: "2026-04-01",
          time: "14:00",
        }, patientUser)
      ).rejects.toMatchObject({
        statusCode: 409,
      });
    });

    it("should skip double-booking check when only non-date fields change", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        doctor: new mongoose.Types.ObjectId(),
        patient: PATIENT_ID,
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      };

      Appointment.findById.mockResolvedValue(mockAppt);

      await appointmentService.updateAppointment(mockAppt._id, {
        symptoms: "Updated",
      }, patientUser);

      expect(Appointment.findOne).not.toHaveBeenCalled();
      expect(mockAppt.save).toHaveBeenCalled();
    });
  });

  // ─── deleteAppointment ──────────────────────────────────────────────

  describe("deleteAppointment", () => {
    it("should delete a pending appointment", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: PATIENT_ID,
        doctor: DOCTOR_ID,
        deleteOne: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockResolvedValue(mockAppt);

      const result = await appointmentService.deleteAppointment(mockAppt._id, patientUser);

      expect(mockAppt.deleteOne).toHaveBeenCalled();
      expect(result.message).toBe("Appointment deleted");
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockResolvedValue(null);

      await expect(
        appointmentService.deleteAppointment(new mongoose.Types.ObjectId(), patientUser)
      ).rejects.toMatchObject({
        statusCode: 404,
        message: "Appointment not found",
      });
    });

    it("should reject deleting non-pending appointments", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        patient: PATIENT_ID,
        doctor: DOCTOR_ID,
      };

      Appointment.findById.mockResolvedValue(mockAppt);

      await expect(
        appointmentService.deleteAppointment(mockAppt._id, patientUser)
      ).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("pending"),
      });
    });
  });

  // ─── transitionStatus ───────────────────────────────────────────────

  describe("transitionStatus", () => {
    it("should allow pending -> confirmed", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.transitionStatus(mockAppt._id, "confirmed", doctorUser);
      expect(result.status).toBe("confirmed");
    });

    it("should allow pending -> cancelled", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.transitionStatus(mockAppt._id, "cancelled", doctorUser);
      expect(result.status).toBe("cancelled");
    });

    it("should allow confirmed -> completed", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.transitionStatus(mockAppt._id, "completed", doctorUser);
      expect(result.status).toBe("completed");
    });

    it("should allow confirmed -> cancelled", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.transitionStatus(mockAppt._id, "cancelled", doctorUser);
      expect(result.status).toBe("cancelled");
    });

    it("should reject invalid transitions", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "completed",
        doctor: { _id: DOCTOR_ID },
        save: jest.fn(),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await expect(
        appointmentService.transitionStatus(mockAppt._id, "confirmed", doctorUser)
      ).rejects.toMatchObject({
        statusCode: 400,
      });
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(null),
      });

      await expect(
        appointmentService.transitionStatus(new mongoose.Types.ObjectId(), "confirmed", doctorUser)
      ).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it("should call email only on confirmed transition", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await appointmentService.transitionStatus(mockAppt._id, "confirmed", doctorUser);
      expect(emailService.sendAppointmentConfirmed).toHaveBeenCalled();

      jest.clearAllMocks();

      const mockAppt2 = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt2),
      });

      await appointmentService.transitionStatus(mockAppt2._id, "cancelled", doctorUser);
      expect(emailService.sendAppointmentConfirmed).not.toHaveBeenCalled();
    });
  });

  // ─── rescheduleAppointment ──────────────────────────────────────────

  describe("rescheduleAppointment", () => {
    it("should reschedule a confirmed appointment", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        date: new Date("2026-03-01"),
        time: "10:00",
        doctor: { _id: DOCTOR_ID },
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        rescheduleHistory: [],
        reminderSent: true,
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });
      Appointment.findOne.mockResolvedValue(null);

      const result = await appointmentService.rescheduleAppointment(
        mockAppt._id,
        "2026-04-01",
        "14:00",
        patientUser
      );

      expect(result.date).toEqual(new Date("2026-04-01"));
      expect(result.time).toBe("14:00");
      expect(result.reminderSent).toBe(false);
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(null),
      });

      await expect(
        appointmentService.rescheduleAppointment(new mongoose.Types.ObjectId(), "2026-04-01", "14:00", patientUser)
      ).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it("should throw 400 when appointment is not confirmed", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID },
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await expect(
        appointmentService.rescheduleAppointment(mockAppt._id, "2026-04-01", "14:00", patientUser)
      ).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("confirmed"),
      });
    });

    it("should throw 409 on double booking", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        doctor: { _id: DOCTOR_ID },
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        rescheduleHistory: [],
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });
      Appointment.findOne.mockResolvedValue({ _id: "existing" });

      await expect(
        appointmentService.rescheduleAppointment(mockAppt._id, "2026-04-01", "14:00", patientUser)
      ).rejects.toMatchObject({
        statusCode: 409,
      });
    });

    it("should push to rescheduleHistory", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        date: new Date("2026-03-01"),
        time: "10:00",
        doctor: { _id: DOCTOR_ID },
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        rescheduleHistory: [],
        reminderSent: false,
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });
      Appointment.findOne.mockResolvedValue(null);

      await appointmentService.rescheduleAppointment(mockAppt._id, "2026-04-01", "14:00", patientUser);

      expect(mockAppt.rescheduleHistory).toHaveLength(1);
      expect(mockAppt.rescheduleHistory[0].previousDate).toEqual(new Date("2026-03-01"));
      expect(mockAppt.rescheduleHistory[0].previousTime).toBe("10:00");
    });

    it("should call email notification after reschedule", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        date: new Date("2026-03-01"),
        time: "10:00",
        doctor: { _id: DOCTOR_ID },
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        rescheduleHistory: [],
        reminderSent: false,
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });
      Appointment.findOne.mockResolvedValue(null);

      await appointmentService.rescheduleAppointment(mockAppt._id, "2026-04-01", "14:00", patientUser);

      expect(emailService.sendAppointmentRescheduled).toHaveBeenCalled();
    });
  });

  // ─── cancelAppointment ──────────────────────────────────────────────

  describe("cancelAppointment", () => {
    it("should cancel a pending appointment", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.cancelAppointment(mockAppt._id, "No longer needed", patientUser);

      expect(result.status).toBe("cancelled");
      expect(result.cancellationReason).toBe("No longer needed");
    });

    it("should cancel a confirmed appointment", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      const result = await appointmentService.cancelAppointment(mockAppt._id, "Emergency", patientUser);

      expect(result.status).toBe("cancelled");
    });

    it("should throw 404 when appointment not found", async () => {
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(null),
      });

      await expect(
        appointmentService.cancelAppointment(new mongoose.Types.ObjectId(), "reason", patientUser)
      ).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it("should throw 400 when appointment is completed", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "completed",
        patient: { _id: PATIENT_ID },
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await expect(
        appointmentService.cancelAppointment(mockAppt._id, "reason", patientUser)
      ).rejects.toMatchObject({
        statusCode: 400,
      });
    });

    it("should throw 400 when appointment is already cancelled", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "cancelled",
        patient: { _id: PATIENT_ID },
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await expect(
        appointmentService.cancelAppointment(mockAppt._id, "reason", patientUser)
      ).rejects.toMatchObject({
        statusCode: 400,
      });
    });

    it("should call email notification after cancellation", async () => {
      const mockAppt = {
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      };

      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockAppt),
      });

      await appointmentService.cancelAppointment(mockAppt._id, "Changed plans", patientUser);

      expect(emailService.sendAppointmentCancelled).toHaveBeenCalled();
    });
  });

  // ─── V1: IDOR / BOLA (object-level authorization) ───────────────────

  describe("V1 IDOR/BOLA protection", () => {
    const mockListChain = () => {
      Appointment.countDocuments.mockResolvedValue(0);
      Appointment.find.mockReturnValue({
        populate: jest.fn().mockReturnValue({
          sort: jest.fn().mockReturnValue({
            skip: jest.fn().mockReturnValue({
              limit: jest.fn().mockResolvedValue([]),
            }),
          }),
        }),
      });
    };

    const mockPopulatedFind = (appt) =>
      Appointment.findById.mockReturnValue({
        populate: jest.fn().mockResolvedValue(appt),
      });

    describe("getAppointments (list)", () => {
      it("should scope a patient to their own appointments, ignoring a spoofed patient query", async () => {
        mockListChain();
        const victimId = new mongoose.Types.ObjectId();

        await appointmentService.getAppointments({ patient: victimId }, patientUser);

        const query = Appointment.find.mock.calls[0][0];
        expect(query.patient).toBe(PATIENT_ID);
        expect(Appointment.countDocuments.mock.calls[0][0].patient).toBe(PATIENT_ID);
      });

      it("should scope a doctor to appointments assigned to them, ignoring a spoofed doctor query", async () => {
        mockListChain();

        await appointmentService.getAppointments(
          { doctor: new mongoose.Types.ObjectId() },
          doctorUser
        );

        expect(Appointment.find.mock.calls[0][0].doctor).toBe(DOCTOR_ID);
      });

      it("should let an admin list with any filter", async () => {
        mockListChain();
        const patientId = new mongoose.Types.ObjectId();

        await appointmentService.getAppointments({ patient: patientId }, adminUser);

        expect(Appointment.find.mock.calls[0][0].patient).toBe(patientId);
      });

      it("should return 403 for other roles and not query the database", async () => {
        mockListChain();

        await expect(
          appointmentService.getAppointments({}, { userId: new mongoose.Types.ObjectId(), role: "responder" })
        ).rejects.toMatchObject({ statusCode: 403 });
        expect(Appointment.find).not.toHaveBeenCalled();
      });

      it("should return 403 when no authenticated user is supplied", async () => {
        await expect(appointmentService.getAppointments({})).rejects.toMatchObject({
          statusCode: 403,
        });
      });
    });

    describe("getAppointmentById (read)", () => {
      const mockLean = (appt) =>
        Appointment.findById.mockReturnValue({
          populate: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue(appt) }),
        });

      const ownedAppt = () => ({
        _id: new mongoose.Types.ObjectId(),
        patient: { _id: PATIENT_ID, fullName: "Alice" },
        doctor: null,
      });

      it("should allow the owning patient to read their appointment", async () => {
        const appt = ownedAppt();
        mockLean(appt);

        await expect(appointmentService.getAppointmentById(appt._id, patientUser)).resolves.toBe(appt);
      });

      it("should allow the assigned doctor to read the appointment", async () => {
        const appt = { ...ownedAppt(), doctor: { _id: DOCTOR_ID } };
        mockLean(appt);
        const Doctor = require("../../../models/Doctor");
        jest.spyOn(Doctor, "findOne").mockReturnValue({
          select: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue(null) }),
        });

        await expect(appointmentService.getAppointmentById(appt._id, doctorUser)).resolves.toBe(appt);
        Doctor.findOne.mockRestore();
      });

      it("should return 404 when another patient reads the appointment", async () => {
        const appt = ownedAppt();
        mockLean(appt);

        await expect(
          appointmentService.getAppointmentById(appt._id, otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404, message: "Appointment not found" });
      });

      it("should return 404 when an unassigned doctor reads the appointment", async () => {
        const appt = { ...ownedAppt(), doctor: { _id: DOCTOR_ID } };
        mockLean(appt);

        await expect(
          appointmentService.getAppointmentById(appt._id, otherDoctorUser)
        ).rejects.toMatchObject({ statusCode: 404 });
      });

      it("should return 404 when no authenticated user is supplied", async () => {
        const appt = ownedAppt();
        mockLean(appt);

        await expect(appointmentService.getAppointmentById(appt._id)).rejects.toMatchObject({
          statusCode: 404,
        });
      });
    });

    describe("updateAppointment (modify)", () => {
      const pendingAppt = () => ({
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: PATIENT_ID,
        doctor: DOCTOR_ID,
        symptoms: "Original",
        save: jest.fn().mockResolvedValue(true),
        populate: jest.fn().mockReturnThis(),
      });

      it("should return 404 and not save when another patient updates the appointment", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        await expect(
          appointmentService.updateAppointment(appt._id, { symptoms: "Hacked" }, otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.save).not.toHaveBeenCalled();
        expect(appt.symptoms).toBe("Original");
      });

      it("should not let the assigned doctor edit the patient's booking", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        await expect(
          appointmentService.updateAppointment(appt._id, { symptoms: "Changed" }, doctorUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.save).not.toHaveBeenCalled();
      });

      it("should check ownership before status so non-owners cannot probe appointment state", async () => {
        const appt = { ...pendingAppt(), status: "confirmed" };
        Appointment.findById.mockResolvedValue(appt);

        await expect(
          appointmentService.updateAppointment(appt._id, { symptoms: "x" }, otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
      });

      it("should still apply the V2 allow-list for the owning patient", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        await appointmentService.updateAppointment(
          appt._id,
          { symptoms: "Headache", patient: new mongoose.Types.ObjectId(), status: "confirmed" },
          patientUser
        );

        expect(appt.symptoms).toBe("Headache");
        expect(appt.patient).toBe(PATIENT_ID);
        expect(appt.status).toBe("pending");
        expect(appt.save).toHaveBeenCalled();
      });
    });

    describe("deleteAppointment (delete)", () => {
      const pendingAppt = () => ({
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: PATIENT_ID,
        doctor: DOCTOR_ID,
        deleteOne: jest.fn().mockResolvedValue(true),
      });

      it("should return 404 and not delete when another patient deletes the appointment", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        await expect(
          appointmentService.deleteAppointment(appt._id, otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.deleteOne).not.toHaveBeenCalled();
      });

      it("should return 404 and not delete when an unassigned doctor deletes the appointment", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        await expect(
          appointmentService.deleteAppointment(appt._id, otherDoctorUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.deleteOne).not.toHaveBeenCalled();
      });

      it("should allow the assigned doctor to delete the appointment", async () => {
        const appt = pendingAppt();
        Appointment.findById.mockResolvedValue(appt);

        const result = await appointmentService.deleteAppointment(appt._id, doctorUser);

        expect(appt.deleteOne).toHaveBeenCalled();
        expect(result.message).toBe("Appointment deleted");
      });
    });

    describe("cancelAppointment / rescheduleAppointment (modify)", () => {
      const confirmedAppt = () => ({
        _id: new mongoose.Types.ObjectId(),
        status: "confirmed",
        date: new Date("2026-03-01"),
        time: "10:00",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        rescheduleHistory: [],
        save: jest.fn().mockResolvedValue(true),
      });

      it("should return 404 and not cancel when another patient cancels the appointment", async () => {
        const appt = confirmedAppt();
        mockPopulatedFind(appt);

        await expect(
          appointmentService.cancelAppointment(appt._id, "grief", otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.status).toBe("confirmed");
        expect(appt.save).not.toHaveBeenCalled();
        expect(emailService.sendAppointmentCancelled).not.toHaveBeenCalled();
      });

      it("should allow the assigned doctor to cancel the appointment", async () => {
        const appt = confirmedAppt();
        mockPopulatedFind(appt);

        const result = await appointmentService.cancelAppointment(appt._id, "Unavailable", doctorUser);

        expect(result.status).toBe("cancelled");
      });

      it("should return 404 and not reschedule when another patient reschedules the appointment", async () => {
        const appt = confirmedAppt();
        mockPopulatedFind(appt);

        await expect(
          appointmentService.rescheduleAppointment(appt._id, "2026-04-01", "14:00", otherPatientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.time).toBe("10:00");
        expect(appt.rescheduleHistory).toHaveLength(0);
        expect(appt.save).not.toHaveBeenCalled();
      });

      it("should allow the assigned doctor to reschedule the appointment", async () => {
        const appt = confirmedAppt();
        mockPopulatedFind(appt);
        Appointment.findOne.mockResolvedValue(null);

        const result = await appointmentService.rescheduleAppointment(
          appt._id,
          "2026-04-01",
          "14:00",
          doctorUser
        );

        expect(result.time).toBe("14:00");
      });
    });

    describe("transitionStatus (modify)", () => {
      const pendingAppt = () => ({
        _id: new mongoose.Types.ObjectId(),
        status: "pending",
        patient: { _id: PATIENT_ID, fullName: "Alice", email: "alice@test.com" },
        doctor: { _id: DOCTOR_ID, fullName: "Dr. Sarah", email: "sarah@test.com" },
        save: jest.fn().mockResolvedValue(true),
      });

      it("should return 404 when a doctor changes the status of another doctor's appointment", async () => {
        const appt = pendingAppt();
        mockPopulatedFind(appt);

        await expect(
          appointmentService.transitionStatus(appt._id, "confirmed", otherDoctorUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.status).toBe("pending");
        expect(appt.save).not.toHaveBeenCalled();
      });

      it("should not let the patient change the status of their own appointment", async () => {
        const appt = pendingAppt();
        mockPopulatedFind(appt);

        await expect(
          appointmentService.transitionStatus(appt._id, "confirmed", patientUser)
        ).rejects.toMatchObject({ statusCode: 404 });
        expect(appt.status).toBe("pending");
      });
    });
  });
});
