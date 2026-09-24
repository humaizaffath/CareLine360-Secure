const paymentService = require("../services/paymentService");
const { generateReceiptBuffer, uploadReceiptBuffer } = require("../services/receiptPdfService");
const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Doctor = require("../models/Doctor");

// server.js registers an upload error handler before middleware/errorHandler that
// answers every error with 500, so expected client errors (e.g. the 403 from the
// payment access check) are sent here; anything else still goes to next().
const handleError = (error, res, next) => {
  if (error.statusCode >= 400 && error.statusCode < 500) {
    return res.status(error.statusCode).json({ success: false, message: error.message });
  }
  return next(error);
};

const createPayment = async (req, res, next) => {
  try {
    const payment = await paymentService.createPayment(req.body, req.user);
    res.status(201).json({ success: true, data: payment });
  } catch (error) {
    handleError(error, res, next);
  }
};

const getPaymentById = async (req, res, next) => {
  try {
    const payment = await paymentService.getPaymentById(req.params.id, req.user);
    res.json({ success: true, data: payment });
  } catch (error) {
    handleError(error, res, next);
  }
};

const getPaymentByAppointment = async (req, res, next) => {
  try {
    const payment = await paymentService.getPaymentByAppointment(req.params.appointmentId, req.user);
    res.json({ success: true, data: payment });
  } catch (error) {
    handleError(error, res, next);
  }
};

const verifyPayment = async (req, res, next) => {
  try {
    const payment = await paymentService.verifyPayment(req.params.id, req.user);
    res.json({ success: true, data: payment });
  } catch (error) {
    handleError(error, res, next);
  }
};

const failPayment = async (req, res, next) => {
  try {
    const payment = await paymentService.failPayment(req.params.id, req.user);
    res.json({ success: true, data: payment });
  } catch (error) {
    handleError(error, res, next);
  }
};

const getReceipt = async (req, res, next) => {
  try {
    const payment = await paymentService.getPaymentById(req.params.id, req.user);
    if (!payment) {
      const err = new Error("Payment not found");
      err.statusCode = 404;
      throw err;
    }
    if (payment.status !== "verified") {
      const err = new Error("Receipt available only for verified payments");
      err.statusCode = 400;
      throw err;
    }

    // payment.appointment is already populated from getPaymentById, but we need doctor details
    const appointmentId = payment.appointment._id || payment.appointment;
    const appointment = await Appointment.findById(appointmentId).populate("patient doctor");
    if (!appointment) {
      const err = new Error("Appointment not found");
      err.statusCode = 404;
      throw err;
    }

    const doctorProfile = await Doctor.findOne({ userId: appointment.doctor._id }).lean();

    const pdfBuffer = await generateReceiptBuffer({
      patient: appointment.patient,
      appointment,
      payment,
      doctor: doctorProfile || { fullName: appointment.doctor.fullName, specialization: "General" },
    });

    // Non-fatal Cloudinary upload
    try {
      await uploadReceiptBuffer(pdfBuffer);
    } catch (uploadErr) {
      console.warn("Receipt upload to Cloudinary failed (non-fatal):", uploadErr.message);
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="receipt-${payment.transactionRef || payment._id}.pdf"`);
    res.status(200).end(pdfBuffer);
  } catch (error) {
    handleError(error, res, next);
  }
};

module.exports = {
  createPayment,
  getPaymentById,
  getPaymentByAppointment,
  verifyPayment,
  failPayment,
  getReceipt,
};
