const Payment = require("../models/Payment");
const Appointment = require("../models/Appointment");
const crypto = require("crypto");

// Only these patient fields are ever returned; never passwordHash/refreshTokenHash.
const PAYMENT_POPULATE = [
  { path: "appointment" },
  { path: "patient", select: "fullName email phone" },
];

const httpError = (message, statusCode) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

const idOf = (value) => (value?._id || value)?.toString();

/**
 * Allow the payment's patient, the appointment's doctor, or an admin.
 * Denies by default (including when no user is supplied).
 */
const assertPaymentAccess = async (payment, user) => {
  if (user?.role === "admin") return;
  const userId = user?.userId?.toString();
  if (userId) {
    if (user.role === "patient" && idOf(payment.patient) === userId) return;
    if (user.role === "doctor") {
      const appointment = payment.appointment?.doctor
        ? payment.appointment
        : await Appointment.findById(payment.appointment).select("doctor");
      if (appointment && idOf(appointment.doctor) === userId) return;
    }
  }
  throw httpError("Forbidden: you do not have access to this payment", 403);
};

const createPayment = async (data, user) => {
  // A patient can only pay for their own appointment; the payer is always the caller.
  const appointment = await Appointment.findById(data.appointment).select("patient");
  if (!appointment) throw httpError("Appointment not found", 404);
  if (!user?.userId || idOf(appointment.patient) !== user.userId.toString()) {
    throw httpError("Forbidden: you do not have access to this appointment", 403);
  }

  const existing = await Payment.findOne({ appointment: data.appointment });
  if (existing) {
    const error = new Error("Payment already exists for this appointment");
    error.statusCode = 409;
    throw error;
  }

  const payment = await Payment.create({
    appointment: data.appointment,
    patient: user.userId,
    amount: data.amount,
    currency: data.currency,
    method: data.method,
  });
  return payment.populate(PAYMENT_POPULATE);
};

const getPaymentById = async (id, user) => {
  const payment = await Payment.findById(id).populate(PAYMENT_POPULATE);
  if (!payment) {
    const error = new Error("Payment not found");
    error.statusCode = 404;
    throw error;
  }
  await assertPaymentAccess(payment, user);
  return payment;
};

const getPaymentByAppointment = async (appointmentId, user) => {
  const payment = await Payment.findOne({ appointment: appointmentId }).populate(PAYMENT_POPULATE);
  if (!payment) {
    const error = new Error("Payment not found for this appointment");
    error.statusCode = 404;
    throw error;
  }
  await assertPaymentAccess(payment, user);
  return payment;
};

const verifyPayment = async (id, user) => {
  const payment = await Payment.findById(id);
  if (!payment) {
    const error = new Error("Payment not found");
    error.statusCode = 404;
    throw error;
  }
  await assertPaymentAccess(payment, user);

  if (payment.status !== "pending") {
    const error = new Error("Payment is not in pending status");
    error.statusCode = 400;
    throw error;
  }

  payment.status = "verified";
  payment.verifiedAt = new Date();
  payment.transactionRef = `TXN-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  await payment.save();
  return payment.populate(PAYMENT_POPULATE);
};

const failPayment = async (id, user) => {
  const payment = await Payment.findById(id);
  if (!payment) {
    const error = new Error("Payment not found");
    error.statusCode = 404;
    throw error;
  }
  await assertPaymentAccess(payment, user);

  if (payment.status !== "pending") {
    const error = new Error("Payment is not in pending status");
    error.statusCode = 400;
    throw error;
  }

  payment.status = "failed";
  await payment.save();
  return payment.populate(PAYMENT_POPULATE);
};

module.exports = {
  createPayment,
  getPaymentById,
  getPaymentByAppointment,
  verifyPayment,
  failPayment,
  PAYMENT_POPULATE,
};
