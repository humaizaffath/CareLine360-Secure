const Appointment = require("../models/Appointment");
const User = require("../models/User");
const emailService = require("./emailService");

const getAppointmentStats = async (userId, role) => {
  const match = {};
  if (role === "patient") match.patient = userId;
  if (role === "doctor") match.doctor = userId;

  const [total, pending, confirmed, completed, cancelled] = await Promise.all([
    Appointment.countDocuments(match),
    Appointment.countDocuments({ ...match, status: "pending" }),
    Appointment.countDocuments({ ...match, status: "confirmed" }),
    Appointment.countDocuments({ ...match, status: "completed" }),
    Appointment.countDocuments({ ...match, status: "cancelled" }),
  ]);

  return { total, pending, confirmed, completed, cancelled };
};

const VALID_TRANSITIONS = {
  pending: ["confirmed", "cancelled"],
  confirmed: ["completed", "cancelled"],
};

// SECURITY (V2): Mass Assignment mitigation – CWE-915 / OWASP A08:2021.
// Previously the whole request body was saved (Appointment.create(req.body) and
// Object.assign(appointment, req.body)), so a patient could set fields the server
// must own. These allow-lists name the ONLY fields a patient may supply; anything
// not listed is dropped. Server-controlled fields that are therefore rejected:
//   status             – starts as "pending"; changed only by a doctor via /status
//   patient            – always taken from the authenticated JWT
//   meetingUrl         – generated server-side by the meeting services
//   reminderSent       – managed by the reminder scheduler
//   cancellationReason – set only through the /cancel endpoint
//   rescheduleHistory  – appended only through the /reschedule endpoint
const CREATE_FIELDS = ["doctor", "date", "time", "consultationType", "symptoms", "notes", "priority"];

// Update is stricter than create: the patient chooses a doctor when booking, but
// may not reassign an existing appointment to a different doctor afterwards.
const UPDATE_FIELDS = ["date", "time", "consultationType", "symptoms", "notes", "priority"];

// Builds a new object containing only allow-listed keys. Using an allow-list
// (rather than deleting known-bad keys) means any unexpected or future property
// in the request body never reaches the Mongoose document.
const pickFields = (data, allowed) => {
  const picked = {};
  for (const key of allowed) {
    if (data[key] !== undefined) picked[key] = data[key];
  }
  return picked;
};

// SECURITY (V1): IDOR / BOLA mitigation – CWE-639 / OWASP A01:2021.
// Previously every /:id operation loaded the appointment by id alone, so any
// authenticated user could read, edit, cancel or delete someone else's appointment.
// `user` is req.user (set by authMiddleware from the verified JWT), never the body.
// `parties` lists which side of the appointment may perform the action. A mismatch
// returns the same 404 as a missing appointment so ids cannot be probed.
const assertParticipant = (appointment, user, parties) => {
  const userId = user?.userId?.toString();
  const allowed = parties.some((party) => {
    const ref = appointment[party];
    const ownerId = (ref?._id ?? ref)?.toString();
    return !!userId && ownerId === userId;
  });

  if (!allowed) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }
};

const checkDoubleBooking = async (doctorId, date, time, excludeId = null) => {
  const startOfDay = new Date(date);
  startOfDay.setHours(0, 0, 0, 0);
  const endOfDay = new Date(date);
  endOfDay.setHours(23, 59, 59, 999);

  const query = {
    doctor: doctorId,
    date: { $gte: startOfDay, $lte: endOfDay },
    time: time,
    status: { $nin: ["cancelled"] },
  };

  if (excludeId) {
    query._id = { $ne: excludeId };
  }

  const existing = await Appointment.findOne(query);
  return !!existing;
};

const createAppointment = async (body, patientId) => {
  // SECURITY (V2): patient comes from the verified JWT (passed in by the controller)
  // and is applied last, so a "patient" key in the body can never set the owner.
  const data = { ...pickFields(body, CREATE_FIELDS), patient: patientId };

  const isBooked = await checkDoubleBooking(data.doctor, data.date, data.time);
  if (isBooked) {
    const error = new Error("Doctor already has an appointment at this date and time");
    error.statusCode = 409;
    throw error;
  }

  const appointment = await Appointment.create(data);
  const populated = await Appointment.findById(appointment._id).populate("patient doctor");

  try {
    await emailService.sendAppointmentCreated(populated, populated.patient, populated.doctor);
  } catch (e) {
    console.error("Email notification failed:", e.message);
  }

  return populated;
};

const getAppointments = async (filters = {}, user) => {
  const {
    status, doctor, patient, dateFrom, dateTo,
    page = 1, limit = 10, sort = "-createdAt",
  } = filters;

  const query = {};

  if (status) {
    const statuses = status.split(",").map((s) => s.trim());
    query.status = statuses.length > 1 ? { $in: statuses } : statuses[0];
  }
  if (doctor) query.doctor = doctor;
  if (patient) query.patient = patient;

  // SECURITY (V1): scope the list to the authenticated user instead of trusting
  // the client-supplied patient/doctor query params. Admins keep full access.
  if (user?.role === "patient") {
    query.patient = user.userId;
  } else if (user?.role === "doctor") {
    query.doctor = user.userId;
  } else if (user?.role !== "admin") {
    const error = new Error("Forbidden: role not allowed");
    error.statusCode = 403;
    throw error;
  }
  if (dateFrom || dateTo) {
    query.date = {};
    if (dateFrom) query.date.$gte = new Date(dateFrom);
    if (dateTo) query.date.$lte = new Date(dateTo);
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);
  const total = await Appointment.countDocuments(query);

  const appointments = await Appointment.find(query)
    .populate("patient doctor")
    .sort(sort)
    .skip(skip)
    .limit(parseInt(limit));

  return {
    appointments,
    pagination: {
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      pages: Math.ceil(total / parseInt(limit)),
    },
  };
};

const getAppointmentById = async (id, user) => {
  const appointment = await Appointment.findById(id).populate("patient doctor").lean();
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["patient", "doctor"]);

  // Enrich with Doctor profile (fullName, specialization, avatarUrl) from Doctor model
  if (appointment.doctor?._id) {
    const Doctor = require("../models/Doctor");
    const doctorProfile = await Doctor.findOne({ userId: appointment.doctor._id, isDeleted: false })
      .select("fullName specialization avatarUrl doctorId")
      .lean();
    if (doctorProfile) {
      appointment.doctorProfile = doctorProfile;
    }
  }

  return appointment;
};

const updateAppointment = async (id, body, user) => {
  // SECURITY (V2): only allow-listed fields are passed to Object.assign below.
  const data = pickFields(body, UPDATE_FIELDS);
  const appointment = await Appointment.findById(id);
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["patient"]);

  if (appointment.status !== "pending") {
    const error = new Error("Can only update pending appointments");
    error.statusCode = 400;
    throw error;
  }

  if (data.date && data.time) {
    const isBooked = await checkDoubleBooking(appointment.doctor, data.date, data.time, id);
    if (isBooked) {
      const error = new Error("Doctor already has an appointment at this date and time");
      error.statusCode = 409;
      throw error;
    }
  }

  Object.assign(appointment, data);
  await appointment.save();
  return appointment.populate("patient doctor");
};

const deleteAppointment = async (id, user) => {
  const appointment = await Appointment.findById(id);
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["patient", "doctor"]);

  if (appointment.status !== "pending") {
    const error = new Error("Can only delete pending appointments");
    error.statusCode = 400;
    throw error;
  }

  await appointment.deleteOne();
  return { message: "Appointment deleted" };
};

const transitionStatus = async (id, newStatus, user) => {
  const appointment = await Appointment.findById(id).populate("patient doctor");
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["doctor"]);

  const allowed = VALID_TRANSITIONS[appointment.status];
  if (!allowed || !allowed.includes(newStatus)) {
    const error = new Error(
      `Cannot transition from "${appointment.status}" to "${newStatus}"`
    );
    error.statusCode = 400;
    throw error;
  }

  appointment.status = newStatus;
  await appointment.save();

  try {
    if (newStatus === "confirmed") {
      await emailService.sendAppointmentConfirmed(appointment, appointment.patient, appointment.doctor);
    }
  } catch (e) {
    console.error("Email notification failed:", e.message);
  }

  return appointment;
};

const rescheduleAppointment = async (id, newDate, newTime, user) => {
  const appointment = await Appointment.findById(id).populate("patient doctor");
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["patient", "doctor"]);

  if (appointment.status !== "confirmed") {
    const error = new Error("Can only reschedule confirmed appointments");
    error.statusCode = 400;
    throw error;
  }

  const isBooked = await checkDoubleBooking(appointment.doctor._id, newDate, newTime, id);
  if (isBooked) {
    const error = new Error("Doctor already has an appointment at this date and time");
    error.statusCode = 409;
    throw error;
  }

  appointment.rescheduleHistory.push({
    previousDate: appointment.date,
    previousTime: appointment.time,
  });

  appointment.date = new Date(newDate);
  appointment.time = newTime;
  appointment.reminderSent = false;
  await appointment.save();

  try {
    await emailService.sendAppointmentRescheduled(appointment, appointment.patient, appointment.doctor);
  } catch (e) {
    console.error("Email notification failed:", e.message);
  }

  return appointment;
};

const cancelAppointment = async (id, reason, user) => {
  const appointment = await Appointment.findById(id).populate("patient doctor");
  if (!appointment) {
    const error = new Error("Appointment not found");
    error.statusCode = 404;
    throw error;
  }

  assertParticipant(appointment, user, ["patient", "doctor"]);

  if (appointment.status === "completed" || appointment.status === "cancelled") {
    const error = new Error("Cannot cancel a completed or already cancelled appointment");
    error.statusCode = 400;
    throw error;
  }

  appointment.status = "cancelled";
  appointment.cancellationReason = reason;
  await appointment.save();

  try {
    await emailService.sendAppointmentCancelled(appointment, appointment.patient, appointment.doctor);
  } catch (e) {
    console.error("Email notification failed:", e.message);
  }

  return appointment;
};

module.exports = {
  createAppointment,
  getAppointments,
  getAppointmentById,
  updateAppointment,
  deleteAppointment,
  transitionStatus,
  rescheduleAppointment,
  cancelAppointment,
  getAppointmentStats,
};
