const appointmentService = require("../services/appointmentService");

const createAppointment = async (req, res, next) => {
  try {
    // SECURITY (V2): the owner is the authenticated user from the JWT (set by
    // authMiddleware), passed separately instead of trusting req.body.patient.
    const appointment = await appointmentService.createAppointment(req.body, req.user.userId);
    res.status(201).json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const getAppointments = async (req, res, next) => {
  try {
    // SECURITY (V1): req.user (from the verified JWT) is passed to every service
    // call below so the service can enforce ownership of each appointment.
    const result = await appointmentService.getAppointments(req.query, req.user);
    res.json({ success: true, ...result });
  } catch (error) {
    next(error);
  }
};

const getAppointmentById = async (req, res, next) => {
  try {
    const appointment = await appointmentService.getAppointmentById(req.params.id, req.user);
    res.json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const updateAppointment = async (req, res, next) => {
  try {
    const appointment = await appointmentService.updateAppointment(req.params.id, req.body, req.user);
    res.json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const deleteAppointment = async (req, res, next) => {
  try {
    const result = await appointmentService.deleteAppointment(req.params.id, req.user);
    res.json({ success: true, ...result });
  } catch (error) {
    next(error);
  }
};

const transitionStatus = async (req, res, next) => {
  try {
    const appointment = await appointmentService.transitionStatus(req.params.id, req.body.status, req.user);
    res.json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const rescheduleAppointment = async (req, res, next) => {
  try {
    const appointment = await appointmentService.rescheduleAppointment(
      req.params.id,
      req.body.date,
      req.body.time,
      req.user
    );
    res.json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const cancelAppointment = async (req, res, next) => {
  try {
    const appointment = await appointmentService.cancelAppointment(req.params.id, req.body.reason, req.user);
    res.json({ success: true, data: appointment });
  } catch (error) {
    next(error);
  }
};

const getAppointmentStats = async (req, res, next) => {
  try {
    const stats = await appointmentService.getAppointmentStats(req.user.userId, req.user.role);
    res.json({ success: true, data: stats });
  } catch (error) {
    next(error);
  }
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
