const express = require("express");
const router = express.Router();
const validateRequest = require("../middleware/validateRequest");
const { createPaymentRules, paymentIdRules } = require("../validators/paymentValidator");
const {
  createPayment,
  getPaymentById,
  getPaymentByAppointment,
  verifyPayment,
  failPayment,
  getReceipt,
} = require("../controllers/paymentController");
const { authMiddleware, roleMiddleware } = require("../middleware/auth");

// All payment routes require authentication. Object-level access (payment's
// patient, appointment's doctor, or admin) is enforced in paymentService.
router.use(authMiddleware, roleMiddleware(["patient", "doctor", "admin"]));

router.post("/", roleMiddleware(["patient"]), createPaymentRules, validateRequest, createPayment);
router.get("/appointment/:appointmentId", getPaymentByAppointment);
router.get("/:id", paymentIdRules, validateRequest, getPaymentById);
router.patch("/:id/verify", paymentIdRules, validateRequest, verifyPayment);
router.patch("/:id/fail", paymentIdRules, validateRequest, failPayment);
router.get("/:id/receipt", paymentIdRules, validateRequest, getReceipt);

module.exports = router;
