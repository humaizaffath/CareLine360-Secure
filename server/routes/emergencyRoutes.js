const express = require('express');
const router = express.Router();
const {
    createEmergency,
    getAllEmergencies,
    getEmergencyById,
    updateStatus,
    getNearestHospital,
} = require('../controllers/emergencyController');
const { validateEmergency, validateStatusUpdate } = require('../validators/emergencyValidator');
const { authMiddleware, roleMiddleware } = require('../middleware/auth');

// All emergency routes require authentication.
router.use(authMiddleware);

// Patients raise SOS; admins and responders monitor and dispatch.
const monitorRoles = roleMiddleware(['admin', 'responder']);

router.post('/', roleMiddleware(['patient']), validateEmergency, createEmergency);
router.get('/', monitorRoles, getAllEmergencies);
router.get('/:id', monitorRoles, getEmergencyById);
router.patch('/:id/status', monitorRoles, validateStatusUpdate, updateStatus);
router.get('/:id/nearest-hospital', monitorRoles, getNearestHospital);

module.exports = router;
