const emergencyService = require('../services/emergencyService');

const createEmergency = async (req, res, next) => {
    try {
        // The case is always raised for the authenticated patient; a client-supplied
        // `patient` is ignored so one user cannot file (or spoof) an SOS for another.
        const { description, latitude, longitude } = req.body;
        const emergency = await emergencyService.createEmergency({
            patient: req.user.userId,
            description,
            latitude,
            longitude,
        });
        res.status(201).json({ success: true, data: emergency });
    } catch (error) {
        next(error);
    }
};

const getAllEmergencies = async (req, res, next) => {
    try {
        const emergencies = await emergencyService.getAllEmergencies();
        res.status(200).json({ success: true, data: emergencies });
    } catch (error) {
        next(error);
    }
};

const getEmergencyById = async (req, res, next) => {
    try {
        const emergency = await emergencyService.getEmergencyById(req.params.id);
        if (!emergency) {
            return res.status(404).json({ success: false, error: 'Emergency case not found' });
        }
        res.status(200).json({ success: true, data: emergency });
    } catch (error) {
        next(error);
    }
};

const updateStatus = async (req, res, next) => {
    try {
        const emergency = await emergencyService.updateStatus(req.params.id, req.body);
        res.status(200).json({ success: true, data: emergency });
    } catch (error) {
        next(error);
    }
};

const getNearestHospital = async (req, res, next) => {
    try {
        const hospital = await emergencyService.getNearestHospital(req.params.id);
        res.status(200).json({ success: true, nearestHospital: hospital });
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createEmergency,
    getAllEmergencies,
    getEmergencyById,
    updateStatus,
    getNearestHospital,
};
