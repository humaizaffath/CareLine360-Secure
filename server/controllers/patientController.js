const Patient = require("../models/Patient");
const User = require("../models/User");
const MedicalRecord = require("../models/MedicalRecord");
const Prescription = require("../models/Prescription");
const Doctor = require("../models/Doctor");
const Hospital = require("../models/Hospital");
const { verifyPassword } = require("../utils/password");
const EmergencyCase = require("../models/EmergencyCase");

const { calcPatientProfileStrength } = require("../services/profileStrength");

const { GoogleGenerativeAI } = require("@google/generative-ai");

const getMyProfile = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    const patient = await Patient.findOne({
      userId,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
    if (!patient) return res.status(404).json({ success: false, message: "Profile not found" });

    const user = await User.findById(userId).select("email isVerified role");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // ✅ Document count (for now no doc module => 0)
    const docsCount = 0;

    const profileStrength = calcPatientProfileStrength({ patient, docsCount });

    // optional: store latest score in DB
    if (patient.profileStrength !== profileStrength.score) {
      patient.profileStrength = profileStrength.score;
      await patient.save();
    }

    return res.json({
      fullName: patient.fullName,
      patientId: patient.patientId,
      email: user.email,
      isVerified: user.isVerified,
      role: user.role,

      avatarUrl: patient.avatarUrl,

      dob: patient.dob,
      gender: patient.gender,
      address: patient.address,
      nic: patient.nic,
      emergencyContact: patient.emergencyContact,
      bloodGroup: patient.bloodGroup,
      allergies: patient.allergies,
      chronicConditions: patient.chronicConditions,
      heightCm: patient.heightCm,
      weightKg: patient.weightKg,

      profileStrength, // ✅ includes score + breakdown + missing
    });
  } catch (e) {
    next(e);
  }
};

const updateMyProfile = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    // Validation is now handled by patientValidator + validateRequest middleware.
    // This controller only handles the update logic.

    const {
      dob,
      gender,
      nic,
      address,
      emergencyContact,
      heightCm,
      weightKg,
      bloodGroup,
      allergies,
      chronicConditions,
      fullName,
    } = req.body;

    const update = {};

    // Basic fields
    if (fullName !== undefined) update.fullName = fullName;
    if (dob !== undefined) update.dob = dob;
    if (gender !== undefined) update.gender = gender;
    if (nic !== undefined) update.nic = nic;

    // Nested address
    if (address) {
      update["address.district"] = address.district;
      update["address.city"] = address.city;
      update["address.line1"] = address.line1;
    }

    // Nested emergency contact
    if (emergencyContact) {
      update["emergencyContact.name"] = emergencyContact.name;
      update["emergencyContact.phone"] = emergencyContact.phone;
      update["emergencyContact.relationship"] =
        emergencyContact.relationship;
    }

    // Medical
    if (bloodGroup !== undefined) update.bloodGroup = bloodGroup;
    if (allergies !== undefined) update.allergies = allergies;
    if (chronicConditions !== undefined)
      update.chronicConditions = chronicConditions;
    if (heightCm !== undefined) update.heightCm = heightCm;
    if (weightKg !== undefined) update.weightKg = weightKg;

    const patient = await Patient.findOneAndUpdate(
      {
        userId,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
      { $set: update },
      { new: true, runValidators: true },
    );

    if (!patient) return res.status(404).json({ success: false, message: "Profile not found" });

    return res.json({ message: "Profile updated successfully", patient });
  } catch (e) {
    if (e?.name === "ValidationError") {
      const messages = Object.values(e.errors).map((err) => err.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    next(e);
  }
};

const uploadAvatar = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    if (!req.file?.path) {
      return res.status(400).json({ success: false, message: "No image uploaded" });
    }

    // multer-storage-cloudinary gives secure URL in req.file.path
    const avatarUrl = req.file.path;

    const patient = await Patient.findOneAndUpdate(
      {
        userId,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
      { $set: { avatarUrl } },
      { returnDocument: "after", runValidators: true },
    );

    if (!patient) return res.status(404).json({ success: false, message: "Profile not found" });

    return res.json({ message: "Avatar updated", avatarUrl });
  } catch (e) {
    next(e);
  }
};

const removeAvatar = async (req, res) => {
  try {
    const userId = req.user.userId;

    const patient = await Patient.findOneAndUpdate(
      {
        userId,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
      { $set: { avatarUrl: null } },
      { new: true }
    );

    if (!patient) return res.status(404).json({ message: "Profile not found" });

    return res.json({ message: "Avatar removed", avatarUrl: null });
  } catch (e) {
    console.error("REMOVE AVATAR ERROR ❌", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const deactivateMyAccount = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    // 1) Deactivate user account
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          isActive: false,
          status: "SUSPENDED", // or "REJECTED"/"PENDING" - your choice
          refreshTokenHash: null,
        },
      },
      { returnDocument: "after" }, // mongoose v7+ (instead of { new: true })
    );

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // 2) Soft delete patient profile (if exists)
    await Patient.findOneAndUpdate(
      { userId },
      { $set: { isDeleted: true } },
      { returnDocument: "after" },
    );

    return res.json({ message: "Account deactivated successfully" });
  } catch (e) {
    next(e);
  }
};

const reactivateAccount = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: "identifier and password required" });
    }

    const user = await User.findOne({
      $or: [{ email: identifier.toLowerCase() }, { phone: identifier }],
    });

    // Same 401 for unknown account and wrong password (CWE-203/204)
    const ok = await verifyPassword(user, password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    user.isActive = true;
    user.status = "ACTIVE";
    await user.save();

    await Patient.findOneAndUpdate(
      { userId: user._id },
      { $set: { isDeleted: false } }
    );

    return res.json({ message: "Account reactivated successfully" });
  } catch (e) {
    console.error("REACTIVATE ERROR:", e);
    return res.status(500).json({ message: e.message || "Server error" });
  }
};

const medicalRecord = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    // 1) find patient profile (because medicalrecords uses patientId = Patient._id)
    const patient = await Patient.findOne({
      userId,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });

    if (!patient)
      return res.status(404).json({ success: false, message: "Patient profile not found" });

    // 2) fetch medical records
    const histories = await MedicalRecord.find({
      patientId: patient._id,
      isDeleted: false,
    })
      .populate("doctorId") // returns Doctor document (fullName, specialization, etc.)
      .populate("appointmentId") // if linked later
      .populate("prescriptionId") // if linked later
      .sort({ visitDate: -1 });

    return res.json({ histories });
  } catch (e) {
    next(e);
  }
};

const explainMedicalText = async (req, res, next) => {
  try {
    const { text, language } = req.body;

    if (!text) {
      return res.status(400).json({ success: false, message: "Text is required" });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ success: false, message: "Gemini API key not configured" });
    }

    const genAI = new GoogleGenerativeAI(apiKey);

    // gemini-2.0-flash-lite has a separate (more generous) free-tier quota bucket
    const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash-lite" });

    // Default language = English
    const selectedLanguage = language || "english";

    const result = await model.generateContent(
      `Explain this medical information in simple language for a patient.

      Language: ${selectedLanguage}

      Do NOT use markdown formatting.
      Do NOT use headings.
      Do NOT use bold text.
      Do NOT give medical advice.
      Do NOT change dosage.
      Only explain meaning clearly.

      ${text}`,
    );

    const explanation = result.response.text();

    return res.json({
      language: selectedLanguage,
      explanation,
    });
  } catch (error) {
    // Detect quota / rate-limit errors (HTTP 429 from Google's API)
    const errMsg = error?.message || "";
    const isQuota =
      errMsg.includes("429") ||
      errMsg.includes("Too Many Requests") ||
      errMsg.includes("quota") ||
      errMsg.includes("RESOURCE_EXHAUSTED");

    if (isQuota) {
      return res.status(429).json({
        success: false,
        message: "AI quota exceeded. Please try again in a few minutes.",
        detail: errMsg,
      });
    }

    return res.status(500).json({
      success: false,
      message: "AI service error",
      detail: errMsg || "Unknown error",
    });
  }
};

/**
 * GET /api/patient/me/medical-records
 * Patient fetch their own medical records
 */
const getMyMedicalRecords = async (req, res, next) => {
  try {
    const patientId = req.user.userId; // from authMiddleware

    const records = await MedicalRecord.find({
      patientId,
      isDeleted: false,
    }).sort({ createdAt: -1 });

    return res.json({ count: records.length, records });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/patient/me/prescriptions
 * Patient fetch their own prescriptions
 */
const getMyPrescriptions = async (req, res, next) => {
  try {
    const patientId = req.user.userId;

    const prescriptions = await Prescription.find({ patientId }).sort({
      createdAt: -1,
    });

    return res.json({ count: prescriptions.length, prescriptions });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/patient/doctors
 * Patient fetch all doctors (users with role doctor)
 */
const getAllDoctorsForPatient = async (req, res, next) => {
  try {
    const { q = "" } = req.query;

    const filter = { isDeleted: { $ne: true } };

    if (q) {
      filter.$or = [
        { fullName: { $regex: q, $options: "i" } },
        { specialization: { $regex: q, $options: "i" } },
      ];
    }

    const doctors = await Doctor.find(filter)
      .select(
        "fullName specialization phone avatarUrl qualifications experience bio consultationFee rating totalRatings availabilitySlots doctorId licenseNumber",
      )
      .sort({ fullName: 1 });

    return res.json(doctors);
  } catch (e) {
    next(e);
  }
};

const getDoctorDetailsForPatient = async (req, res, next) => {
  try {
    const doc = await Doctor.findOne({
      _id: req.params.id,
      isDeleted: { $ne: true },
    });

    if (!doc) return res.status(404).json({ success: false, message: "Doctor not found" });

    return res.json(doc);
  } catch (e) {
    // Handle invalid ObjectId in params gracefully
    if (e.name === "CastError") {
      return res.status(400).json({ success: false, message: "Invalid doctor ID format" });
    }
    next(e);
  }
};

const getAllHospitalsForPatient = async (req, res, next) => {
  try {
    const { q = "" } = req.query;

    const filter = { isActive: true };

    if (q) {
      filter.$or = [
        { name: { $regex: q, $options: "i" } },
        { address: { $regex: q, $options: "i" } },
        { contact: { $regex: q, $options: "i" } },
      ];
    }

    const hospitals = await Hospital.find(filter)
      .select("name address contact lat lng isActive")
      .sort({ name: 1 });

    res.json(hospitals);
  } catch (e) {
    next(e);
  }
};

const getHospitalDetailsForPatient = async (req, res, next) => {
  try {
    const hospital = await Hospital.findOne({
      _id: req.params.id,
      isActive: true,
    }).select("name address contact lat lng isActive");

    if (!hospital)
      return res.status(404).json({ success: false, message: "Hospital not found" });

    res.json(hospital);
  } catch (e) {
    // Handle invalid ObjectId in params gracefully
    if (e.name === "CastError") {
      return res.status(400).json({ success: false, message: "Invalid hospital ID format" });
    }
    next(e);
  }
};

const createEmergency = async (req, res, next) => {
  try {
    const emergencyService = require("../services/emergencyService");
    const emergency = await emergencyService.createEmergency({
      ...req.body,
      patient: req.user.userId, // 👈 take patient from token
    });

    res.status(201).json({ success: true, data: emergency });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getMyProfile,
  updateMyProfile,
  uploadAvatar,
  deactivateMyAccount,
  reactivateAccount,
  removeAvatar,
  medicalRecord,
  explainMedicalText,
  getMyMedicalRecords,
  getMyPrescriptions,
  getAllDoctorsForPatient,
  getDoctorDetailsForPatient,
  getAllHospitalsForPatient,
  getHospitalDetailsForPatient,
  createEmergency,
};
