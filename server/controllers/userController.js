const User = require("../models/User");

// Explicit allow-lists so secrets (passwordHash, refreshTokenHash) or any
// future sensitive field are never serialised to clients.
const ADMIN_USER_FIELDS = "_id role fullName email phone isVerified isActive status lastLoginAt createdAt updatedAt";
const PUBLIC_DOCTOR_FIELDS = "_id role fullName email";
const ROLES = ["patient", "doctor", "responder", "admin"];

const getUsers = async (req, res, next) => {
  try {
    const { role } = req.query;
    if (role !== undefined && (typeof role !== "string" || !ROLES.includes(role))) {
      return res.status(400).json({ success: false, message: "Invalid role filter" });
    }

    const isAdmin = req.user.role === "admin";
    // Non-admins may only list doctors (used by appointment booking).
    if (!isAdmin && role !== "doctor") {
      return res.status(403).json({ success: false, message: "Forbidden: role not allowed" });
    }

    const query = role ? { role } : {};
    const fields = isAdmin ? ADMIN_USER_FIELDS : PUBLIC_DOCTOR_FIELDS;
    const users = await User.find(query).select(fields).sort("email");
    res.json({ success: true, data: users });
  } catch (error) {
    next(error);
  }
};

const getUserById = async (req, res, next) => {
  try {
    // Admins can view any user; everyone else only themselves.
    if (req.user.role !== "admin" && req.user.userId.toString() !== req.params.id) {
      return res.status(403).json({ success: false, message: "Forbidden: role not allowed" });
    }

    const user = await User.findById(req.params.id).select(ADMIN_USER_FIELDS);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    res.json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

module.exports = { getUsers, getUserById };
