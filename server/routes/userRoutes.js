const express = require("express");
const router = express.Router();
const { authMiddleware } = require("../middleware/auth");
const { getUsers, getUserById } = require("../controllers/userController");

// All user routes require authentication; per-role rules live in the controller.
router.use(authMiddleware);

router.get("/", getUsers);
router.get("/:id", getUserById);

module.exports = router;
