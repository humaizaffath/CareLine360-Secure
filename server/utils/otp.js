const crypto = require("crypto");

// 6 digits from a CSPRNG; leading zeros are valid ("000042")
const generateOtp = () => String(crypto.randomInt(0, 1000000)).padStart(6, "0");

const hashOtp = (otp) =>
  crypto.createHash("sha256").update(otp).digest("hex");

module.exports = { generateOtp, hashOtp };
