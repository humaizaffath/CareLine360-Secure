const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// Hash of a random value nobody knows. Comparing against it when the account
// does not exist keeps the response time the same as for a real account.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), 10);

// Returns false for a missing user or a non-string password, without revealing
// which: bcrypt always runs, so every failure takes the same time
const verifyPassword = async (user, password) => {
  const isString = typeof password === "string";
  const ok = await bcrypt.compare(isString ? password : "", user?.passwordHash || DUMMY_PASSWORD_HASH);
  return Boolean(user) && isString && ok;
};

module.exports = { verifyPassword };
