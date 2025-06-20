const jwt = require("jsonwebtoken");

exports.isPasswordStrong = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);

exports.generateAccessToken = (email, type) =>
  jwt.sign({ email, type }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

exports.generateRefreshToken = (email, type) =>
  jwt.sign({ email, type }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
