const rateLimit = require("express-rate-limit");

exports.otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many OTP attempts, please try again later.",
});
