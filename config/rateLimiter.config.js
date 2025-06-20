// config/rateLimiter.config.js
const rateLimit = require("express-rate-limit");

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max requests per windowMs
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // max OTP attempts
  message: "Too many OTP attempts, please try again later.",
});

module.exports = {
  generalLimiter,
  otpLimiter,
};
