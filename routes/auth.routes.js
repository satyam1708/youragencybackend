const express = require("express");
const { body, validationResult } = require("express-validator");
const authService = require("../services/auth.service");
const { otpLimiter } = require("../utils/rate.util");

const router = express.Router();

router.post(
  "/register",
  body("email").isEmail().normalizeEmail(),
  body("password").isString(),
  body("fullName").isString().isLength({ min: 3 }),
  authService.register
);

router.post(
  "/login",
  body("email").isEmail().normalizeEmail(),
  body("password").isString(),
  authService.login
);

router.post(
  "/verify-otp",
  otpLimiter,
  body("email").isEmail().normalizeEmail(),
  body("otp").isLength({ min: 6, max: 6 }).isNumeric(),
  authService.verifyOtp
);

router.post("/refresh-token", authService.refreshToken);
router.post("/logout", authService.logout);
router.get("/me", authService.getUserInfo);
router.post("/delete", authService.deleteUser);
router.get("/csrf-token", authService.getCsrfToken);
router.get("/privacy-policy", authService.getPrivacyPolicy);

module.exports = router;
