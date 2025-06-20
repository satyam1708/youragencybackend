const { PrismaClient, UserType } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const crypto = require("crypto");
const { resend } = require("../utils/email.util");
const { auditLog } = require("../utils/audit.util");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/token.util");

const prisma = new PrismaClient();

const failedOtpAttempts = {};
const MAX_OTP_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

const isPasswordStrong = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);

const sendOtpEmail = async (email, otp) => {
  await resend.emails.send({
    from: "Your Agency <onboarding@resend.dev>",
    to: email,
    subject: "Your OTP Code",
    html: `<p>Your OTP code is: <strong>${otp}</strong>. It will expire in 5 minutes.</p>`,
  });
};

// === Controllers ===

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ errors: errors.array() });

  const { email, password, fullName } = req.body;

  if (!isPasswordStrong(password)) {
    return res.status(400).json({
      message:
        "Password must be at least 8 characters, include uppercase, lowercase, number, and special character.",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser)
      return res.status(409).json({ message: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 12);

    await prisma.user.create({
      data: {
        email,
        passwordHash,
        fullName,
        type: UserType.NORMAL,
        consentGivenAt: new Date(),
      },
    });

    auditLog(email, "Registered");
    res
      .status(201)
      .json({ message: "Registered successfully", csrfToken: req.csrfToken() });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

    await prisma.user.update({
      where: { email },
      data: { otpHash, otpExpiry },
    });

    await sendOtpEmail(email, otp);
    auditLog(email, "OTP sent");

    res.status(200).json({ message: "OTP sent", csrfToken: req.csrfToken() });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ errors: errors.array() });

  const attemptData = failedOtpAttempts[email];
  if (
    attemptData &&
    attemptData.count >= MAX_OTP_ATTEMPTS &&
    Date.now() - attemptData.lastAttemptTime < LOCKOUT_DURATION
  ) {
    return res
      .status(429)
      .json({ message: "Account locked. Try after some time." });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.otpHash)
      return res.status(401).json({ message: "OTP not generated" });

    if (new Date() > user.otpExpiry) {
      await prisma.user.update({
        where: { email },
        data: { otpHash: null, otpExpiry: null },
      });
      return res.status(401).json({ message: "OTP expired" });
    }

    const validOtp = await bcrypt.compare(otp, user.otpHash);
    if (!validOtp) {
      failedOtpAttempts[email] = {
        count: (failedOtpAttempts[email]?.count || 0) + 1,
        lastAttemptTime: Date.now(),
      };
      return res.status(401).json({ message: "Invalid OTP" });
    }

    delete failedOtpAttempts[email];

    const accessToken = generateAccessToken(user.email, user.type);
    const refreshToken = generateRefreshToken(user.email, user.type);

    await prisma.refreshToken.create({
      data: { token: refreshToken, userId: user.id },
    });

    await prisma.user.update({
      where: { email },
      data: { otpHash: null, otpExpiry: null },
    });

    auditLog(email, "Logged in");

    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60 * 1000,
      })
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ message: "Logged in", csrfToken: req.csrfToken() });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const dbToken = await prisma.refreshToken.findUnique({ where: { token } });
    if (!dbToken) {
      await prisma.refreshToken.deleteMany({ where: { userId: decoded.userId } });
      return res.sendStatus(403);
    }

    const user = await prisma.user.findUnique({ where: { email: decoded.email } });
    if (!user) return res.sendStatus(403);

    const accessToken = generateAccessToken(user.email, user.type);
    auditLog(user.email, "Token refreshed");

    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60 * 1000,
      })
      .json({ message: "Token refreshed" });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.sendStatus(403);
  }
};

exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(200).json({ message: "Logged out" });

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    auditLog(decoded.email, "Logged out");

    await prisma.refreshToken.deleteMany({ where: { token } });

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logged out" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.getMe = (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Not logged in" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    res.json({ email: decoded.email, type: decoded.type });
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
};

exports.deleteUser = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "User not found" });

    await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await prisma.user.delete({ where: { email } });

    auditLog(email, "User data deleted");

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(200).json({ message: "User data deleted" });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ message: "Server error" });
  }
};
