const { PrismaClient, UserType } = require("@prisma/client");
const { validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const {
  isPasswordStrong,
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/password.util");
const { sendOtpEmail } = require("./email.service");
const { auditLog } = require("../utils/audit.util");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient();
const failedOtpAttempts = {};
const MAX_OTP_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password, fullName } = req.body;

  if (!isPasswordStrong(password)) {
    return res.status(400).json({
      message: "Weak password. Must include uppercase, lowercase, number & special character.",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(409).json({ message: "User already exists" });

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
    res.status(201).json({ message: "Registered successfully", csrfToken: req.csrfToken() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

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
};

exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  const attemptData = failedOtpAttempts[email];
  if (attemptData && attemptData.count >= MAX_OTP_ATTEMPTS && (Date.now() - attemptData.lastAttemptTime) < LOCKOUT_DURATION) {
    return res.status(429).json({ message: "Too many OTP attempts. Try again later." });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.otpHash) return res.status(401).json({ message: "OTP not generated" });

  if (new Date() > user.otpExpiry) {
    await prisma.user.update({ where: { email }, data: { otpHash: null, otpExpiry: null } });
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

  await prisma.refreshToken.create({ data: { token: refreshToken, userId: user.id } });
  await prisma.user.update({ where: { email }, data: { otpHash: null, otpExpiry: null } });

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
    .json({ message: "Logged in successfully", csrfToken: req.csrfToken() });
};

exports.refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const dbToken = await prisma.refreshToken.findUnique({ where: { token } });
    if (!dbToken) return res.sendStatus(403);

    const user = await prisma.user.findUnique({ where: { email: decoded.email } });
    if (!user) return res.sendStatus(403);

    const newAccessToken = generateAccessToken(user.email, user.type);
    auditLog(user.email, "Token refreshed");

    res
      .cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60 * 1000,
      })
      .json({ message: "Token refreshed" });
  } catch (err) {
    res.sendStatus(403);
  }
};

exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(200).json({ message: "Logged out" });

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    await prisma.refreshToken.deleteMany({ where: { token } });
    auditLog(decoded.email, "Logged out");

    res.clearCookie("accessToken").clearCookie("refreshToken").json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.getUserInfo = (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Not logged in" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    res.json({ email: decoded.email, type: decoded.type });
  } catch {
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

    auditLog(email, "User deleted");
    res.clearCookie("accessToken").clearCookie("refreshToken").json({ message: "User deleted" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
};

exports.getCsrfToken = (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
};

exports.getPrivacyPolicy = (_, res) => {
  res.json({ url: "https://yourdomain.com/privacy-policy" });
};
