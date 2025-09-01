const express = require("express");
const axios = require("axios");
const { authenticateUser } = require("../middlewares/auth");
const { PrismaClient } = require("@prisma/client");
const { fetchCallsOptimized } = require("../services/voiceaiService");
const prisma = new PrismaClient();
require("dotenv").config();
const router = express.Router();

const VOICE_AI_API_BASE_URL = "https://api.vapi.ai";
const allowedOrigins = process.env.FRONTEND_URLS
  ? process.env.FRONTEND_URLS.split(",")
  : [
      "http://localhost:5173",
      "http://localhost:8080",
      "https://voice.cognitiev.com",
      "https://youragency2.netlify.app",
      "https://suisseai.netlify.app",
      "https://your-newai.netlify.app",
      "https://propai.cognitiev.com",
      "https://Vaani.cognitiev.com",
      "https://Voice2.cognitiev.com",
      "https://Voice3.cognitiev.com",
      "https://Voice4.cognitiev.com",
    ];

function getCorsHeaders(origin) {
  const isAllowed = allowedOrigins.includes(origin);
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : "", // ✅ must be a single string
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
router.use((req, res, next) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  // Apply CORS headers
  res.set(corsHeaders);

  // Manually handle OPTIONS requests for CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(204).end(); // Preflight success response
  }

  next(); // Continue to actual route
});

// Middleware to validate API key and build headers
function buildHeaders(req) {
  const voiceAIKey = process.env.VAPI_API_KEY;
  if (!voiceAIKey) {
    throw new Error("VOICEAIKEY is not set in environment variables.");
  }

  const headers = {
    Authorization: `Bearer ${voiceAIKey}`,
    "Content-Type": "application/json",
  };

  const allowedForwardHeaders = ["user-agent", "accept", "accept-language"];
  allowedForwardHeaders.forEach((key) => {
    if (req.headers[key]) headers[key] = req.headers[key];
  });

  return headers;
}

// Helper to forward request to VoiceAI API
async function proxyRequest(req, res, endpointPath, methodOverride = null) {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);
  try {
    const headers = buildHeaders(req);
    const targetUrl = `${VOICE_AI_API_BASE_URL}${endpointPath}${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`;
    const method = methodOverride || req.method;

    const response = await axios({
      url: targetUrl,
      method,
      headers,
      data: ["GET", "HEAD"].includes(method) ? undefined : req.body,
      responseType: "text",
      validateStatus: null,
    });

    res.set({
      ...corsHeaders,
      "Content-Type": response.headers["content-type"] || "application/json",
    });

    try {
      const jsonData = JSON.parse(response.data);
      res.status(response.status).json(jsonData);
    } catch {
      res.status(response.status).send(response.data);
    }
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: "Unknown proxy error" };
    res.set(corsHeaders).status(status).json({
      error: "Proxy Error",
      message: err.message,
      responseData: data,
    });
  }
}

// DELETE a scheduled or ongoing call from Vapi
router.delete("/call/:callId", authenticateUser, async (req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);
  res.set(corsHeaders);

  try {
    const headers = buildHeaders(req);
    const { callId } = req.params;

    const response = await axios.delete(
      `${VOICE_AI_API_BASE_URL}/call/${callId}`,
      {
        headers,
      }
    );

    res.status(response.status).json(response.data);
  } catch (err) {
    console.error("Failed to delete call:", err);
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: "Unknown deletion error" };
    res.status(status).json({
      error: "Failed to delete call",
      message: err.message,
      responseData: data,
    });
  }
});

// === Routes ===

router.get("/call", authenticateUser, async (req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);
  res.set(corsHeaders);

  const {
    createdAtGt,
    createdAtLt,
    days,
    limit,
    id,
    phoneNumberId,
    createdAtGe,
    createdAtLe,
    updatedAtGt,
    updatedAtLt,
    updatedAtGe,
    updatedAtLe,
    earliestAt,
    latestAt,
  } = req.query;

  try {
    const email = req.user.email;

    const assistantRecords = await prisma.assistantID.findMany({
      where: {
        user: {
          email: email,
        },
      },
      select: {
        value: true,
      },
    });

    const assistantIds = assistantRecords.map((r) => r.value);
    console.log("Assistant IDs for user:", assistantIds);

    if (assistantIds.length === 0) {
      return res.status(200).json([]);
    }

    // Calculate time range
    let timePeriod = days;
    if (!timePeriod && createdAtGt && createdAtLt) {
      const start = new Date(createdAtGt);
      const end = new Date(createdAtLt);
      const diffDays = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
      if (diffDays <= 7) timePeriod = "7";
      else if (diffDays <= 30) timePeriod = "30";
      else if (diffDays <= 60) timePeriod = "60";
      else timePeriod = "all";
    }

    // Fetch in parallel
    const callFetchPromises = assistantIds.map((assistantId) =>
      fetchCallsOptimized({
        assistantId,
        days: timePeriod || "30",
        customStartDate: createdAtGt,
        customEndDate: createdAtLt,
        earliestAt,
        latestAt,
        phoneNumberId, // add this
      })
    );

    const results = await Promise.all(callFetchPromises);
    const allCalls = results.flatMap((r) => r.calls);

    return res.status(200).json(allCalls);
  } catch (error) {
    console.error("Optimized fetch failed, falling back to proxy:", error);

    // If optimization fails, fallback to proxy-based fetch using first assistant ID
    try {
      const userId = req.user.userId;
      const assistantRecords = await prisma.assistantID.findMany({
        where: { userId },
        select: { value: true },
      });

      const assistantIds = assistantRecords.map((r) => r.value);
      const fallbackAssistantId = assistantIds[0]; // pick the first one

      const queryParams = new URLSearchParams();
      if (id) queryParams.append("id", id);
      if (fallbackAssistantId)
        queryParams.append("assistantId", fallbackAssistantId);
      if (phoneNumberId) queryParams.append("phoneNumberId", phoneNumberId);
      if (limit) queryParams.append("limit", limit);
      else queryParams.append("limit", "200");

      if (createdAtGt) queryParams.append("createdAtGt", createdAtGt);
      if (createdAtLt) queryParams.append("createdAtLt", createdAtLt);
      if (createdAtGe) queryParams.append("createdAtGe", createdAtGe);
      if (createdAtLe) queryParams.append("createdAtLe", createdAtLe);
      if (updatedAtGt) queryParams.append("updatedAtGt", updatedAtGt);
      if (updatedAtLt) queryParams.append("updatedAtLt", updatedAtLt);
      if (updatedAtGe) queryParams.append("updatedAtGe", updatedAtGe);
      if (updatedAtLe) queryParams.append("updatedAtLe", updatedAtLe);

      const proxiedUrl = `/call?${queryParams.toString()}`;
      return await proxyRequest(req, res, proxiedUrl, "GET");
    } catch (fallbackErr) {
      console.error("Proxy fallback also failed:", fallbackErr);
      return res.status(500).json({ error: "Failed to fetch call data" });
    }
  }
});
// // CALL
// router.get("/call", async (req, res) => {
//   const origin = req.headers.origin;
//   const corsHeaders = getCorsHeaders(origin);

//   const {
//     id,
//     assistantId,
//     phoneNumberId,
//     limit,
//     createdAtGt,
//     createdAtLt,
//     createdAtGe,
//     createdAtLe,
//     updatedAtGt,
//     updatedAtLt,
//     updatedAtGe,
//     updatedAtLe,
//   } = req.query;

//   const queryParams = new URLSearchParams();
//   if (id) queryParams.append("id", id);
//   if (assistantId) queryParams.append("assistantId", assistantId);
//   if (phoneNumberId) queryParams.append("phoneNumberId", phoneNumberId);

//   // Use provided limit or default to 1000
//   queryParams.append("limit", limit || "200");

//   if (createdAtGt) queryParams.append("createdAtGt", createdAtGt);
//   if (createdAtLt) queryParams.append("createdAtLt", createdAtLt);
//   if (createdAtGe) queryParams.append("createdAtGe", createdAtGe);
//   if (createdAtLe) queryParams.append("createdAtLe", createdAtLe);
//   if (updatedAtGt) queryParams.append("updatedAtGt", updatedAtGt);
//   if (updatedAtLt) queryParams.append("updatedAtLt", updatedAtLt);
//   if (updatedAtGe) queryParams.append("updatedAtGe", updatedAtGe);
//   if (updatedAtLe) queryParams.append("updatedAtLe", updatedAtLe);

//   const proxiedUrl = queryParams.toString() ? `/call?${queryParams.toString()}` : "/call";

//   await proxyRequest(req, res, proxiedUrl, "GET");
// });

router.post("/call", (req, res) => proxyRequest(req, res, "/call"));

// ASSISTANT
router.get("/assistant", (req, res) => proxyRequest(req, res, "/assistant"));
router.post("/assistant", (req, res) => proxyRequest(req, res, "/assistant"));
router.patch("/assistant/:id", (req, res) =>
  proxyRequest(req, res, `/assistant/${req.params.id}`, "PATCH")
);

// KNOWLEDGE BASE
router.get("/knowledge-base", (req, res) =>
  proxyRequest(req, res, "/knowledge-base")
);
router.post("/knowledge-base", (req, res) =>
  proxyRequest(req, res, "/knowledge-base")
);

// CATCH OTHER ROUTES (OPTIONAL — add if you want dynamic flexibility)
router.use((req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  res
    .status(404)
    .set(corsHeaders)
    .json({
      error: "Route not found",
      message: `Route ${req.originalUrl} not defined in VoiceAI proxy.`,
    });
});

module.exports = router;
