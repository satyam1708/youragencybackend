const express = require("express");
const axios = require("axios");
const { authenticateUser } = require("../middlewares/auth");

const router = express.Router();

router.get("/assistant/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const VAPI_API_KEY = process.env.VAPI_API_KEY;

  if (!VAPI_API_KEY) {
    return res.status(500).json({ message: "VoiceAI API key not set in environment variables" });
  }

  try {
    const voiceaiResponse = await axios.get(`https://api.vapi.ai/assistant/${id}`, {
      headers: {
        Authorization: `Bearer ${VAPI_API_KEY}`,
      },
    });

    res.status(200).json(voiceaiResponse.data);
  } catch (error) {
    console.error("Error fetching assistant from Voiceai:", error?.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      message: "Failed to fetch assistant from Voiceai",
      details: error.response?.data || error.message,
    });
  }
});

module.exports = router;
