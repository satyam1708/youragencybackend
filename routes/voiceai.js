const express = require("express");
const axios = require("axios");
const { authenticateUser } = require("../middlewares/auth");
const {
  createAgentJSon,
  beforePrompt,
  afterPrompt,
} = require("../utils/constants");
const router = express.Router();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
router.get("/assistant/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const VAPI_API_KEY = process.env.VAPI_API_KEY;

  if (!VAPI_API_KEY) {
    return res
      .status(500)
      .json({ message: "VoiceAI API key not set in environment variables" });
  }

  try {
    const voiceaiResponse = await axios.get(
      `https://api.vapi.ai/assistant/${id}`,
      {
        headers: {
          Authorization: `Bearer ${VAPI_API_KEY}`,
        },
      }
    );

    res.status(200).json(voiceaiResponse.data);
  } catch (error) {
    console.error(
      "Error fetching assistant from Voiceai:",
      error?.response?.data || error.message
    );
    res.status(error.response?.status || 500).json({
      message: "Failed to fetch assistant from Voiceai",
      details: error.response?.data || error.message,
    });
  }
});

// -------------------------
// Create Assistant (Vapi + DB)
// -------------------------
router.post("/assistant", authenticateUser, async (req, res) => {
  const { name, prompt } = req.body;
  const VAPI_API_KEY = process.env.VAPI_API_KEY;

  if (!VAPI_API_KEY) {
    return res
      .status(500)
      .json({ message: "VoiceAI API key not set in environment variables" });
  }

  if (!name || !prompt) {
    return res
      .status(400)
      .json({ message: "Both name and prompt are required" });
  }

  try {
    // Build payload
    const payload = { ...createAgentJSon };
    payload.name = name;
    // Wrap user’s prompt with before + after
    const fullPrompt = `${beforePrompt}\n${prompt}\n${afterPrompt}`;
    if (payload.model && Array.isArray(payload.model.messages)) {
      payload.model.messages = [
        {
          role: "system",
          content: fullPrompt,
        },
      ];
    }

    // Step 1: Create assistant on Vapi
    const vapiResponse = await axios.post(
      "https://api.vapi.ai/assistant",
      payload,
      {
        headers: {
          Authorization: `Bearer ${VAPI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    const vapiAssistant = vapiResponse.data;

    // Step 2: Save assistant in DB
    const user = await prisma.User.findUnique({
      where: { email: req.user.email },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const newAssistant = await prisma.AssistantID.create({
      data: {
        value: vapiAssistant.id, // Vapi assistant id
        assistantName: vapiAssistant.name,
        voice: vapiAssistant.voice?.voiceId || null,
        userId: user.id,
      },
    });

    // Step 3: Respond back with both
    res.status(201).json({
      message: "Assistant created successfully",
      data: {
        vapi: vapiAssistant,
        db: newAssistant,
      },
    });
  } catch (error) {
    console.error(
      "Error creating assistant:",
      error?.response?.data || error.message
    );
    res.status(error.response?.status || 500).json({
      message: "Failed to create assistant",
      details: error?.response?.data || error.message,
    });
  }
});

module.exports = router;
