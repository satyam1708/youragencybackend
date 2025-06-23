const express = require("express");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { authenticateUser } = require("../middlewares/auth");

const prisma = new PrismaClient();
const router = express.Router();

// GET /api/assistants → fetch assistant IDs
router.get("/", authenticateUser, async (req, res) => {
  try {
    const assistants = await prisma.AssistantID.findMany({
      where: { user: { email: req.user.email } },
      orderBy: { createdAt: "desc" },
    });
    res.status(200).json({ assistants });
  } catch (err) {
    console.error("Fetch assistants error:", err);
    res.status(500).json({ message: "Error fetching assistants" });
  }
});

// POST /api/assistants → create a new assistant ID
router.post("/", authenticateUser, async (req, res) => {
  const { value, assistantName } = req.body;

  if (!value || !assistantName) {
    return res.status(400).json({ message: "Assistant value and name are required" });
  }

  try {
    const user = await prisma.User.findUnique({
      where: { email: req.user.email },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const newAssistant = await prisma.AssistantID.create({
      data: {
        value,
        assistantName,
        userId: user.id,
      },
    });

    res.status(201).json({ message: "Assistant created", assistant: newAssistant });
  } catch (err) {
    console.error("Create assistant error:", err);
    res.status(500).json({ message: "Error creating assistant" });
  }
});

// PUT /api/assistants/:id → update assistant's name and/or value
router.put("/:id", authenticateUser, async (req, res) => {
  const assistantId = parseInt(req.params.id);
  const { value, assistantName } = req.body;

  if (isNaN(assistantId)) {
    return res.status(400).json({ message: "Invalid assistant ID" });
  }

  if (!value && !assistantName) {
    return res.status(400).json({ message: "Nothing to update" });
  }

  try {
    const user = await prisma.User.findUnique({
      where: { email: req.user.email },
    });

    const assistant = await prisma.AssistantID.findUnique({
      where: { id: assistantId },
    });

    if (!assistant || assistant.userId !== user.id) {
      return res.status(403).json({ message: "Unauthorized or assistant not found" });
    }

    const updatedAssistant = await prisma.AssistantID.update({
      where: { id: assistantId },
      data: {
        ...(value && { value }),
        ...(assistantName && { assistantName }),
      },
    });

    res.status(200).json({ message: "Assistant updated", assistant: updatedAssistant });
  } catch (err) {
    console.error("Update assistant error:", err);
    res.status(500).json({ message: "Error updating assistant" });
  }
});

// DELETE /api/assistants/:id → delete an assistant ID
router.delete("/:id", authenticateUser, async (req, res) => {
  const assistantId = parseInt(req.params.id);
  if (isNaN(assistantId)) {
    return res.status(400).json({ message: "Invalid assistant ID" });
  }

  try {
    const user = await prisma.User.findUnique({
      where: { email: req.user.email },
    });

    const assistant = await prisma.AssistantID.findUnique({
      where: { id: assistantId },
    });

    if (!assistant || assistant.userId !== user.id) {
      return res.status(403).json({ message: "Unauthorized or not found" });
    }

    await prisma.AssistantID.delete({ where: { id: assistantId } });

    res.status(200).json({ message: "Assistant deleted" });
  } catch (err) {
    console.error("Delete assistant error:", err);
    res.status(500).json({ message: "Error deleting assistant" });
  }
});

module.exports = router;
