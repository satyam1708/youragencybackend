const express = require("express");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const FormData = require("form-data");
const fs = require("fs");

const router = express.Router();
const upload = multer({ dest: "uploads/" }); // Temp upload dir

router.post("/", upload.single("file"), async (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ message: "Not logged in" });
  }

  const { assistantId, model } = req.body; // model is JSON string from frontend
  if (!assistantId || !model) {
    return res.status(400).json({ message: "Assistant ID and model are required" });
  }

  let filePath = req.file?.path;

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const parsedModel = typeof model === "string" ? JSON.parse(model) : model;
    let knowledgeBaseId = parsedModel.knowledgeBaseId;

    // Step 1: Upload file to Vapi
    const fileForm = new FormData();
    fileForm.append("file", fs.createReadStream(filePath), {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const fileUploadResponse = await axios.post(
      "https://api.vapi.ai/file",
      fileForm,
      {
        headers: {
          Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
          ...fileForm.getHeaders(),
        },
      }
    );

    const url = fileUploadResponse.data?.url;
    if (!url) throw new Error("File upload failed or missing file URL.");
      // Create new KB
      const kbResponse = await axios.post(
        "https://api.vapi.ai/knowledge-base",
        {
          provider: "custom-knowledge-base",
          server: { url },
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
            "Content-Type": "application/json",
          },
        }
      );

      knowledgeBaseId = kbResponse.data.id;
      parsedModel.knowledgeBaseId = knowledgeBaseId; // update model with new KB id

    // Step 3: Update assistant with full model from frontend
    await axios.patch(
      `https://api.vapi.ai/assistant/${assistantId}`,
      {
        model: parsedModel,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.status(201).json({
      message: "Custom knowledge base created/updated and linked to assistant successfully",
      data: {
        id: knowledgeBaseId,
        filename: req.file.originalname,
        assistantId,
      },
    });
  } catch (error) {
    console.error(
      "Error creating or linking knowledge base:",
      error.response?.data || error.message
    );
    res.status(500).json({
      message: "Failed to create or link custom knowledge base",
      error: error.response?.data || error.message,
    });
  } finally {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlink(filePath, (err) => {
        if (err) console.error("Failed to delete uploaded file:", err);
      });
    }
  }
});



// GET: List all knowledge bases
router.get("/", async (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const response = await axios.get("https://api.vapi.ai/knowledge-base", {
      headers: {
        Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
      },
    });

    // Filter data to only include id for each KB
    // const filteredData = (response.data || []).map(kb => ({ id: kb.id }));
    const filteredData = (response.data );
    res.status(200).json({
      message: "Knowledge bases fetched successfully",
      data: filteredData,
    });
  } catch (error) {
    console.error(
      "Error fetching knowledge bases:",
      error.response?.data || error.message
    );
    res.status(500).json({
      message: "Failed to fetch knowledge bases",
      error: error.response?.data || error.message,
    });
  }
});

// DELETE: Delete a knowledge base by ID
router.delete("/:id", async (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ message: "Not logged in" });
  }

  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ message: "Knowledge Base ID is required" });
  }

  try {
    // Verify JWT token
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Call Vapi API to delete the knowledge base
    const response = await axios.delete(`https://api.vapi.ai/knowledge-base/${id}`, {
      headers: {
        Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
      },
    });

    res.status(200).json({
      message: "Knowledge base deleted successfully",
      data: response.data,
    });
  } catch (error) {
    console.error(
      "Error deleting knowledge base:",
      error.response?.data || error.message
    );
    res.status(500).json({
      message: "Failed to delete knowledge base",
      error: error.response?.data || error.message,
    });
  }
});



module.exports = router;
