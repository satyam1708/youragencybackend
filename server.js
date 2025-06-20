require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const cors = require("cors");
const { auditLog } = require("./utils/audit.util");

const helmetConfig = require("./config/helmet.config");
const corsConfig = require("./config/cors.config");
const csrfMiddleware = require("./middlewares/csrf.middleware");
const errorMiddleware = require("./middlewares/error.middleware");
const authRoutes = require("./routes/auth.routes");

const app = express();

// Use Helmet with your config
app.use(helmet(helmetConfig));

// Use CORS with your config
app.use(cors(corsConfig));

// Parse JSON and cookies
app.use(express.json());
app.use(cookieParser());

// HTTPS redirect middleware (production only)
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// CSRF Protection Middleware
app.use(csrfMiddleware);

// Mount Auth routes
app.use("/auth", authRoutes);

// Error handling middleware (should be after routes)
app.use(errorMiddleware);

// Start server and log
app.listen(5000, () => {
  auditLog("SYSTEM", "Auth server running on http://localhost:5000");
});
