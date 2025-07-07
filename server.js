const express = require("express");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const path = require("path");
const argon2 = require("argon2");
const app = express();
const mongoose = require("mongoose");
require("dotenv").config();

// phase 2 Csurf
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// phase 2 JWT
const jwt = require("jsonwebtoken");
const { verifyRefreshToken, generateToken } = require("./utils/jwt");

// phase 2 Middleware
app.use(express.json());
app.use(csrfProtection); // Must come after express.json() and cookieParser

// need this to send csrf token to frontend
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// HTTPS security headers
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
    },
  })
);
app.use(helmet.frameguard({ action: "deny" }));

// phase 2 using Google SSO and passport
const passport = require("passport");
const session = require("express-session");
require("./config/passport");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

//user model and middleware
const User = require("./models/User");
const authorize = require("./middleware/authorize");
const { ensureAuthenticated } = require("./middleware/auth");

// MongoDB connection
mongoose
  .connect("mongodb://localhost:27017/userAuth", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err));

// JWT refresh
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: "No refresh token" });

  try {
    const payload = verifyRefreshToken(refreshToken);
    const user = { _id: payload.id, role: "User" };
    const newAccessToken = generateToken(user);

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });

    res.json({ message: "Token refreshed" });
  } catch (err) {
    res.status(403).json({ error: "Invalid refresh token" });
  }
});

// Google SSO
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const user = req.user;
    const accessToken = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.redirect("/profile");
  }
);

// routes requiring CSRF protection

app.post("/register", csrfProtection, async (req, res) => {
});

app.post("/login", csrfProtection, async (req, res) => { 
});

app.post("/forgot-password", csrfProtection, async (req, res) => {
});

app.post("/reset-password", csrfProtection, async (req, res) => {
});

// example secure route
app.get("/profile", ensureAuthenticated, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ username: req.user.username, role: req.user.role });
});

// HTTPS server
const options = {
  key: fs.readFileSync(path.join(__dirname, "certs", "ca-key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "ca-cert.pem")),
  passphrase: "1111",
};

https.createServer(options, app).listen(3000, () => {
  console.log("HTTPS server running at https://localhost:3000");
});
