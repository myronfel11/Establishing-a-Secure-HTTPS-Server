const express = require("express");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const path = require("path");
const argon2 = require("argon2");
const app = express();
const mongoose = require("mongoose");
require("dotenv").config();
const { ensureAuthenticated } = require("./middleware/auth");

//phase 3 ejs
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const { body, validationResult } = require("express-validator");
const escapeHtml = require("escape-html");
const crypto = require("crypto");

// AES encryption helper
const algorithm = "aes-256-cbc";

if (!process.env.CRYPTO_SECRET) {
  throw new Error("Missing CRYPTO_SECRET in .env file");
}
const key = crypto.scryptSync(process.env.CRYPTO_SECRET, 'salt', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16); 
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}



//phase 3 update
function decrypt(encrypted) {
  const [ivHex, encryptedDataHex] = encrypted.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encryptedData = Buffer.from(encryptedDataHex, "hex");

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

// phase 2 using Google SSO and passport
const passport = require("passport");
const session = require("express-session");
require("./config/passport");

// phase 2 Csurf
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

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

// Update profile route
app.post(
  "/profile/update",
  ensureAuthenticated,
  csrfProtection,
  [
    body("name").isLength({ min: 3, max: 50 }).isAlpha("en-US", { ignore: " " }),
    body("email").isEmail(),
    body("bio").optional().isLength({ max: 500 }).matches(/^[^<>]+$/), // no HTML tags
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, bio } = req.body;

    try {
      const encryptedEmail = encrypt(email);
      const encryptedBio = encrypt(bio || "");

      await User.findByIdAndUpdate(req.user._id, {
        username: escapeHtml(name),
        email: encryptedEmail,
        bio: encryptedBio,
      });

      res.redirect("/profile");
    } catch (err) {
      console.error(err);
      res.status(500).send("Failed to update profile");
    }
  }
);


// phase 2 JWT
const jwt = require("jsonwebtoken");
const { verifyRefreshToken, generateToken, generateRefreshToken } = require("./utils/jwt");





// phase 2 Middleware



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


//user model and middleware
const User = require("./models/User");
const authorize = require("./middleware/authorize");


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


app.get("/session-check", (req, res) => {
  res.json({
    isAuthenticated: req.isAuthenticated(),
    user: req.user || null,
  });
});

// JWT middleware for protected routes
// function jwtAuth(req, res, next) {
//   const token = req.cookies.accessToken;
//   if (!token) return res.status(401).json({ error: "Not authenticated" });

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded;
//     next();
//   } catch (err) {
//     return res.status(403).json({ error: "Invalid token" });
//   }
// }


// Google SSO
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/"); // Redirect to homepage
  }
);

// routes requiring CSRF protection

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hash = await argon2.hash(password);
    const newUser = new User({ username, password: hash, role: "User" });
    await newUser.save();

    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });

    const valid = await argon2.verify(user.password, password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

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

    res.json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/forgot-password", csrfProtection, async (req, res) => {
});

app.post("/reset-password", csrfProtection, async (req, res) => {
});

app.get("/logout", (req, res, next) => {
  req.logout(function(err) {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie("connect.sid"); 
      res.redirect("/"); 
    });
  });
});

// example secure route
// app.get("/profile", ensureAuthenticated, (req, res) => {
//   res.set("Cache-Control", "no-store");
//   res.json({ username: req.user.username, role: req.user.role });
// });

// app.get("/admin", ensureAuthenticated, authorize(["Admin"]), (req, res) => {
//   res.set("Cache-Control", "no-store");
//   res.json({ message: "Welcome to the admin dashboard", user: req.user });
// });

//phase 3 profile update

app.get("/profile", ensureAuthenticated, csrfProtection, async (req, res) => {
  const user = await User.findById(req.user._id);
const decryptedEmail = user.email ? decrypt(user.email) : "";
const decryptedBio = user.bio ? decrypt(user.bio) : "";

  res.render("dashboard", {
    user: {
      username: escapeHtml(user.username),
      email: escapeHtml(decryptedEmail),
      bio: escapeHtml(decryptedBio),
    },
    csrfToken: req.csrfToken(),
  });
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
