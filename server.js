const express = require("express");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const path = require("path");
const argon2 = require("argon2");
const app = express();

app.use(express.json());

const users = [];

// phase 2 register & login
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hash = await argon2.hash(password);

    users.push({ username, password: hash });

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ error: "User not found" });

  try {
    const valid = await argon2.verify(user.password, password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    res.json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Helmet setup
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

// all of my routes

app.get("/profile", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    name: "Hero",
    level: 4,
    xp: 1250,
    badges: ["Early Bird", "Daily Streak"],
  });
});

app.get("/inventory", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    items: [
      { name: "Healing Potion", quantity: 3 },
      { name: "Sword of Focus", quantity: 1 },
      { name: "XP Boost", quantity: 2 },
    ],
  });
});

app.get("/quests", (req, res) => {
  res.set("Cache-Control", "public, max-age=300, stale-while-revalidate=300");
  res.json([
    { id: 1, title: "Drink Water", xp: 10 },
    { id: 2, title: "Study for 30 minutes", xp: 20 },
    { id: 3, title: "Go for a walk", xp: 15 },
  ]);
});

app.get("/guilds", (req, res) => {
  res.set("Cache-Control", "public, max-age=600");
  res.json([
    { id: 1, name: "Quest Masters", members: 5 },
    { id: 2, name: "Focus Warriors", members: 3 },
  ]);
});

app.get("/store", (req, res) => {
  res.set("Cache-Control", "public, max-age=300");
  res.json([
    { id: 1, name: "XP Boost", price: 100 },
    { id: 2, name: "Energy Drink", price: 50 },
    { id: 3, name: "Lucky Charm", price: 75 },
  ]);
});

// SSL Cert
const options = {
  key: fs.readFileSync(path.join(__dirname, "certs", "ca-key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "ca-cert.pem")),
  passphrase: "1111",
};

https.createServer(options, app).listen(3000, () => {
  console.log("🚀 HTTPS server running at https://localhost:3000");
});
