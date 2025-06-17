const express = require("express");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const path = require("path");

const app = express();

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
