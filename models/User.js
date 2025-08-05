const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String },
  email: { type: String },
  bio: { type: String },
  role: { type: String, default: "User" }
});

module.exports = mongoose.model("User", userSchema);