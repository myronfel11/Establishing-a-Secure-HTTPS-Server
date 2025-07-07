const jwt = require("jsonwebtoken");

function authenticateJWT(req, res, next) {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ error: "No access token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

module.exports = authenticateJWT;
