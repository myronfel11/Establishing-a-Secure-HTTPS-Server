function authorize(allowedRoles) {
  return (req, res, next) => {
    if (allowedRoles.includes(req.user.role)) {
      return next();
    }
    return res.status(403).json({ error: "Forbidden" });
  };
}

module.exports = authorize;