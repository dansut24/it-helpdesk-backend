const express = require("express");
const router = express.Router();
const db = require("../db"); // ⬅️ Your MySQL connection
const authenticateToken = require("../middleware/auth"); // ⬅️ Your JWT middleware

// ✅ Get all users
router.get("/", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  
  db.query("SELECT id, username, email, role, active FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(results);
  });
});

// ✅ Change role
router.put("/:id/role", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  const { role } = req.body;
  db.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Failed to update role" });
    res.json({ success: true });
  });
});

// ✅ Toggle active
router.put("/:id/status", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  const { active } = req.body;
  db.query("UPDATE users SET active = ? WHERE id = ?", [active, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Failed to update status" });
    res.json({ success: true });
  });
});

// ✅ Reset password (default: "changeme123")
const bcrypt = require("bcryptjs");
router.post("/:id/reset-password", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);
  const hashed = await bcrypt.hash("changeme123", 10);
  db.query("UPDATE users SET password = ? WHERE id = ?", [hashed, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Failed to reset password" });
    res.json({ success: true });
  });
});

module.exports = router;
