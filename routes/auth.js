const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const util = require("util");
require("dotenv").config();

const router = express.Router();
const SECRET_KEY = process.env.SECRET_KEY || "secret_key";

// ✅ MySQL Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "it_helpdesk",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to MySQL Database: it_helpdesk");
});

// ✅ Promisify db.query for async/await
const query = util.promisify(db.query).bind(db);

// ✅ Login route returning full role array
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  try {
    const [user] = await query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    if (!user.active) {
      return res.status(403).json({ error: "This account has been deactivated" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const rolesResult = await query(
      `SELECT r.name FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ?`,
      [user.id]
    );
    const roles = rolesResult.map(r => r.name);

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        username: user.username,
        team_id: user.team_id,
        roles,
      },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      team_id: user.team_id,
      avatar_url: user.avatar_url,
      roles,
      token,
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;