require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bodyParser = require("body-parser");
const authRoutes = require("./routes/auth");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const sgMail = require("@sendgrid/mail");
const util = require("util");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
  },
});

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
}));

// Explicitly allow x-selected-role in preflight
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-selected-role");
  next();
});



app.set("io", io);

io.on("connection", (socket) => {
  console.log("🟢 Client connected");

  socket.on("join", (userId) => {
    socket.join(`user_${userId}`);
    console.log(`📢 User joined room: user_${userId}`);
  });

  socket.on("disconnect", () => {
    console.log("🔌 Client disconnected");
  });
});

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || "secret_key";
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  methods: "GET, POST, PUT, DELETE, OPTIONS",
  allowedHeaders: "Content-Type, Authorization",
  credentials: true,
};

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.options("*", cors(corsOptions));

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST || "localhost",
  user: process.env.DATABASE_USER || "root",
  password: process.env.DATABASE_PASSWORD || "",
  database: process.env.DATABASE_NAME || "it_helpdesk",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to MySQL Database: it_helpdesk");
});

const query = util.promisify(db.query).bind(db);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ error: "Invalid Token Format" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid Token" });
    }
    req.user = user;
    next();
  });
};

const logAuditAction = async (user, action, details) => {
  const sql = `
    INSERT INTO audit_logs (user_id, username, action, details, timestamp)
    VALUES (?, ?, ?, ?, NOW())
  `;
  try {
    await db.query(sql, [user.id, user.username, action, details]);
    console.log("✅ Audit log written:", action);
  } catch (err) {
    console.error("❌ Audit log error:", err.message);
  }
};

app.use((req, res, next) => {
  console.log(`🔍 Incoming ${req.method} ${req.url}`);
  next();
});


app.get("/api/incidents/next-ref", async (req, res) => {
  console.log("📡 Fetching next reference number...");

  const sql = `
      SELECT MAX(CAST(SUBSTRING(referenceNumber, 4) AS UNSIGNED)) AS maxRef 
      FROM incidents
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error("❌ SQL Error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log("🔍 SQL Query Result:", result);

    let nextReferenceNumber;
    if (!result || result.length === 0 || result[0].maxRef === null) {
      console.warn("⚠️ No incidents found. Defaulting to INC1000.");
      nextReferenceNumber = "INC1000";
    } else {
      const maxRef = result[0].maxRef;
      nextReferenceNumber = `INC${maxRef + 1}`;
    }

    console.log("✅ Next Reference Number:", nextReferenceNumber);
    res.status(200).json({ nextReferenceNumber });
  });
});


// ✅ Configure Multer for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "uploads", "avatars");
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `avatar_${Date.now()}${ext}`;
    cb(null, filename);
  },
});

const uploadAvatar = multer({ storage: avatarStorage });

app.post("/api/users/avatar", authenticateToken, uploadAvatar.single("avatar"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded." });
  }

  const avatarPath = `/uploads/avatars/${req.file.filename}`;
  const userId = req.user.id;

  const sql = "UPDATE users SET avatar_url = ? WHERE id = ?";
  db.query(sql, [avatarPath, userId], (err, result) => {
    if (err) {
      console.error("❌ Error updating avatar URL:", err);
      return res.status(500).json({ error: "Failed to update avatar" });
    }

    console.log(`✅ Updated avatar for user ID ${userId}: ${avatarPath}`);
    res.json({ avatar_url: avatarPath });
  });
});

app.get("/api/incidents", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const teamId = req.user.team_id;
  const roles = req.user.roles || [];
  const selectedRole = req.headers["x-selected-role"];

  console.log("🔍 Incoming GET /api/incidents");
  console.log("🔍 User ID:", userId);
  console.log("🧾 Selected Role:", selectedRole);
  console.log("🧠 Roles from token:", roles);
  console.log("👥 Team ID:", teamId);

  try {
    const all = await query(`
      SELECT 
        i.*, 
        CONCAT(u.first_name, ' ', u.last_name) AS assigned_user_name,
        CONCAT(c.first_name, ' ', c.last_name) AS created_by_user_name,
        t.name AS assigned_team_name,
        (
          SELECT n.content 
          FROM notes n 
          WHERE n.entity_type = 'incident' AND n.entity_id = i.id 
          ORDER BY n.timestamp DESC 
          LIMIT 1
        ) AS latest_note
      FROM incidents i
      LEFT JOIN users u ON i.assigned_user_id = u.id
      LEFT JOIN users c ON i.created_by = c.id
      LEFT JOIN teams t ON i.assigned_team_id = t.id
      ORDER BY i.id DESC
    `);

    // Admins see all incidents
    if (selectedRole === "admin" || roles.includes("admin")) {
      return res.status(200).json({ role: "admin", all });
    }

    // Selfservice users only see their own
    if (selectedRole === "selfservice" || roles.includes("selfservice")) {
      const myIncidents = all.filter(inc => inc.created_by === userId);
      return res.status(200).json({ role: "selfservice", myIncidents });
    }

    // Other roles see a filtered view
    const myIncidents = all.filter(inc => inc.created_by === userId || inc.assigned_user_id === userId);
    const teamIncidents = all.filter(
      inc => inc.assigned_team_id === teamId && (!inc.assigned_user_id || inc.assigned_user_id !== userId)
    );

    res.status(200).json({ role: selectedRole, myIncidents, teamIncidents });
  } catch (err) {
    console.error("❌ Failed to fetch incidents:", err);
    res.status(500).json({ error: "Failed to fetch incidents" });
  }
});



app.put("/api/incidents/:id/assign-to-me", authenticateToken, async (req, res) => {
  const incidentId = req.params.id;
  const userId = req.user.id;

  try {
    // Check if incident already has an assigned user
    const [incident] = await query("SELECT assigned_user_id FROM incidents WHERE id = ?", [incidentId]);

    if (!incident) {
      return res.status(404).json({ error: "Incident not found" });
    }

    if (incident.assigned_user_id) {
      return res.status(409).json({ error: "Incident already assigned" });
    }

    // Assign the incident to the current user
    await query("UPDATE incidents SET assigned_user_id = ? WHERE id = ?", [userId, incidentId]);
    res.json({ success: true, message: "Incident assigned to you." });
  } catch (err) {
    console.error("❌ Failed to assign incident:", err);
    res.status(500).json({ error: "Failed to assign incident" });
  }
});


// Update incident status
app.put("/api/incidents/:id/status", authenticateToken, async (req, res) => {
  const { status } = req.body;
  const { id } = req.params;

  try {
    // Fetch current incident to compare previous status
    const [incident] = await query("SELECT status, sla_due, total_paused_seconds, paused_at FROM incidents WHERE id = ?", [id]);

    if (!incident) {
      return res.status(404).json({ error: "Incident not found" });
    }

    let updateSql = "UPDATE incidents SET status = ?";
    const params = [status];

    // Handle pause start time
    if (status === "Paused" && !incident.paused_at) {
      updateSql += ", paused_at = ?";
      params.push(new Date());
    }

    // Handle resume: add paused duration to total_paused_seconds
    if (incident.status === "Paused" && status !== "Paused" && incident.paused_at) {
      const pausedDurationSeconds = Math.floor((Date.now() - new Date(incident.paused_at)) / 1000);
      const newTotalPaused = (incident.total_paused_seconds || 0) + pausedDurationSeconds;

      updateSql += ", total_paused_seconds = ?, paused_at = NULL";
      params.push(newTotalPaused);
    }

    updateSql += " WHERE id = ?";
    params.push(id);

    await query(updateSql, params);

    res.status(200).json({ message: "Status updated" });
  } catch (err) {
    console.error("❌ Error updating incident status:", err);
    res.status(500).json({ error: "Failed to update status" });
  }
});



app.get("/api/incidents/:referenceNumber", authenticateToken, (req, res) => {
  const { referenceNumber } = req.params;

  console.log("📡 Fetching incident details for:", referenceNumber);

  const sql = `
    SELECT 
      i.*, 
      CONCAT(u.first_name, ' ', u.last_name) AS assigned_user_name,
      u.id AS assigned_user_id,
      CONCAT(creator.first_name, ' ', creator.last_name) AS created_by_user_name,
      IFNULL(GROUP_CONCAT(
          JSON_OBJECT('username', n.username, 'timestamp', n.timestamp, 'content', n.content)
      SEPARATOR ', '), '[]') AS notes
    FROM incidents i
    LEFT JOIN users u ON i.assigned_user_id = u.id
    LEFT JOIN users creator ON i.created_by = creator.id
    LEFT JOIN notes n ON n.entity_type = 'incident' AND n.entity_id = i.id
    WHERE i.referenceNumber = ?
    GROUP BY i.id
  `;

  db.query(sql, [referenceNumber], (err, result) => {
    if (err) {
      console.error("❌ Error fetching incident:", err);
      return res.status(500).json({ error: "Error fetching incident" });
    }

    if (result.length === 0) {
      console.warn(`❌ Incident ${referenceNumber} not found`);
      return res.status(404).json({ error: `Incident ${referenceNumber} not found` });
    }

    const incident = result[0];

    // ✅ Parse notes JSON
    try {
      incident.notes = JSON.parse(`[${incident.notes}]`);
    } catch (parseError) {
      console.error("❌ Error parsing notes JSON:", parseError);
      incident.notes = [];
    }

    // ✅ Ensure attachments is an array
    incident.attachments = incident.attachments ? incident.attachments.split(",") : [];

    console.log("✅ Incident Details Retrieved:", incident);
    res.status(200).json(incident);
  });
});



app.post("/api/incidents", authenticateToken, (req, res, next) => {
  upload.single("file")(req, res, function (err) {
    if (err && err.code === "LIMIT_UNEXPECTED_FILE") {
      console.warn("⚠️ No file uploaded. Proceeding without file.");
      return next(); // continue
    } else if (err) {
      console.error("❌ Multer Error:", err);
      return res.status(500).json({ error: "File upload error", details: err.message });
    }
    next();
  });
});

app.post("/api/incidents", authenticateToken, async (req, res) => {
  console.log("📡 Attempting to create incident...");

  const { title, description, priority, category, referenceNumber, assigned_team_id } = req.body;
  const filePath = req.file ? `/uploads/${req.file.filename}` : null;
  const created_by = req.user?.id || null;

  if (!title || !description || !priority || !category || !referenceNumber) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const slaIntervals = {
    Critical: "1 HOUR",
    High: "4 HOUR",
    Medium: "8 HOUR",
    Low: "24 HOUR",
  };

  try {
    const insertSQL = `
      INSERT INTO incidents (referenceNumber, title, description, priority, category, sla_due, attachments, assigned_team_id, created_by)
      VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ${slaIntervals[priority]}), ?, ?, ?)
    `;

    const result = await query(insertSQL, [
      referenceNumber,
      title,
      description,
      priority,
      category,
      filePath,
      assigned_team_id || null,
      created_by,
    ]);

    const incidentId = result.insertId;

    // 🔔 Create notification
    const message = `🚨 New Incident Assigned: ${title}`;
    const link = `/incident/${referenceNumber}`;
    const io = req.app.get("io");

    if (assigned_team_id) {
      const teamUsers = await query("SELECT id FROM users WHERE team_id = ?", [assigned_team_id]);
      for (const user of teamUsers) {
        await query(
          "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
          [user.id, message, link]
        );
        io.to(`user_${user.id}`).emit("new_notification", { message, link });
      }
    } else if (created_by) {
      await query(
        "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
        [created_by, message, link]
      );
      io.to(`user_${created_by}`).emit("new_notification", { message, link });
    }

    res.status(201).json({
      id: incidentId,
      referenceNumber,
      title,
      description,
      priority,
      category,
      sla_due: new Date(Date.now() + parseInt(slaIntervals[priority]) * 60 * 60 * 1000),
      attachments: filePath ? [filePath] : [],
      assigned_team_id: assigned_team_id || null,
      created_by,
    });
  } catch (err) {
    console.error("❌ Incident creation failed:", err);
    res.status(500).json({ error: "Internal Server Error", details: err.message });
  }
});

// PUT /api/incidents/:id/assign - Reassign incident to a user
// ✅ Assign a user to an incident
app.put("/api/incidents/:id/assign", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { assigned_user_id } = req.body;

  try {
    await query("UPDATE incidents SET assigned_user_id = ? WHERE id = ?", [
      assigned_user_id,
      id,
    ]);
    res.status(200).json({ message: "Incident reassigned successfully" });
  } catch (err) {
    console.error("❌ Error updating incident assignment:", err);
    res.status(500).json({ error: "Failed to reassign incident" });
  }
});

app.put("/api/incidents/:id/team", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { teamId } = req.body;

  try {
    // Clear user if team is changed
    await query("UPDATE incidents SET assigned_team_id = ?, assigned_user_id = NULL WHERE id = ?", [teamId, id]);
    res.status(200).json({ message: "Team updated successfully" });
  } catch (err) {
    console.error("❌ Failed to update incident team:", err);
    res.status(500).json({ error: "Failed to update incident team" });
  }
});

app.get("/api/teams/:teamId/users", authenticateToken, async (req, res) => {
  const { teamId } = req.params;

  try {
    const users = await query("SELECT id, username, first_name, last_name FROM users WHERE team_id = ?", [teamId]);
    res.json(users);
  } catch (err) {
    console.error("❌ Failed to fetch users by team:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



// POST /notes
app.post("/api/notes", authenticateToken, async (req, res) => {
  const { entity_type, entity_id, content } = req.body;
  const username = req.user?.username;

  if (!entity_type || !entity_id || !content) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const sql = `
    INSERT INTO notes (entity_type, entity_id, username, content, timestamp)
    VALUES (?, ?, ?, ?, NOW())
  `;

  try {
    const result = await query(sql, [entity_type, entity_id, username, content]);
    res.status(201).json({
      id: result.insertId,
      username,
      content,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Failed to save note:", err);
    res.status(500).json({ error: "Failed to save note" });
  }
});


app.get("/api/notes", authenticateToken, async (req, res) => {
  const { type, id } = req.query;

  if (!type || !id) {
    return res.status(400).json({ error: "Missing query params" });
  }

  try {
    const sql = `
  SELECT n.username, n.content, n.timestamp, u.avatar_url
  FROM notes n
  LEFT JOIN users u ON n.username = u.username
  WHERE n.entity_type = ? AND n.entity_id = ?
  ORDER BY n.timestamp ASC
`;

    const results = await query(sql, [type, id]);
    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Failed to fetch notes:", err);
    res.status(500).json({ error: "Failed to fetch notes" });
  }
});

// ✅ GET /api/service-requests - Fetch All Requests
app.get("/api/service-requests", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  const sql = `
    SELECT *
    FROM service_requests
    WHERE assigned_team_id = (
      SELECT team_id FROM users WHERE id = ?
    )
    OR created_by = ?
    ORDER BY created_at DESC
  `;

  try {
    const results = await query(sql, [userId, userId]);

    if (!results.length) {
      return res.status(404).json({ error: "No service requests found" });
    }

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Error fetching filtered service requests:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



// ✅ POST /api/service-requests - Create a New Request
// ✅ POST /api/service-requests - Create a New Request
app.post("/api/service-requests", authenticateToken, async (req, res) => {
  const { title, description, template, assigned_team_id } = req.body;
  const created_by = req.user?.id || null;

  console.log("📡 Creating Service Request:", { title, description, template, assigned_team_id, created_by });

  if (!title || !description || !template) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Insert service request
    const result = await query(
      `INSERT INTO service_requests (title, description, template, assigned_team_id, created_by)
       VALUES (?, ?, ?, ?, ?)`,
      [title, description, template, assigned_team_id || null, created_by]
    );

    const serviceRequestId = result.insertId;
    console.log("✅ Service Request Created:", serviceRequestId);

    // Fetch the template row (without destructuring)
    const rows = await query("SELECT auto_tasks FROM service_request_templates WHERE id = ?", [Number(template)]);
    console.log("🧪 Raw template rows:", rows);

    if (!rows || rows.length === 0) {
      console.error("❌ No template found for id:", template);
      return res.status(404).json({ error: "Template not found" });
    }

    const rawAutoTasks = rows[0].auto_tasks;
    console.log("🧪 Raw auto_tasks string:", rawAutoTasks);

    let parsedTasks = [];
    try {
      parsedTasks = JSON.parse(rawAutoTasks);
      console.log("✅ Parsed tasks:", parsedTasks);
    } catch (err) {
      console.error("❌ Failed to parse auto_tasks JSON:", err);
      return res.status(400).json({ error: "Invalid auto_tasks format in template" });
    }

    if (!Array.isArray(parsedTasks)) {
      console.error("❌ Parsed auto_tasks is not an array:", parsedTasks);
      return res.status(400).json({ error: "auto_tasks must be an array" });
    }

    for (const task of parsedTasks) {
      await query(
        `INSERT INTO tasks (title, linked_type, linked_id, assigned_team_id, status, created_by)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          task.title,
          "request",
          serviceRequestId,
          task.assigned_team_id || null,
          "Open",
          created_by
        ]
      );
      console.log("🛠️ Created auto-task:", task.title);
    }

    res.status(201).json({
      id: serviceRequestId,
      title,
      description,
      template,
      status: "Open",
      assigned_team_id: assigned_team_id || null,
      created_by,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error creating service request with tasks:", err);
    res.status(500).json({ error: "Failed to create service request with tasks" });
  }
});






// ✅ GET /api/service-requests/:id
app.get("/api/service-requests/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  const sql = "SELECT * FROM service_requests WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("❌ Error fetching service request:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Service request not found" });
    }

    const request = results[0];

    if (request.attachments && typeof request.attachments === "string") {
      request.attachments = request.attachments.split(",");
    } else {
      request.attachments = [];
    }

    res.status(200).json(request);
  });
});


// ✅ Changes API - Register Route
app.get("/api/changes", (req, res) => {
  db.query("SELECT * FROM changes ORDER BY createdAt DESC", (err, results) => {
    if (err) {
      console.error("❌ Error fetching changes:", err);
      return res.status(500).json({ error: "Error fetching changes" });
    }

    res.status(200).json(results);
  });
});

app.post("/api/changes", authenticateToken, (req, res) => {
  const {
    title,
    description,
    risk_level,
    requested_date,
    backoutPlan,
    testingPlan,
    justification
  } = req.body;

  if (!title || !description || !risk_level || !requested_date) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const sql = `
  INSERT INTO changes (title, description, risk_level, requested_date, backout_plan, testing_plan, justification)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`;


  db.query(
    sql,
    [title, description, risk_level, requested_date, backoutPlan, testingPlan, justification],
    (err, result) => {
      if (err) {
        console.error("❌ Error inserting change:", err);
        return res.status(500).json({ error: "Database error" });
      }

      res.status(201).json({ insertId: result.insertId });
    }
  );
});


app.get("/api/changes/:id", (req, res) => {
  const { id } = req.params;

  db.query("SELECT * FROM changes WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ Error fetching change:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Change not found" });
    }

    res.status(200).json(results[0]);
  });
});


app.put("/api/changes/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  db.query("UPDATE changes SET status = ? WHERE id = ?", [status, id], (err) => {
    if (err) {
      console.error("❌ Error updating change status:", err);
      return res.status(500).json({ error: "Failed to update change status" });
    }

    res.status(200).json({ message: "Change status updated successfully." });
  });
});

// ✅ GET all articles
app.get("/api/kb-articles", authenticateToken, (req, res) => {
  db.query("SELECT * FROM kb_articles ORDER BY created_at DESC", (err, results) => {
    if (err) {
      console.error("❌ Error fetching KB articles:", err);
      return res.status(500).json({ error: "Failed to fetch articles" });
    }
    res.status(200).json(results);
  });
});

// ✅ POST create or update
app.post("/api/kb-articles", authenticateToken, (req, res) => {
  const { id, title, category, content } = req.body;

  if (!title || !category || !content) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (id) {
    // Update
    db.query(
      "UPDATE kb_articles SET title = ?, category = ?, content = ? WHERE id = ?",
      [title, category, content, id],
      (err) => {
        if (err) {
          console.error("❌ Error updating KB article:", err);
          return res.status(500).json({ error: "Failed to update article" });
        }
        res.status(200).json({ message: "Article updated successfully" });
      }
    );
  } else {
    // Insert
    db.query(
      "INSERT INTO kb_articles (title, category, content) VALUES (?, ?, ?)",
      [title, category, content],
      (err, result) => {
        if (err) {
          console.error("❌ Error inserting KB article:", err);
          return res.status(500).json({ error: "Failed to save article" });
        }
        res.status(201).json({ id: result.insertId });
      }
    );
  }
});

// ✅ DELETE article
app.delete("/api/kb-articles/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM kb_articles WHERE id = ?", [id], (err) => {
    if (err) {
      console.error("❌ Error deleting KB article:", err);
      return res.status(500).json({ error: "Failed to delete article" });
    }
    res.status(200).json({ message: "Article deleted" });
  });
});

// ✅ GET /api/email-settings
app.get("/api/email-settings", authenticateToken, async (req, res) => {
  try {
    const [settings] = await query("SELECT * FROM email_settings LIMIT 1");
    res.json(settings || {}); // ✅ always return valid JSON object
  } catch (err) {
    console.error("Error fetching email settings:", err);
    res.status(500).json({ error: "Failed to fetch email settings" });
  }
});



// ✅ POST /api/email-settings
app.post("/api/email-settings", authenticateToken, (req, res) => {
  const { from_name, from_email } = req.body;

  if (!from_name || !from_email) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const sql = `
    UPDATE email_settings
    SET from_name = ?, from_email = ?
    WHERE id = 1
  `;

  db.query(sql, [from_name, from_email], (err) => {
    if (err) {
      console.error("❌ Failed to update email settings:", err);
      return res.status(500).json({ error: "Failed to update email settings" });
    }

    res.status(200).json({ message: "Email settings updated successfully" });
  });
});

// ✅ GET SLA Settings
app.get("/api/sla-settings", authenticateToken, (req, res) => {
  db.query("SELECT * FROM sla_settings", (err, results) => {
    if (err) {
      console.error("❌ Error fetching SLA settings:", err);
      return res.status(500).json({ error: "Failed to load SLA settings" });
    }
    res.status(200).json(results);
  });
});

// ✅ POST SLA Settings
app.post("/api/sla-settings", authenticateToken, (req, res) => {
  const slaUpdates = req.body; // { Critical: 1, High: 4, ... }

  const updates = Object.entries(slaUpdates).map(([priority, hours]) => {
    return new Promise((resolve, reject) => {
      db.query(
        "UPDATE sla_settings SET hours = ? WHERE priority = ?",
        [hours, priority],
        (err) => {
          if (err) {
            console.error(`❌ Failed updating ${priority}:`, err);
            reject(err);
          } else {
            resolve();
          }
        }
      );
    });
  });

  Promise.all(updates)
    .then(() => res.status(200).json({ message: "SLA settings updated" }))
    .catch(() => res.status(500).json({ error: "Failed to update SLA settings" }));
});

// ✅ Fetch all users
// ✅ GET /api/users - include roles from user_roles
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await query(`
      SELECT 
        u.id, u.username, u.email, u.active, u.team_id, u.first_name, u.last_name,
        GROUP_CONCAT(r.name) AS roles
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      GROUP BY u.id
    `);

    const usersWithRoles = users.map(user => ({
      ...user,
      roles: user.roles ? user.roles.split(",") : [],
    }));

    res.json(usersWithRoles);
  } catch (err) {
    console.error("❌ Failed to fetch users:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});


// ✅ Update user role
// ✅ Update user roles
app.put("/api/users/:id/roles", authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const roles = req.body.roles;

  if (!Array.isArray(roles)) {
    return res.status(400).json({ error: "Roles must be an array." });
  }

  try {
    // Clear old roles
    await query("DELETE FROM user_roles WHERE user_id = ?", [userId]);

    // Insert updated roles (always keep selfservice)
    const finalRoles = [...new Set(["selfservice", ...roles])];

    for (const roleName of finalRoles) {
      const [roleRow] = await query("SELECT id FROM roles WHERE name = ?", [roleName]);
      if (roleRow) {
        await query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleRow.id]);
      }
    }

    res.status(200).json({ message: "Roles updated" });
  } catch (err) {
    console.error("❌ Failed to update user roles:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// ✅ Toggle user status (activate/deactivate)
app.put("/api/users/:id/status", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  const sql = "UPDATE users SET active = ? WHERE id = ?";
  db.query(sql, [active ? 1 : 0, id], (err) => {
    if (err) {
      console.error("❌ Failed to update status:", err);
      return res.status(500).json({ error: "Failed to update status" });
    }
    res.status(200).json({ message: "User status updated" });
  });
});

// ✅ Reset user password to 'changeme123'
const bcrypt = require("bcrypt");
app.put("/api/users/:id/reset-password", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    await query("UPDATE users SET password = ? WHERE id = ?", [hashed, id]);
    res.status(200).json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("❌ Password reset failed:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});


app.get("/api/audit-logs", authenticateToken, (req, res) => {
  db.query("SELECT * FROM audit_logs ORDER BY timestamp DESC", (err, results) => {
    if (err) {
      console.error("❌ Failed to fetch audit logs:", err);
      return res.status(500).json({ error: "Failed to load audit logs" });
    }
    res.status(200).json(results);
  });
});

// ✅ GET /api/system-settings
app.get("/api/system-settings", authenticateToken, async (req, res) => {
  try {
    const [settings] = await query("SELECT * FROM system_settings LIMIT 1");
    res.json(settings || {});
  } catch (err) {
    console.error("Error fetching system settings:", err);
    res.status(500).json({ error: "Failed to fetch system settings" });
  }
});



// ✅ POST /api/system-settings
app.post("/api/system-settings", authenticateToken, (req, res) => {
  const { system_name, timezone, date_format, maintenance_mode } = req.body;

  if (!system_name || !timezone || !date_format) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const sql = `
    UPDATE system_settings
    SET system_name = ?, timezone = ?, date_format = ?, maintenance_mode = ?
    WHERE id = 1
  `;

  db.query(sql, [system_name, timezone, date_format, maintenance_mode ? 1 : 0], (err) => {
    if (err) {
      console.error("❌ Failed to update system settings:", err);
      return res.status(500).json({ error: "Failed to update system settings" });
    }

    res.status(200).json({ message: "System settings updated successfully" });
  });
});

app.get("/api/roles", authenticateToken, (req, res) => {
  db.query("SELECT * FROM roles", (err, results) => {
    if (err) {
      console.error("❌ Failed to fetch roles:", err);
      return res.status(500).json({ error: "Failed to load roles" });
    }
    res.status(200).json(results);
  });
});


app.get("/api/permissions", authenticateToken, (req, res) => {
  db.query("SELECT * FROM permissions", (err, results) => {
    if (err) {
      console.error("❌ Failed to fetch permissions:", err);
      return res.status(500).json({ error: "Failed to load permissions" });
    }
    res.status(200).json(results);
  });
});


app.get("/api/roles/:id/permissions", authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT p.id, p.name
    FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
    WHERE rp.role_id = ?
  `;
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("❌ Failed to fetch role permissions:", err);
      return res.status(500).json({ error: "Failed to load role permissions" });
    }
    res.status(200).json(results);
  });
});


app.post("/api/roles/:id/permissions", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { permissionIds } = req.body;

  const deleteSql = "DELETE FROM role_permissions WHERE role_id = ?";
  const insertSql = "INSERT INTO role_permissions (role_id, permission_id) VALUES ?";

  db.query(deleteSql, [id], (err) => {
    if (err) {
      console.error("❌ Failed to clear old permissions:", err);
      return res.status(500).json({ error: "Failed to clear permissions" });
    }

    if (!permissionIds || permissionIds.length === 0) {
      return res.status(200).json({ message: "Permissions cleared" });
    }

    const values = permissionIds.map((pid) => [id, pid]);
    db.query(insertSql, [values], (err) => {
      if (err) {
        console.error("❌ Failed to insert new permissions:", err);
        return res.status(500).json({ error: "Failed to save permissions" });
      }

      res.status(200).json({ message: "Permissions updated successfully" });
    });
  });
});

// ✅ GET all email templates
app.get("/api/email-templates", authenticateToken, async (req, res) => {
  try {
    const templates = await query("SELECT * FROM email_templates");
    res.json(templates);
  } catch (err) {
    console.error("Error fetching email templates:", err);
    res.status(500).json({ error: "Failed to fetch templates" });
  }
});



// ✅ POST create or update email template
app.post("/api/email-templates", authenticateToken, (req, res) => {
  const { id, name, subject, body } = req.body;

  if (!name || !subject || !body) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (id) {
    db.query(
      "UPDATE email_templates SET name = ?, subject = ?, body = ? WHERE id = ?",
      [name, subject, body, id],
      (err) => {
        if (err) {
          console.error("❌ Failed to update template:", err);
          return res.status(500).json({ error: "Failed to update template" });
        }
        res.status(200).json({ message: "Template updated" });
      }
    );
  } else {
    db.query(
      "INSERT INTO email_templates (name, subject, body) VALUES (?, ?, ?)",
      [name, subject, body],
      (err, result) => {
        if (err) {
          console.error("❌ Failed to insert template:", err);
          return res.status(500).json({ error: "Failed to save template" });
        }
        res.status(201).json({ id: result.insertId });
      }
    );
  }
});

// ✅ DELETE email template
app.delete("/api/email-templates/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM email_templates WHERE id = ?", [id], (err) => {
    if (err) {
      console.error("❌ Failed to delete template:", err);
      return res.status(500).json({ error: "Failed to delete template" });
    }
    res.status(200).json({ message: "Template deleted" });
  });
});

// ✅ POST /api/teams - Create a new team
app.post("/api/teams", authenticateToken, async (req, res) => {
  const { name } = req.body;

  if (!name || name.trim() === "") {
    return res.status(400).json({ error: "Team name is required" });
  }

  try {
    const result = await query("INSERT INTO teams (name) VALUES (?)", [name]);
    res.status(201).json({ id: result.insertId, name });
  } catch (err) {
    console.error("❌ Failed to create team:", err);
    res.status(500).json({ error: "Failed to create team" });
  }
});

// ✅ GET /api/teams - fetch all teams
app.get("/api/teams", authenticateToken, async (req, res) => {
  try {
    const results = await query("SELECT * FROM teams ORDER BY name ASC");
    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Failed to fetch teams:", err);
    res.status(500).json({ error: "Failed to fetch teams" });
  }
});

// ✅ PUT /api/users/:id/team - Assign user to a team
app.put("/api/users/:id/team", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { team_id } = req.body;

  const sql = "UPDATE users SET team_id = ? WHERE id = ?";
  db.query(sql, [team_id || null, id], (err) => {
    if (err) {
      console.error("❌ Failed to assign team:", err);
      return res.status(500).json({ error: "Failed to assign team" });
    }
    res.status(200).json({ message: "Team assigned successfully" });
  });
});


// ✅ POST /api/users - Create new user
// ✅ Updated POST /api/users to support multiple roles
app.post("/api/users", authenticateToken, async (req, res) => {
  const { username, email, roles, password, first_name, last_name } = req.body;

  if (!username || !email || !roles || !password || !first_name || !last_name) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const existing = await query(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: "Username or email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Create user (without storing single role)
    const result = await query(
      `INSERT INTO users (username, email, password, active, first_name, last_name)
       VALUES (?, ?, ?, 1, ?, ?)`,
      [username, email, hashedPassword, first_name, last_name]
    );

    const userId = result.insertId;

    // ✅ Insert selected roles into user_roles
    for (const roleName of roles) {
      const [roleRow] = await query("SELECT id FROM roles WHERE name = ?", [roleName]);
      if (roleRow) {
        await query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleRow.id]);
      }
    }

    res.status(201).json({ message: "User created", id: userId });
  } catch (err) {
    console.error("❌ Error creating user:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



// ✅ Check if username or email exists
app.get("/api/users/check", authenticateToken, async (req, res) => {
  const { username, email } = req.query;

  if (!username && !email) {
    return res.status(400).json({ error: "Missing username or email" });
  }

  try {
    const result = await query(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username || "", email || ""]
    );

    res.status(200).json({ exists: result.length > 0 });
  } catch (err) {
    console.error("❌ Error checking user:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// ✅ Centralized Attachments API

// Reuse multer from above (already defined as `upload`)
const uploadAttachment = upload.single("file");

// POST /api/attachments
app.post("/api/attachments", authenticateToken, upload.single("file"), async (req, res) => {
  const { entity_type, entity_id } = req.body;

  if (!req.file || !entity_type || !entity_id) {
    return res.status(400).json({ error: "Missing required data or file" });
  }

  const filePath = `/uploads/${req.file.filename}`;
  const originalName = req.file.originalname;
  const uploadedBy = req.user?.username || "Unknown";

  try {
    const result = await query(
      "INSERT INTO attachments (entity_type, entity_id, file_path, original_name, uploaded_by, uploaded_at) VALUES (?, ?, ?, ?, ?, NOW())",
      [entity_type, entity_id, filePath, originalName, uploadedBy]
    );

    res.status(201).json({
      id: result.insertId,
      file_path: filePath,
      original_name: originalName,
      uploaded_by: uploadedBy,
      uploaded_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Error saving attachment:", err);
    res.status(500).json({ error: "Failed to save attachment" });
  }
});


// GET /api/attachments?type=incident&id=123
app.get("/api/attachments", authenticateToken, async (req, res) => {
  const { type, id } = req.query;

  if (!type || !id) {
    return res.status(400).json({ error: "Missing type or id query parameter" });
  }

  try {
    const sql = `
      SELECT id, file_path, original_name, uploaded_at, uploaded_by
      FROM attachments
      WHERE entity_type = ? AND entity_id = ?
      ORDER BY uploaded_at DESC
    `;
    const results = await query(sql, [type, id]);
    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Error fetching attachments:", err);
    res.status(500).json({ error: "Failed to load attachments" });
  }
});

app.delete("/api/attachments/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await query("DELETE FROM attachments WHERE id = ?", [id]);
    res.status(200).json({ message: "Attachment deleted" });
  } catch (err) {
    console.error("❌ Error deleting attachment:", err);
    res.status(500).json({ error: "Failed to delete attachment" });
  }
});

//tsks

// ✅ TASKS API ROUTES

// 🔹 1. GET all tasks relevant to current user or team
app.get("/api/tasks", authenticateToken, async (req, res) => {
  const { id: userId, team_id: teamId } = req.user;

  try {
    const results = await query(
      `SELECT * FROM tasks WHERE assigned_user_id = ? OR assigned_team_id = ?`,
      [userId, teamId]
    );

    res.json(results);
  } catch (err) {
    console.error("❌ Failed to fetch tasks:", err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

// 🔹 2. GET all tasks linked to a specific entity (e.g., service request, change)
app.get("/api/tasks/type/:type/:id", authenticateToken, async (req, res) => {
  const { type, id } = req.params;

  try {
    const tasks = await query(
      "SELECT * FROM tasks WHERE linked_type = ? AND linked_id = ?",
      [type, id]
    );
    res.status(200).json(tasks);
  } catch (err) {
    console.error("❌ Failed to fetch tasks by type and ID:", err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

// 🔹 3. GET a single task by ID
app.get("/api/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [task] = await query("SELECT * FROM tasks WHERE id = ?", [id]);
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }
    res.status(200).json(task);
  } catch (err) {
    console.error("❌ Failed to fetch task by ID:", err);
    res.status(500).json({ error: "Failed to fetch task" });
  }
});

// 🔹 4. POST create a new task
app.post("/api/tasks", authenticateToken, async (req, res) => {
  const {
    title,
    description,
    status,
    due_date,
    assigned_user_id,
    linked_type,
    linked_id,
  } = req.body;

  const created_by = req.user.id;

  try {
    const result = await query(
      "INSERT INTO tasks (title, description, status, due_date, assigned_user_id, linked_type, linked_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [title, description, status, due_date, assigned_user_id, linked_type, linked_id, created_by]
    );

    res.json({ id: result.insertId });
  } catch (err) {
    console.error("❌ Failed to create task:", err);
    res.status(500).json({ error: "Failed to create task" });
  }
});

// 🔹 5. PUT update an existing task
app.put("/api/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, status, due_date, assigned_user_id } = req.body;

  try {
    await query(
      "UPDATE tasks SET title = ?, description = ?, status = ?, due_date = ?, assigned_user_id = ? WHERE id = ?",
      [title, description, status, due_date, assigned_user_id, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Failed to update task:", err);
    res.status(500).json({ error: "Failed to update task" });
  }
});

// 🔹 6. DELETE a task
app.delete("/api/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    await query("DELETE FROM tasks WHERE id = ?", [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Failed to delete task:", err);
    res.status(500).json({ error: "Failed to delete task" });
  }
});

// ✅ PUT /api/tasks/:id/assign - Reassign task to user or team
app.put("/api/tasks/:id/assign", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { assigned_user_id, assigned_team_id } = req.body;

  try {
    await query(
      "UPDATE tasks SET assigned_user_id = ?, assigned_team_id = ? WHERE id = ?",
      [assigned_user_id || null, assigned_team_id || null, id]
    );
    res.status(200).json({ message: "Task reassigned successfully." });
  } catch (err) {
    console.error("❌ Failed to reassign task:", err);
    res.status(500).json({ error: "Failed to reassign task" });
  }
});



// GET all templates
app.get('/api/templates', authenticateToken, async (req, res) => {
  try {
    const templates = await query('SELECT * FROM service_request_templates');
    res.json(templates);
  } catch (err) {
    console.error("❌ Template fetch error:", err);
    res.status(500).json({ error: 'Failed to fetch templates' });
  }
});

// POST create template
// POST create template
app.post("/api/templates", authenticateToken, async (req, res) => {
  const { name, description, auto_tasks } = req.body;

  console.log("📦 Creating template with data:", { name, description, auto_tasks });

  if (!name) {
    return res.status(400).json({ error: "Template name is required" });
  }

  try {
    // ✅ Ensure auto_tasks is valid JSON
    let autoTasksJson = "[]";
    if (Array.isArray(auto_tasks)) {
      autoTasksJson = JSON.stringify(auto_tasks);
    } else if (typeof auto_tasks === "string") {
      try {
        const parsed = JSON.parse(auto_tasks);
        if (Array.isArray(parsed)) {
          autoTasksJson = JSON.stringify(parsed);
        }
      } catch (err) {
        console.warn("⚠️ auto_tasks is invalid JSON. Defaulting to []");
      }
    }

    const result = await db.query(
      "INSERT INTO service_request_templates (name, description, auto_tasks) VALUES (?, ?, ?)",
      [name, description || null, autoTasksJson]
    );

    console.log("✅ Template created with ID:", result.insertId);
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error("❌ Template create error:", err);
    res.status(500).json({ error: "Failed to create template" });
  }
});


// PUT update template
app.put('/api/templates/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, description, auto_tasks } = req.body;
  try {
    await db.query(
      'UPDATE service_request_templates SET name = ?, description = ?, auto_tasks = ? WHERE id = ?',
      [name, description, JSON.stringify(auto_tasks || []), id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Template update error:", err);
    res.status(500).json({ error: 'Failed to update template' });
  }
});

// DELETE /api/templates/:id
app.delete('/api/templates/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [existing] = await query('SELECT id FROM service_request_templates WHERE id = ?', [id]);
    if (!existing) {
      return res.status(404).json({ error: "Template not found" });
    }

    await query('DELETE FROM service_request_templates WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Failed to delete template:", err);
    res.status(500).json({ error: "Failed to delete template" });
  }
});


///notifications

// ✅ Fetch notifications for the logged-in user
app.get("/api/notifications", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const results = await query(
      "SELECT id, message, link, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );
    res.json(results);
  } catch (err) {
    console.error("❌ Failed to fetch notifications:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});


app.post("/api/notifications", authenticateToken, async (req, res) => {
  const { user_id, message, link } = req.body;
  if (!user_id || !message) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    await query(
      `INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)`,
      [user_id, message, link || null]
    );

    const io = req.app.get("io");
    io.to(`user_${user_id}`).emit("new_notification", { user_id, message, link });

    res.status(201).json({ message: "Notification created" });
  } catch (err) {
    console.error("❌ Failed to create notification:", err);
    res.status(500).json({ error: "Failed to create notification" });
  }
});

app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  const notificationId = req.params.id;
  try {
    await query(
      `UPDATE notifications SET is_read = 1 WHERE id = ?`,
      [notificationId]
    );
    res.json({ message: "Marked as read" });
  } catch (err) {
    console.error("❌ Failed to mark as read:", err);
    res.status(500).json({ error: "Failed to update notification" });
  }
});


app.put("/api/notifications/mark-all-read", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    await query(
      "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
      [userId]
    );
    res.json({ message: "All notifications marked as read" });
  } catch (err) {
    console.error("❌ Failed to mark all as read:", err);
    res.status(500).json({ error: "Failed to mark notifications as read" });
  }
});


app.delete("/api/notifications/:id", authenticateToken, async (req, res) => {
  const notificationId = req.params.id;
  try {
    await query(`DELETE FROM notifications WHERE id = ?`, [notificationId]);
    res.json({ message: "Notification deleted" });
  } catch (err) {
    console.error("❌ Failed to delete notification:", err);
    res.status(500).json({ error: "Failed to delete notification" });
  }
});


console.log("✅ Available Routes:");
app._router.stack.forEach((r) => {
  if (r.route && r.route.path) {
    console.log(r.route.path);
  }
});


// PUT /api/incidents/:id/update-customer
app.put("/api/incidents/:id/update-customer", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { newCustomerId } = req.body;

  try {
    const [user] = await query("SELECT id FROM users WHERE id = ?", [newCustomerId]);

    if (!user) {
      return res.status(404).json({ error: "Selected customer not found." });
    }

    await query("UPDATE incidents SET created_by = ? WHERE id = ?", [newCustomerId, id]);

    res.json({ success: true, message: "Customer updated successfully." });
  } catch (err) {
    console.error("❌ Failed to update customer:", err);
    res.status(500).json({ error: "Failed to update customer." });
  }
});


// ✅ Start Server
// ✅ Start Server with Socket.IO support
server.listen(PORT, () => {
  console.log(`✅ Server + Socket.IO running at http://localhost:${PORT}`);
});
