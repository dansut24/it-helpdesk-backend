const mysql = require("mysql");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "it_helpdesk",
});

db.connect((err) => {
  if (err) {
    console.error("❌ DB connect error:", err);
    return;
  }
  console.log("✅ DB Connected");

  db.query("SELECT * FROM users", (err, results) => {
    if (err) {
      console.error("❌ Query error:", err);
    } else {
      console.log("✅ User data:", results);
    }
    db.end();
  });
});
