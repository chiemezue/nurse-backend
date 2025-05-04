import express from "express";
import pg from "pg";
import bcryptjs from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { dirname } from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import cron from "node-cron";
import { DateTime } from "luxon";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 3000;

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
//SESSION CREATION

const db = new pg.Client({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect();

//REGISTRATION AUTHENTICATION

app.post("/api/register", async (req, res) => {
  const { fname, mname, lname, regno, level, email, pwd } = req.body;

  // Hashing password
  const salt = await bcryptjs.genSalt(10);
  const hashedPwd = await bcryptjs.hash(pwd, salt);

  try {
    // ✅ Check if regno exists in any of the valid year tables
    const tables = ["secondYear", "thirdYear", "fourthYear", "fifthYear"];
    let regnoFound = false;

    for (const table of tables) {
      const check = await db.query(`SELECT * FROM ${table} WHERE regno = $1`, [
        regno,
      ]);
      if (check.rows.length > 0) {
        regnoFound = true;
        break;
      }
    }

    if (!regnoFound) {
      console.log("You are not a nursing student");
      return res.status(403).json({
        message: "RegNo not found in Nursing Student Records",
      });
    }

    // Check if the email ended with stu.unizik.edu.ng or the regno has 634 in
    const emailVerify = "stu.unizik.edu.ng";

    if (!email.endsWith(emailVerify)) {
      console.log("Put your school email");
      return res.status(400).json({ message: "Put your school email" });
    }

    // ✅ Check if email or regno already exists in users table
    const duplicateCheck1 = await db.query(
      "SELECT * FROM users WHERE email = $1 OR regno = $2",
      [email, regno]
    );

    if (duplicateCheck1.rows.length > 0) {
      console.log("Email or reg no or username exist");

      return res
        .status(409)
        .json({ message: "Email or Registration Number already registered" });
    }

    // ✅ Insert user into users table
    await db.query(
      "INSERT INTO users(fname, mname, lname, regno, levels, email, pwd) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [fname, mname, lname, regno, level, email, hashedPwd]
    );

    // Fetch the user data, including the 'person' column
    const newUser = await db.query(
      "SELECT * FROM users WHERE email = $1 AND regno = $2",
      [email, regno]
    );

    // Generate a JWT token
    const user = newUser.rows[0]; // you can include additional details like user ID
    const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "3h" });

    console.log("User registered successfully");

    // Send back the data, including the 'person' column
    return res.status(201).json({
      message: "User registered successfully",
      token,
      person: user.person, // Send the user data with the 'person' column
      id: user.id,
    });
  } catch (err) {
    console.error("Error registering user:", err);
    return res
      .status(500)
      .json({ error: "An error occurred during registration" });
  }
});

//ADMIN REGISTRATION AUTHENTICATION
app.post("/api/admins/register", async (req, res) => {
  const { name, email, password, person } = req.body;

  const fname = name.trim(); // Use name as fname

  try {
    // Hash password
    const salt = await bcryptjs.genSalt(10);
    const hashedPwd = await bcryptjs.hash(password, salt);

    // Insert admin into users table
    await db.query(
      "INSERT INTO users(fname, email, pwd, person) VALUES ($1, $2, $3, $4)",
      [fname, email, hashedPwd, person]
    );

    console.log("Admin registered successfully");

    return res.status(201).json({
      success: true,
      message: "Admin registered successfully",
      admin: { fname, email, person },
    });
  } catch (err) {
    console.error("Error registering admin:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

//LOGIN AUTHENTICATION
app.post("/api/login", async (req, res) => {
  const { identifier, pwd } = req.body;

  try {
    const result = await db.query(
      "SELECT * FROM users WHERE regno = $1 OR email = $1",
      [identifier]
    );

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.pwd;

      const isMatch = await bcryptjs.compare(pwd, storedPassword);

      if (!isMatch) {
        return res.status(401).json({ message: "Incorrect password" });
      }

      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: "3h",
      });

      console.log("User logged in successfully");
      return res.status(200).json({
        message: "Login successful",
        token,
        person: user.person, // e.g. "Student"
        id: user.id,
      });
    } else {
      return res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ message: error.message });
  }
});

///USER VISTITS
// Track visit route
app.post("/api/track-visit", async (req, res) => {
  console.log("Request body:", req.body); // Log incoming data

  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    const query = `
      INSERT INTO user_visits (user_id, visited_at) 
      VALUES ($1, CURRENT_TIMESTAMP)
    `;
    await db.query(query, [userId]);

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error tracking visit:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Cleanup task to delete records older than 6 months
cron.schedule("0 0 1 * *", async () => {
  // Runs at midnight on the 1st of every month
  try {
    const sixMonthsAgo = DateTime.now().minus({ months: 6 }).toISODate();
    const query = `DELETE FROM user_visits WHERE visited_at < $1`;
    await db.query(query, [sixMonthsAgo]);
    console.log("Old user visits deleted successfully");
  } catch (error) {
    console.error("Error during cleanup task:", error);
  }
});

// Backend endpoint to fetch visit counts (for Chart.js)
app.get("/api/visit-count", async (req, res) => {
  try {
    const query = `
      SELECT DATE(visited_at) as date, COUNT(*) as visit_count
      FROM user_visits
      GROUP BY DATE(visited_at)
      ORDER BY date DESC
      LIMIT 30`; // Get visits for the last 30 days

    const result = await db.query(query);
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    console.error("Error fetching visit count:", error);
    res.status(500).json({ error: "Server error" });
  }
});

//PROTECTED ROUTES

const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers["authorization"].split(" ")[1];
    if (!token) {
      return res.status(403).json({ message: "No token found" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
};

app.get("/", verifyToken, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      req.userId,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      return res.status(200).json({ user: user });
    }
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
});

//SUBMITTING THE PDF FORM
const storage = multer.diskStorage({
  destination: (req, res, cb) => {
    const uploadPath = "uploads/";
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const originalName = file.originalname;
    const extname = path.extname(originalName);
    const baseName = path.basename(originalName, extname);

    let fileName = originalName;
    let fileIndex = 1;

    // Check if file with the same name already exists and append a number
    while (fs.existsSync(path.join("uploads", fileName))) {
      fileName = `${baseName}_${fileIndex}${extname}`;
      fileIndex++;
    }

    cb(null, fileName);
  },
});

const upload = multer({ storage });

// Serve static files from the "uploads" directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Upload route to handle both single and multiple files
app.post("/api/upload", upload.array("pdfs"), async (req, res) => {
  const { description, category } = req.body;
  const files = req.files; // Array of uploaded files

  if (!files || files.length === 0) {
    return res.status(400).json({ error: "No files uploaded" });
  }

  try {
    const insertQueries = files.map((file) => {
      const query = `INSERT INTO pdfs (description, category, filename, filepath) VALUES ($1, $2, $3, $4) RETURNING *;`;
      const values = [description, category, file.filename, file.path];
      return db.query(query, values);
    });

    // Execute all insert queries in parallel
    const results = await Promise.all(insertQueries);
    const uploadedFiles = results.map((result) => result.rows[0]);

    res.status(200).json({
      success: true,
      data: uploadedFiles,
    });
  } catch (error) {
    console.error("Error uploading files:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/resources", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM pdfs ORDER BY id DESC");
    res.json({ resources: result.rows });
  } catch (error) {
    console.error("Error fetching PDFs:", error);
    res.status(500).json({ error: "Server error" });
  }
});

//Deleting pfs
app.delete("/api/resources/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query("DELETE FROM pdfs WHERE id = $1", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "PDF not found" });
    }

    res.json({ success: true, message: "PDF deleted successfully" });
  } catch (error) {
    console.error("Error deleting PDF:", error);
    res.status(500).json({ error: "Server error" });
  }
});

//deleting students
app.delete("/api/students/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query("DELETE FROM users WHERE id = $1", [id]);

    if (result.rowCount === 0) {
      return res.status(404).send({ error: "User not found" });
    }

    res.status(200).send({ message: "User deleted" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send({ error: "Error deleting user" });
  }
});

//Recently added books
app.get("/api/resources/recent", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM pdfs ORDER BY uploaded_at DESC LIMIT 4"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching recent PDFs:", error);
    res.status(500).json({ error: "Server error" });
  }
});

///ADMIN DESIGNS
//Dynamic numbers
// Example route: GET /api/stats

app.get("/api/stats", async (req, res) => {
  try {
    const usersResult = await db.query("SELECT COUNT(*) FROM users");
    const booksResult = await db.query("SELECT COUNT(*) FROM pdfs"); // Replace 'books' with your actual table

    res.json({
      totalUsers: parseInt(usersResult.rows[0].count, 10),
      totalBooks: parseInt(booksResult.rows[0].count, 10),
    });
  } catch (err) {
    console.error("Stats fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

//fetching users and admin
app.get("/api/admins", async (req, res) => {
  try {
    // Fetch all users (admins and students) from the database
    const result = await db.query("SELECT * FROM users");

    // Return the list of users to the frontend
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
