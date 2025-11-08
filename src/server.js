import express from "express";
import bcrypt from "bcryptjs";
import { v4 as uuid } from "uuid";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json());

const pool = new Pool({
  user: process.env.DBUSER ?? "postgres",
  host: process.env.DBHOST ?? "localhost",
  database: process.env.DBDATABASE ?? "postgres",
  password: process.env.DBPASSWORD ?? "Pra@1ful",
  port: Number(process.env.DBPORT ?? 5432),
});

const ensureUsersTable = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
};

ensureUsersTable().catch((err) => {
  console.error("Failed to initialize database:", err);
  process.exit(1);
});

const sanitizeUser = (userRecord) => ({
  id: userRecord.id,
  username: userRecord.username,
  name: userRecord.name,
});

app.post("/signup", async (req, res) => {
  const { username, name, password } = req.body ?? {};

  if (!username || !name || !password) {
    return res.status(400).json({
      error: "username, name, and password are required",
    });
  }

  try {
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: "username already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuid(),
      username,
      name,
      passwordHash,
    };

    await pool.query(
      `INSERT INTO users (id, username, name, password_hash)
       VALUES ($1, $2, $3, $4)`,
      [newUser.id, newUser.username, newUser.name, newUser.passwordHash]
    );

    return res.status(201).json({
      message: "user created",
      user: sanitizeUser(newUser),
    });
  } catch (err) {
    console.error("Signup failed:", err);
    return res.status(500).json({ error: "failed to create user" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "username and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT id, username, name, password_hash FROM users WHERE username = $1",
      [username]
    );
    const userRecord = result.rows[0];

    if (!userRecord) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    const doesPasswordMatch = await bcrypt.compare(
      password,
      userRecord.password_hash
    );

    if (!doesPasswordMatch) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    return res.json({
      message: "login successful",
      user: sanitizeUser({
        id: userRecord.id,
        username: userRecord.username,
        name: userRecord.name,
      }),
    });
  } catch (err) {
    console.error("Login failed:", err);
    return res.status(500).json({ error: "failed to login" });
  }
});

app.post("/reset-password", async (req, res) => {
  const { username, currentPassword, newPassword } = req.body ?? {};
  if (!username || !currentPassword || !newPassword) {
    return res.status(400).json({
      error: "username, currentPassword, and newPassword are required",
    });
  }

  try {
    const result = await pool.query(
      "SELECT id, username, name, password_hash FROM users WHERE username = $1",
      [username]
    );
    const userRecord = result.rows[0];

    if (!userRecord) {
      return res.status(404).json({ error: "user not found" });
    }

    const doesPasswordMatch = await bcrypt.compare(
      currentPassword,
      userRecord.password_hash
    );

    if (!doesPasswordMatch) {
      return res.status(401).json({ error: "current password is incorrect" });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE username = $2",
      [newPasswordHash, username]
    );

    return res.json({ message: "password updated" });
  } catch (err) {
    console.error("Reset password failed:", err);
    return res.status(500).json({ error: "failed to reset password" });
  }
});

app.get("/users/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, username, name FROM users WHERE username = $1",
      [username]
    );
    const userRecord = result.rows[0];

    if (!userRecord) {
      return res.status(404).json({ error: "user not found" });
    }

    return res.json({ user: sanitizeUser(userRecord) });
  } catch (err) {
    console.error("Fetch user failed:", err);
    return res.status(500).json({ error: "failed to fetch user" });
  }
});

app.get("/users", async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, name FROM users ORDER BY created_at DESC"
    );
    return res.json({ users: result.rows.map(sanitizeUser) });
  } catch (err) {
    console.error("List users failed:", err);
    return res.status(500).json({ error: "failed to list users" });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "route not found" });
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "unexpected error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth API listening on http://localhost:${PORT}`);
});
