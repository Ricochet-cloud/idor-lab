/**
 * IDOR (Insecure Direct Object Reference) Lab
 * -------------------------------------------
 * This server is INTENTIONALLY VULNERABLE for educational purposes.
 * Do not deploy this code anywhere reachable by the public internet.
 *
 * Scenario:
 *   - Users log in and get a simple session token.
 *   - GET /api/user/:id returns that user's profile.
 *   - THE BUG: the vulnerable endpoint checks that you are LOGGED IN,
 *     but never checks that the :id you asked for is actually YOUR id.
 *     So any logged-in user can read anyone else's profile just by
 *     changing the number in the URL. This is IDOR / Broken Object
 *     Level Authorization (OWASP API Security Top 10 - API1:2023).
 *
 * The server also exposes a FIXED version of the same endpoint at
 * /api/secure/user/:id so the before/after behavior can be compared.
 */

const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

// ---------------------------------------------------------------------
// "Database" (in-memory, for lab purposes only)
// ---------------------------------------------------------------------
const users = {
  1: {
    id: 1,
    username: "alice",
    password: "alice123",
    email: "alice@example.com",
    secretNote: "Alice's private note: I hid the spare key under the mat.",
  },
  2: {
    id: 2,
    username: "bob",
    password: "bob123",
    email: "bob@example.com",
    secretNote: "Bob's private note: My bank PIN is 4821.",
  },
  3: {
    id: 3,
    username: "carol",
    password: "carol123",
    email: "carol@example.com",
    secretNote: "Carol's private note: Planning a surprise party for Dave.",
  },
};

// token -> userId   (very simplified "session" store; not production auth)
const sessions = {};

function findUserByUsername(username) {
  return Object.values(users).find((u) => u.username === username);
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = findUserByUsername(username);

  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = crypto.randomBytes(16).toString("hex");
  sessions[token] = user.id;

  res.json({
    message: "Login successful",
    token,
    userId: user.id,
  });
});

function requireLogin(req, res, next) {
  const token = req.header("Authorization");
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: "Missing or invalid token" });
  }
  req.userId = sessions[token]; // the id of whoever actually owns this token
  next();
}

// ---------------------------------------------------------------------
// VULNERABLE endpoint: checks you're logged in, but NOT that :id is you
// ---------------------------------------------------------------------
app.get("/api/user/:id", requireLogin, (req, res) => {
  const user = users[req.params.id];
  if (!user) return res.status(404).json({ error: "User not found" });

  // BUG: no check that req.userId === user.id
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    secretNote: user.secretNote,
  });
});

// ---------------------------------------------------------------------
// FIXED endpoint: enforces object-level authorization
// ---------------------------------------------------------------------
app.get("/api/secure/user/:id", requireLogin, (req, res) => {
  const requestedId = Number(req.params.id);

  if (requestedId !== req.userId) {
    return res.status(403).json({
      error: "Forbidden: you are not allowed to view this user's data",
    });
  }

  const user = users[requestedId];
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    secretNote: user.secretNote,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`IDOR lab server running on http://0.0.0.0:${PORT}`);
  console.log("Test accounts: alice/alice123, bob/bob123, carol/carol123");
});
