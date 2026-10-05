const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@libsql/client");
const cookieParser = require("cookie-parser");

const app = express();

const dbUrl = process.env.TURSO_DATABASE_URL;
const dbToken = process.env.TURSO_AUTH_TOKEN;

if (!dbUrl || !dbToken) {
  console.error("Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN");
}

const db = createClient({
  url: dbUrl || "file:local.db",
  authToken: dbToken,
});

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

let initPromise;

function initDb() {
  if (!initPromise) {
    initPromise = db.batch([
      `CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS expenses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL,
        subcategory TEXT,
        payment TEXT,
        type TEXT,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`,
      `CREATE TABLE IF NOT EXISTS incomes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        amount REAL NOT NULL,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`,
      `CREATE TABLE IF NOT EXISTS budgets(
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        PRIMARY KEY(user_id, category),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`,
      `CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`
    ]);
  }
  return initPromise;
}

const makeHash = (password) => new Promise((resolve, reject) => {
  crypto.scrypt(password, "deabul-salt", 64, (err, key) => {
    if (err) reject(err);
    else resolve(key.toString("hex"));
  });
});

async function auth(req, res, next) {
  try {
    await initDb();
    const token = req.cookies.session;
    if (!token) return res.status(401).json({ error: "לא מחובר" });
    const result = await db.execute({
      sql: "SELECT user_id FROM sessions WHERE token = ?",
      args: [token]
    });
    if (!result.rows.length) return res.status(401).json({ error: "לא מחובר" });
    req.uid = Number(result.rows[0].user_id);
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
}

app.post("/api/register", async (req, res) => {
  try {
    await initDb();
    let { username, password } = req.body || {};
    username = (username || "").trim();
    if (username.length < 3 || !password || password.length < 6) {
      return res.status(400).json({ error: "שם משתמש צריך 3 תווים לפחות וסיסמה 6 תווים לפחות" });
    }
    const h = await makeHash(password);
    const result = await db.execute({
      sql: "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,datetime('now'))",
      args: [username, h]
    });
    const token = crypto.randomBytes(32).toString("hex");
    await db.execute({
      sql: "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,datetime('now'))",
      args: [token, result.lastInsertRowid]
    });
    res.cookie("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 30
    });
    res.json({ username });
  } catch (e) {
    console.error(e);
    if (String(e.message || "").toLowerCase().includes("unique")) {
      return res.status(409).json({ error: "שם המשתמש כבר קיים" });
    }
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    await initDb();
    const { username, password } = req.body || {};
    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [(username || "").trim()]
    });
    const u = result.rows[0];
    if (!u) return res.status(401).json({ error: "שם משתמש או סיסמה שגויים" });
    const h = await makeHash(password || "");
    if (h !== u.password_hash) return res.status(401).json({ error: "שם משתמש או סיסמה שגויים" });
    const token = crypto.randomBytes(32).toString("hex");
    await db.execute({
      sql: "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,datetime('now'))",
      args: [token, u.id]
    });
    res.cookie("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 30
    });
    res.json({ username: u.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.post("/api/logout", async (req, res) => {
  try {
    await initDb();
    if (req.cookies.session) {
      await db.execute({ sql: "DELETE FROM sessions WHERE token = ?", args: [req.cookies.session] });
    }
    res.clearCookie("session");
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT username,created_at FROM users WHERE id = ?",
      args: [req.uid]
    });
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.get("/api/data", auth, async (req, res) => {
  try {
    const [expenses, incomes, budgets] = await Promise.all([
      db.execute({ sql: "SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC,id DESC", args: [req.uid] }),
      db.execute({ sql: "SELECT * FROM incomes WHERE user_id=? ORDER BY date DESC,id DESC", args: [req.uid] }),
      db.execute({ sql: "SELECT category,amount FROM budgets WHERE user_id=?", args: [req.uid] })
    ]);
    res.json({
      expenses: expenses.rows,
      incomes: incomes.rows,
      budgets: Object.fromEntries(budgets.rows.map(x => [x.category, x.amount]))
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.post("/api/expenses", auth, async (req, res) => {
  try {
    const x = req.body || {};
    if (!x.date || !x.amount || !x.category) return res.status(400).json({ error: "חסרים נתונים" });
    const result = await db.execute({
      sql: "INSERT INTO expenses(user_id,date,amount,category,subcategory,payment,type,note,created_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))",
      args: [req.uid, x.date, +x.amount, x.category, x.subcategory || "", x.payment || "", x.type || "משתנה", x.note || ""]
    });
    res.json({ id: result.lastInsertRowid });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.delete("/api/expenses/:id", auth, async (req, res) => {
  try {
    await db.execute({ sql: "DELETE FROM expenses WHERE id=? AND user_id=?", args: [req.params.id, req.uid] });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.post("/api/incomes", auth, async (req, res) => {
  try {
    const x = req.body || {};
    if (!x.date || !x.amount || !x.source) return res.status(400).json({ error: "חסרים נתונים" });
    await db.execute({
      sql: "INSERT INTO incomes(user_id,date,amount,source,created_at) VALUES(?,?,?,?,datetime('now'))",
      args: [req.uid, x.date, +x.amount, x.source]
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.put("/api/budgets", auth, async (req, res) => {
  try {
    const { category, amount } = req.body || {};
    if (!category) return res.status(400).json({ error: "חסרים נתונים" });
    await db.execute({
      sql: "INSERT INTO budgets(user_id,category,amount) VALUES(?,?,?) ON CONFLICT(user_id,category) DO UPDATE SET amount=excluded.amount",
      args: [req.uid, category, +amount || 0]
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "שגיאת שרת" });
  }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log("Deabul Budget Pro running"));
}

module.exports = app;
