const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn("DATABASE_URL is not set. The app will start, but submissions will not be stored.");
}

const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
}) : null;

app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.json({ limit: "50kb" }));
app.use(express.static("public", { extensions: ["html"] }));

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const APP_SECRET = process.env.APP_SECRET || "";
const ENCRYPTION_KEY_HEX = process.env.ENCRYPTION_KEY || "";

function requireSecrets() {
  if (!ADMIN_PASSWORD || !APP_SECRET || !/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY_HEX)) {
    throw new Error("Missing ADMIN_PASSWORD, APP_SECRET, or valid 64-hex ENCRYPTION_KEY.");
  }
}

function encrypt(text) {
  requireSecrets();
  const key = Buffer.from(ENCRYPTION_KEY_HEX, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, encrypted].map(x => x.toString("base64url")).join(".");
}

function decrypt(payload) {
  requireSecrets();
  const [ivB64, tagB64, dataB64] = String(payload).split(".");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(ENCRYPTION_KEY_HEX, "hex"),
    Buffer.from(ivB64, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function sign(value) {
  return crypto.createHmac("sha256", APP_SECRET).update(value).digest("base64url");
}

function makeSession(username) {
  const value = `${username}|${Date.now()}`;
  return `${Buffer.from(value).toString("base64url")}.${sign(value)}`;
}

function isAdmin(req) {
  try {
    const raw = req.headers.cookie?.split(";").map(x => x.trim()).find(x => x.startsWith("admin_session="));
    if (!raw) return false;
    const token = raw.slice("admin_session=".length);
    const [payload, sig] = token.split(".");
    if (!payload || !sig) return false;
    const value = Buffer.from(payload, "base64url").toString("utf8");
    const expected = sign(value);
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
    const [username] = value.split("|");
    return username === ADMIN_USER;
  } catch {
    return false;
  }
}

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id BIGSERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      loan_amount NUMERIC(14,2) NOT NULL,
      email TEXT NOT NULL,
      national_id_encrypted TEXT NOT NULL,
      professional_status TEXT NOT NULL,
      loan_purpose TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
  }[c]));
}

app.get("/", (req, res) => res.redirect("/bot/bot7"));

app.get("/bot/bot7", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "index.html"));
});

app.post("/api/applications", async (req, res) => {
  try {
    const { fullName, loanAmount, email, nationalId, professionalStatus, loanPurpose, consent } = req.body;

    if (!consent) return res.status(400).json({ error: "Consent is required." });
    if (!fullName || !email || !nationalId || !professionalStatus || !loanPurpose) {
      return res.status(400).json({ error: "Please complete all required fields." });
    }

    const amount = Number(loanAmount);
    if (!Number.isFinite(amount) || amount < 50) {
      return res.status(400).json({ error: "Loan amount must be at least 50 USD." });
    }

    if (!pool) return res.status(503).json({ error: "Database is not configured yet." });

    const encryptedId = encrypt(nationalId.trim());

    const result = await pool.query(
      `INSERT INTO applications
       (full_name, loan_amount, email, national_id_encrypted, professional_status, loan_purpose)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, created_at`,
      [fullName.trim(), amount, email.trim(), encryptedId, professionalStatus, loanPurpose]
    );

    res.json({ ok: true, applicationId: result.rows[0].id });
  } catch (err) {
    console.error("Application error:", err.message);
    res.status(500).json({ error: "Unable to submit application." });
  }
});

app.get("/admin/login", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "admin-login.html"));
});

app.post("/admin/login", (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(500).send("ADMIN_PASSWORD is not configured.");
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", `admin_session=${makeSession(username)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`);
    return res.redirect("/admin");
  }
  res.status(401).send("Invalid credentials. <a href='/admin/login'>Try again</a>");
});

app.post("/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  res.redirect("/admin/login");
});

app.get("/admin", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin/login");
  if (!pool) return res.status(503).send("Database is not configured.");

  const { rows } = await pool.query(`
    SELECT id, full_name, loan_amount, email, professional_status, loan_purpose, created_at
    FROM applications ORDER BY created_at DESC LIMIT 200
  `);

  const rowsHtml = rows.map(r => `
    <tr>
      <td>${escapeHtml(r.id)}</td>
      <td>${escapeHtml(r.full_name)}</td>
      <td>$${escapeHtml(r.loan_amount)}</td>
      <td>${escapeHtml(r.email)}</td>
      <td>${escapeHtml(r.professional_status)}</td>
      <td>${escapeHtml(r.loan_purpose)}</td>
      <td>${new Date(r.created_at).toLocaleString()}</td>
      <td><a href="/admin/application/${encodeURIComponent(r.id)}">View</a></td>
    </tr>`).join("");

  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
  <title>Applications</title><style>
  body{font-family:Arial;margin:0;background:#f5f5f5;color:#222}.top{background:#c91b23;color:#fff;padding:18px 24px;display:flex;justify-content:space-between}
  .wrap{padding:24px;overflow:auto}table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;white-space:nowrap}
  th{background:#eee}.logout{color:#fff}.empty{padding:30px;background:#fff}
  </style></head><body><div class="top"><b>Application Admin</b><form method="post" action="/admin/logout"><button>Logout</button></form></div>
  <div class="wrap"><h2>Applications</h2>${rowsHtml ? `<table><thead><tr><th>ID</th><th>Name</th><th>Amount</th><th>Email</th><th>Status</th><th>Purpose</th><th>Created</th><th></th></tr></thead><tbody>${rowsHtml}</tbody></table>` : '<div class="empty">No applications yet.</div>'}</div>
  </body></html>`);
});

app.get("/admin/application/:id", async (req, res) => {
  if (!isAdmin(req)) return res.redirect("/admin/login");
  if (!pool) return res.status(503).send("Database is not configured.");

  const { rows } = await pool.query(
    `SELECT * FROM applications WHERE id=$1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).send("Application not found.");

  const r = rows[0];
  let nationalId = "[unavailable]";
  try { nationalId = decrypt(r.national_id_encrypted); } catch {}

  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
  <title>Application #${escapeHtml(r.id)}</title><style>
  body{font-family:Arial;background:#f5f5f5;margin:0}.top{background:#c91b23;color:#fff;padding:18px 24px}.card{background:#fff;max-width:720px;margin:24px auto;padding:24px;border-radius:8px}
  dt{font-weight:bold;margin-top:16px}dd{margin:5px 0 0;padding:10px;background:#f4f4f4;border-radius:4px}.back{display:inline-block;margin-top:20px}
  </style></head><body><div class="top"><b>Application #${escapeHtml(r.id)}</b></div><div class="card">
  <dl>
  <dt>Nom complet</dt><dd>${escapeHtml(r.full_name)}</dd>
  <dt>Montant</dt><dd>$${escapeHtml(r.loan_amount)}</dd>
  <dt>Email</dt><dd>${escapeHtml(r.email)}</dd>
  <dt>Carte nationale d'identité</dt><dd>${escapeHtml(nationalId)}</dd>
  <dt>Statut professionnel</dt><dd>${escapeHtml(r.professional_status)}</dd>
  <dt>Objet du prêt</dt><dd>${escapeHtml(r.loan_purpose)}</dd>
  <dt>Date</dt><dd>${escapeHtml(new Date(r.created_at).toLocaleString())}</dd>
  </dl><a class="back" href="/admin">← Back to applications</a></div></body></html>`);
});

initDb().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log(`Listening on ${PORT}`));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});
