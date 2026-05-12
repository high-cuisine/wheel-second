/**
 * Wheel API (Node.js + Express + SQLite).
 *
 * Bot contract: return user to https://<your-host>/?token=<jwt>
 * JWT: algorithm HS256, secret from JWT_SECRET.
 * Required claims: sub (string, e.g. Telegram user id), exp.
 * Optional: iss (JWT_ISSUER), aud (JWT_AUDIENCE).
 */
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";
import cookieParser from "cookie-parser";
import multer from "multer";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "";
const JWT_ISSUER = process.env.JWT_ISSUER || undefined;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || undefined;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const DATABASE_PATH =
  process.env.DATABASE_PATH ||
  path.join(__dirname, "..", "..", "data", "wheel.db");
/** Default: wheel-second/uploads (sibling of server/) */
const UPLOAD_DIR =
  process.env.UPLOAD_DIR || path.join(__dirname, "..", "..", "uploads");
const STATIC_DIR =
  process.env.WHEEL_STATIC_DIR || path.join(__dirname, "..", "..");

const REDEEM_HINT =
  process.env.REDEEM_HINT ||
  "Покажите этот код менеджеру в заведении.";

/** Set COOKIE_SECURE=true behind HTTPS (reverse proxy). */
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

const USER_COOKIE = "wheel_session";
const ADMIN_COOKIE = "wheel_admin";
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const ADMIN_SESSION_MS = 24 * 60 * 60 * 1000;

const DRUM_COUNT = 5;

function prizeKey(id) {
  return `p${id}`;
}

function nowMs() {
  return Date.now();
}

function randomCodePart(len = 4) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < len; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}

function generateUniqueCode(db) {
  for (let i = 0; i < 50; i++) {
    const code = `NSK-${randomCodePart()}-${randomCodePart()}`;
    const row = db
      .prepare("SELECT 1 FROM redeem_codes WHERE code = ?")
      .get(code);
    if (!row) return code;
  }
  throw new Error("could not generate unique code");
}

function initDb(db) {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      sub TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_sub TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_sub) REFERENCES users(sub)
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS prizes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      subtitle TEXT NOT NULL DEFAULT '',
      image_path TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS redeem_codes (
      code TEXT PRIMARY KEY,
      user_sub TEXT NOT NULL,
      prize_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      redeemed_at INTEGER,
      redeemed_by TEXT,
      FOREIGN KEY (prize_id) REFERENCES prizes(id)
    );

    CREATE TABLE IF NOT EXISTS spins (
      user_sub TEXT PRIMARY KEY,
      prize_id INTEGER NOT NULL,
      redeem_code TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_sub) REFERENCES users(sub),
      FOREIGN KEY (prize_id) REFERENCES prizes(id),
      FOREIGN KEY (redeem_code) REFERENCES redeem_codes(code)
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_admin_sessions_exp ON admin_sessions(expires_at);
  `);
}

function cleanupSessions(db) {
  const t = nowMs();
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(t);
  db.prepare("DELETE FROM admin_sessions WHERE expires_at < ?").run(t);
}

function getActivePrizes(db) {
  return db
    .prepare(
      `SELECT id, title, subtitle, image_path, sort_order, active
       FROM prizes WHERE active = 1 ORDER BY sort_order ASC, id ASC`,
    )
    .all();
}

function symbolImagesFromPrizes(prizes) {
  const m = {};
  for (const p of prizes) {
    m[prizeKey(p.id)] = `/uploads/${path.basename(p.image_path)}`;
  }
  return m;
}

function verifyJwt(token) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not set");
  }
  const payload = jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256"],
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
  const sub = payload.sub;
  if (sub === undefined || sub === null || sub === "") {
    throw new Error("missing sub");
  }
  return String(sub);
}

function getUserSubFromRequest(db, req) {
  cleanupSessions(db);
  const sid = req.cookies[USER_COOKIE];
  if (!sid) return null;
  const row = db
    .prepare(
      `SELECT user_sub FROM sessions WHERE id = ? AND expires_at > ?`,
    )
    .get(sid, nowMs());
  return row ? row.user_sub : null;
}

function requireAdmin(db, req) {
  cleanupSessions(db);
  const sid = req.cookies[ADMIN_COOKIE];
  if (!sid) return false;
  const row = db
    .prepare(`SELECT 1 FROM admin_sessions WHERE id = ? AND expires_at > ?`)
    .get(sid, nowMs());
  return !!row;
}

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DATABASE_PATH);
db.pragma("journal_mode = WAL");
initDb(db);

const storage = multer.diskStorage({
  destination(_req, _file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename(_req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safe =
      [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(ext) ? ext : ".bin";
    cb(null, `${uuidv4()}${safe}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter(_req, file, cb) {
    const ok = /^image\/(jpeg|png|gif|webp)/i.test(file.mimetype || "");
    cb(null, ok);
  },
});

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: "64kb" }));
app.use("/uploads", express.static(UPLOAD_DIR, { fallthrough: true }));

function buildSessionPayload(userSub) {
  const prizes = getActivePrizes(db);
  const symbol_images = symbolImagesFromPrizes(prizes);
  const spin = db
    .prepare(
      `SELECT redeem_code, prize_id FROM spins WHERE user_sub = ?`,
    )
    .get(userSub);
  const already_spun = !!spin;
  return {
    authenticated: true,
    can_spin: !already_spun && prizes.length > 0,
    already_spun,
    symbol_images,
    redeem_code: spin ? spin.redeem_code : null,
    redeem_hint: REDEEM_HINT,
    prizes: prizes.map((p) => ({
      id: prizeKey(p.id),
      title: p.title,
      subtitle: p.subtitle,
    })),
  };
}

app.post("/api/auth", (req, res) => {
  try {
    const token = req.body?.token;
    if (!token || typeof token !== "string") {
      return res.status(400).json({ error: "token required" });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ error: "server misconfigured: JWT_SECRET" });
    }
    const userSub = verifyJwt(token);
    const t = nowMs();
    db.prepare(
      `INSERT INTO users (sub, created_at) VALUES (?, ?)
       ON CONFLICT(sub) DO NOTHING`,
    ).run(userSub, t);

    const sessionId = uuidv4().replace(/-/g, "") + uuidv4().replace(/-/g, "");
    db.prepare(
      `INSERT INTO sessions (id, user_sub, expires_at) VALUES (?, ?, ?)`,
    ).run(sessionId, userSub, t + SESSION_MS);

    res.cookie(USER_COOKIE, sessionId, {
      httpOnly: true,
      sameSite: "lax",
      secure: COOKIE_SECURE,
      maxAge: SESSION_MS,
      path: "/",
    });
    return res.json({ ok: true });
  } catch (e) {
    return res
      .status(401)
      .json({ error: "invalid token", detail: String(e.message) });
  }
});

function sessionHandler(req, res) {
  try {
    const userSub = getUserSubFromRequest(db, req);
    if (!userSub) {
      return res.status(401).json({ error: "unauthorized" });
    }
    return res.json(buildSessionPayload(userSub));
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
}

app.get("/api/session", sessionHandler);
app.get("/api/roulette", sessionHandler);

function spinHandler(req, res) {
  try {
    const userSub = getUserSubFromRequest(db, req);
    if (!userSub) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const existing = db
      .prepare(`SELECT redeem_code, prize_id FROM spins WHERE user_sub = ?`)
      .get(userSub);
    if (existing) {
      return res.status(409).json({
        error: "already_spun",
        redeem_code: existing.redeem_code,
        redeem_hint: REDEEM_HINT,
      });
    }

    const prizes = getActivePrizes(db);
    if (prizes.length === 0) {
      return res.status(400).json({ error: "no_active_prizes" });
    }

    const pick = prizes[Math.floor(Math.random() * prizes.length)];
    const code = generateUniqueCode(db);
    const t = nowMs();
    const pk = prizeKey(pick.id);
    const symbols = Array(DRUM_COUNT).fill(pk);
    const symbol_images = symbolImagesFromPrizes(prizes);

    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO redeem_codes (code, user_sub, prize_id, created_at, redeemed_at, redeemed_by)
         VALUES (?, ?, ?, ?, NULL, NULL)`,
      ).run(code, userSub, pick.id, t);
      db.prepare(
        `INSERT INTO spins (user_sub, prize_id, redeem_code, created_at)
         VALUES (?, ?, ?, ?)`,
      ).run(userSub, pick.id, code, t);
    });
    tx();

    return res.json({
      win: true,
      symbols,
      prize: pick.title,
      prize_description: pick.subtitle || REDEEM_HINT,
      symbol_images,
      redeem_code: code,
      redeem_hint: REDEEM_HINT,
      prizes: prizes.map((p) => ({
        id: prizeKey(p.id),
        title: p.title,
        subtitle: p.subtitle,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
}

app.post("/api/spin", spinHandler);
app.post("/api/roulette", spinHandler);

app.post("/api/admin/login", (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: "ADMIN_PASSWORD not set" });
  }
  const pw = req.body?.password;
  if (pw !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "invalid password" });
  }
  const t = nowMs();
  const sid = uuidv4().replace(/-/g, "") + uuidv4().replace(/-/g, "");
  db.prepare(`INSERT INTO admin_sessions (id, expires_at) VALUES (?, ?)`).run(
    sid,
    t + ADMIN_SESSION_MS,
  );
  res.cookie(ADMIN_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    maxAge: ADMIN_SESSION_MS,
    path: "/",
  });
  return res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  const sid = req.cookies[ADMIN_COOKIE];
  if (sid) {
    db.prepare(`DELETE FROM admin_sessions WHERE id = ?`).run(sid);
  }
  res.clearCookie(ADMIN_COOKIE, { path: "/" });
  return res.json({ ok: true });
});

function adminOnly(req, res, next) {
  if (!requireAdmin(db, req)) {
    return res.status(401).json({ error: "admin required" });
  }
  next();
}

app.get("/api/admin/prizes", adminOnly, (_req, res) => {
  const rows = db
    .prepare(
      `SELECT id, title, subtitle, image_path, sort_order, active FROM prizes ORDER BY sort_order, id`,
    )
    .all();
  res.json({
    prizes: rows.map((p) => ({
      ...p,
      image_url: `/uploads/${path.basename(p.image_path)}`,
    })),
  });
});

app.post("/api/admin/prizes", adminOnly, upload.single("image"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "image file required" });
    }
    const title = (req.body?.title || "Приз").slice(0, 200);
    const subtitle = (req.body?.subtitle || "").slice(0, 500);
    const sort_order = Number(req.body?.sort_order) || 0;
    const rel = req.file.filename;
    const fullPath = path.join(UPLOAD_DIR, rel);
    const info = db
      .prepare(
        `INSERT INTO prizes (title, subtitle, image_path, sort_order, active)
         VALUES (?, ?, ?, ?, 1)`,
      )
      .run(title, subtitle, fullPath, sort_order);
    return res.json({
      ok: true,
      id: info.lastInsertRowid,
      image_url: `/uploads/${rel}`,
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message) });
  }
});

app.patch("/api/admin/prizes/:id", adminOnly, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "invalid id" });
  const row = db.prepare(`SELECT id FROM prizes WHERE id = ?`).get(id);
  if (!row) return res.status(404).json({ error: "not found" });

  const updates = [];
  const vals = [];
  if (req.body.title !== undefined) {
    updates.push("title = ?");
    vals.push(String(req.body.title).slice(0, 200));
  }
  if (req.body.subtitle !== undefined) {
    updates.push("subtitle = ?");
    vals.push(String(req.body.subtitle).slice(0, 500));
  }
  if (req.body.sort_order !== undefined) {
    updates.push("sort_order = ?");
    vals.push(Number(req.body.sort_order) || 0);
  }
  if (req.body.active !== undefined) {
    updates.push("active = ?");
    vals.push(req.body.active ? 1 : 0);
  }
  if (!updates.length) {
    return res.json({ ok: true });
  }
  vals.push(id);
  db.prepare(`UPDATE prizes SET ${updates.join(", ")} WHERE id = ?`).run(
    ...vals,
  );
  return res.json({ ok: true });
});

app.delete("/api/admin/prizes/:id", adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare(`SELECT image_path FROM prizes WHERE id = ?`).get(id);
  if (!row) return res.status(404).json({ error: "not found" });
  db.prepare(`DELETE FROM prizes WHERE id = ?`).run(id);
  try {
    if (row.image_path && fs.existsSync(row.image_path)) {
      fs.unlinkSync(row.image_path);
    }
  } catch {
    /* ignore */
  }
  return res.json({ ok: true });
});

app.get("/api/admin/codes", adminOnly, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const rows = db
    .prepare(
      `SELECT c.code, c.user_sub, c.prize_id, c.created_at, c.redeemed_at, c.redeemed_by,
              p.title AS prize_title
       FROM redeem_codes c
       JOIN prizes p ON p.id = c.prize_id
       ORDER BY c.created_at DESC
       LIMIT ?`,
    )
    .all(limit);
  res.json({ codes: rows });
});

app.post("/api/admin/codes/redeem", adminOnly, (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  if (!code) {
    return res.status(400).json({ error: "code required" });
  }
  const row = db
    .prepare(
      `SELECT c.code, c.user_sub, c.prize_id, c.redeemed_at, p.title AS prize_title, p.subtitle AS prize_subtitle
       FROM redeem_codes c
       JOIN prizes p ON p.id = c.prize_id
       WHERE c.code = ?`,
    )
    .get(code);

  if (!row) {
    return res.status(404).json({ error: "code not found" });
  }
  if (row.redeemed_at != null) {
    return res.status(409).json({
      error: "already_activated",
      redeemed_at: row.redeemed_at,
    });
  }

  const t = nowMs();
  const by = "admin";
  db.prepare(
    `UPDATE redeem_codes SET redeemed_at = ?, redeemed_by = ? WHERE code = ?`,
  ).run(t, by, code);

  return res.json({
    ok: true,
    code: row.code,
    user_sub: row.user_sub,
    prize_title: row.prize_title,
    prize_subtitle: row.prize_subtitle,
  });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, "index.html"));
});

app.get("/admin.html", (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, "admin.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Wheel server http://0.0.0.0:${PORT}`);
  if (!JWT_SECRET) {
    console.warn("Warning: JWT_SECRET is empty — /api/auth will fail until set.");
  }
  if (!ADMIN_PASSWORD) {
    console.warn("Warning: ADMIN_PASSWORD is empty — admin login disabled.");
  }
});
