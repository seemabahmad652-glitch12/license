// afkstrike's own license server (53rd/54th-pass replacement for the
// KeyAuth-backed gate) - a small Express app meant to run on Railway,
// backed by Railway's Postgres plugin. See README.md in this folder for
// deploy steps and how the afkstrike desktop app talks to this.
//
// Design, in one paragraph: the desktop app never talks to a third
// party for licensing any more - it only ever calls THIS server's
// /verify, which it reaches at a fixed URL baked into the client (same
// as any API-backed app). Every request to /verify must carry the
// shared client secret (CLIENT_SHARED_SECRET below) as a header, which
// is weak-but-real defense in depth against casual scripting against
// this endpoint - the actual security boundary is "does this key exist,
// is it active, and does its bound hwid (if any) match" against this
// server's own Postgres database, which never leaves this process.
// Admin routes (create/list/revoke/ban/reset a license) are a second,
// separate secret (ADMIN_SECRET) - never shipped in the desktop app at
// all, only used by you (or a storefront's backend, if you build one
// later) to issue keys after a sale. `public/index.html` is a small,
// self-contained admin dashboard that drives those same routes from a
// browser instead of curl - see its own header comment, and the
// "Admin dashboard" section in README.md.

"use strict";

const crypto = require("crypto");
const path = require("path");
const express = require("express");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const CLIENT_SHARED_SECRET = process.env.CLIENT_SHARED_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// Fail loudly at boot rather than quietly running with an unprotected
// admin API or an unprotected /verify endpoint - a missing env var here
// is a deploy-config mistake, not something to silently paper over with
// a default.
for (const [name, value] of [
  ["DATABASE_URL", DATABASE_URL],
  ["CLIENT_SHARED_SECRET", CLIENT_SHARED_SECRET],
  ["ADMIN_SECRET", ADMIN_SECRET],
]) {
  if (!value) {
    console.error(`Missing required environment variable: ${name}. See README.md - set this in Railway's Variables tab.`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Railway's managed Postgres is reachable over TLS but with a
  // certificate chain `pg`'s default strict verification doesn't
  // always resolve cleanly from inside their own network - this is
  // Railway's own documented pattern for their Postgres plugin, not a
  // general "disable TLS verification" shortcut.
  ssl: { rejectUnauthorized: false },
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      license_key TEXT UNIQUE NOT NULL,
      hwid TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen_at TIMESTAMPTZ,
      last_seen_ip TEXT
    );
  `);
}

// Constant-time-ish string comparison via fixed-length digests, so two
// secrets of different lengths don't short-circuit the comparison after
// the first differing byte (the thing timingSafeEqual itself can't do
// directly, since it requires equal-length buffers).
function safeEqual(a, b) {
  const da = crypto.createHash("sha256").update(String(a)).digest();
  const db = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(da, db);
}

// Readable license keys: four groups of five, uppercase letters and
// digits only, with visually-confusable characters (0/O, 1/I/L) left
// out - the kind of string a person can type correctly from a screen
// or read out loud, not a raw UUID.
const KEY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function generateLicenseKey() {
  const groups = [];
  for (let g = 0; g < 4; g++) {
    let group = "";
    const bytes = crypto.randomBytes(5);
    for (let i = 0; i < 5; i++) {
      group += KEY_ALPHABET[bytes[i] % KEY_ALPHABET.length];
    }
    groups.push(group);
  }
  return groups.join("-");
}

function clientIp(req) {
  // Railway (like most PaaS) terminates TLS in front of the app and
  // forwards the real client IP via X-Forwarded-For - req.ip alone
  // would just be Railway's internal proxy address otherwise. Takes
  // the first (left-most, client-supplied-closest-to-origin) entry.
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return req.ip;
}

const app = express();
app.use(express.json());

// Serves public/index.html (the admin dashboard) and nothing else -
// this directory has exactly one file in it. express.static calls
// next() for any request that doesn't match a real file under here,
// so this sits harmlessly in front of /health, /verify, and /admin/*
// below rather than intercepting them. The dashboard itself carries no
// secret - it's static HTML/CSS/JS, and the admin secret is typed in
// by whoever opens it and sent only as a header on the API calls it
// makes from there, same as curl would.
app.use(express.static(path.join(__dirname, "public")));

// Auto-updates: the desktop app's Tauri updater plugin GETs
// /updates/latest.json on every launch and, for whichever platform
// key matches, downloads the installer URL inside it. Publishing a
// new release is just dropping an updated latest.json (and the
// signed installer(s) it points to) into this folder - no server
// code changes, no restart needed, same deploy as the licensing API.
// See license-server/updates/README.md for the manifest format and
// how to sign a release; see the main README's "Auto-updates" section
// for how the desktop side consumes it.
app.use("/updates", express.static(path.join(__dirname, "updates")));

// Express 4 (unlike 5) does NOT automatically catch a rejected promise
// from an async route handler - an unhandled rejection in one of the
// `async (req, res) => {...}` handlers below would otherwise just hang
// the request forever instead of reaching the error-handling middleware
// at the bottom of this file. Every async handler is wrapped in this so
// a thrown/rejected error always becomes a real `next(err)` call.
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

function requireClientSecret(req, res, next) {
  const provided = req.headers["x-client-secret"];
  if (typeof provided !== "string" || !safeEqual(provided, CLIENT_SHARED_SECRET)) {
    return res.status(401).json({ success: false, message: "Unauthorized client." });
  }
  next();
}

function requireAdminSecret(req, res, next) {
  const provided = req.headers["x-admin-secret"];
  if (typeof provided !== "string" || !safeEqual(provided, ADMIN_SECRET)) {
    return res.status(401).json({ error: "Unauthorized." });
  }
  next();
}

// ---------- /verify - what the afkstrike desktop app actually calls ----------
//
// Body: { key: string, hwid: string }
// A license is bound to the first hwid that successfully verifies with
// it ("device locked", as asked for) - every call after that must come
// from the same hwid or it's rejected, even though the key itself is
// still valid. This is the server-side half of per-device locking; the
// client can't just claim a different hwid to get a second activation,
// because THIS check is what decides, not anything the client sends
// about its own state.
app.post("/verify", requireClientSecret, ah(async (req, res) => {
  const key = typeof req.body.key === "string" ? req.body.key.trim() : "";
  const hwid = typeof req.body.hwid === "string" ? req.body.hwid.trim() : "";
  if (!key || !hwid) {
    return res.status(400).json({ success: false, message: "Missing key or hwid." });
  }

  const { rows } = await pool.query(
    "SELECT id, hwid, status FROM licenses WHERE license_key = $1",
    [key]
  );
  const license = rows[0];
  if (!license) {
    return res.json({ success: false, message: "Invalid license key." });
  }
  if (license.status === "revoked") {
    return res.json({ success: false, message: "This license key has been revoked." });
  }
  if (license.status === "banned") {
    return res.json({ success: false, message: "This license key has been banned." });
  }

  if (!license.hwid) {
    // First-ever successful check for this key - bind it to this
    // device from now on.
    await pool.query(
      "UPDATE licenses SET hwid = $1, last_seen_at = now(), last_seen_ip = $2 WHERE id = $3",
      [hwid, clientIp(req), license.id]
    );
    return res.json({ success: true, message: "Device unlocked." });
  }

  if (!safeEqual(license.hwid, hwid)) {
    return res.json({
      success: false,
      message: "This license key is already activated on another device. Contact support to reset it.",
    });
  }

  await pool.query(
    "UPDATE licenses SET last_seen_at = now(), last_seen_ip = $1 WHERE id = $2",
    [clientIp(req), license.id]
  );
  return res.json({ success: true, message: "Device unlocked." });
}));

// ---------- Admin routes - never called by the desktop app itself ----------
// Manage these with curl, Postman, a tiny internal tool, or a storefront's
// own backend after a sale goes through - not meant to be exposed to
// customers directly. All require X-Admin-Secret.

app.post("/admin/licenses", requireAdminSecret, ah(async (req, res) => {
  const note = typeof req.body?.note === "string" ? req.body.note.slice(0, 500) : null;
  // Collisions are astronomically unlikely (32^20 keyspace) but checked
  // and retried anyway rather than trusting that away - a crash here
  // would be a strange way to fail to sell a key.
  for (let attempt = 0; attempt < 5; attempt++) {
    const key = generateLicenseKey();
    try {
      const { rows } = await pool.query(
        "INSERT INTO licenses (license_key, note) VALUES ($1, $2) RETURNING id, license_key, status, note, created_at",
        [key, note]
      );
      return res.status(201).json(rows[0]);
    } catch (e) {
      if (e.code === "23505") continue; // unique_violation on license_key - retry with a new one
      console.error("Failed to create license:", e);
      return res.status(500).json({ error: "Could not create license." });
    }
  }
  return res.status(500).json({ error: "Could not generate a unique license key - try again." });
}));

// Optional ?status=active|revoked|banned and/or ?q=<substring> (matched
// against the key and the note, case-insensitive) on top of the
// existing ?limit/?offset pagination - what the dashboard's search box
// and status filter dropdown both call through. Neither param is
// required, so every existing curl/script call to this route (bare
// ?limit&offset) keeps working unchanged.
const LICENSE_STATUSES = ["active", "revoked", "banned"];
app.get("/admin/licenses", requireAdminSecret, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const status = LICENSE_STATUSES.includes(req.query.status) ? req.query.status : null;
  const q = typeof req.query.q === "string" && req.query.q.trim() ? req.query.q.trim() : null;

  const conditions = [];
  const params = [];
  if (status) {
    params.push(status);
    conditions.push(`status = $${params.length}`);
  }
  if (q) {
    params.push(`%${q}%`);
    conditions.push(`(license_key ILIKE $${params.length} OR note ILIKE $${params.length})`);
  }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  params.push(limit);
  const limitPlaceholder = `$${params.length}`;
  params.push(offset);
  const offsetPlaceholder = `$${params.length}`;

  const { rows } = await pool.query(
    `SELECT id, license_key, hwid, status, note, created_at, last_seen_at, last_seen_ip
     FROM licenses ${where} ORDER BY created_at DESC LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder}`,
    params
  );
  res.json(rows);
}));

// Summary counts for the dashboard's stat cards - one grouped query
// rather than making the dashboard fetch every page just to count
// them itself.
app.get("/admin/stats", requireAdminSecret, ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT status, COUNT(*)::int AS count, COUNT(hwid)::int AS bound FROM licenses GROUP BY status`
  );
  const byStatus = { active: 0, revoked: 0, banned: 0 };
  let total = 0;
  let bound = 0;
  for (const row of rows) {
    byStatus[row.status] = row.count;
    total += row.count;
    bound += row.bound;
  }
  res.json({ total, bound, unbound: total - bound, byStatus });
}));

app.post("/admin/licenses/:key/revoke", requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'revoked' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

app.post("/admin/licenses/:key/unrevoke", requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'active' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

// Distinct from revoke: `/verify` already treats 'banned' as its own
// rejection reason with its own message ("...has been banned."), so
// this is for a harder/more deliberate block (abuse, chargebacks,
// sharing a key publicly) than an ordinary revoke (refund, mistake).
// Nothing server-side actually treats the two differently beyond that
// message - split them if that ever needs to change (e.g. banned keys
// also blocking that hwid account-wide).
app.post("/admin/licenses/:key/ban", requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'banned' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

// Same end state as /unrevoke (back to 'active') - kept as its own
// route rather than making the dashboard call /unrevoke for a banned
// key, so the two button labels ("Unrevoke" vs "Unban") each have a
// matching, equally-named endpoint instead of one hiding behind the
// other's name.
app.post("/admin/licenses/:key/unban", requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'active' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

app.post("/admin/licenses/:key/reset-hwid", requireAdminSecret, ah(async (req, res) => {
  // Lets a customer move a key to a new/replacement device - without
  // this there would be no legitimate way back in after a reinstall or
  // a new PC, short of you editing the database by hand.
  const { rowCount } = await pool.query(
    "UPDATE licenses SET hwid = NULL WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

app.delete("/admin/licenses/:key", requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "DELETE FROM licenses WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

// Last-resort handler: anything that throws inside a route above
// (a Postgres hiccup, etc.) lands here instead of taking the whole
// process down or leaking a stack trace to the caller.
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal error." });
});

migrate()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`afkstrike license server listening on :${PORT}`);
    });
  })
  .catch((e) => {
    console.error("Failed to run startup migration:", e);
    process.exit(1);
  });
