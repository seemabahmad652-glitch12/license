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
  // Bounded pool + explicit timeouts. Without these, a Postgres that
  // goes slow (or away) during a redeploy leaves requests hanging on
  // `pool.query` with no ceiling, and every hung request holds a
  // connection - which is how one bad minute turns into a pool that
  // never recovers. `statement_timeout` is enforced by Postgres itself,
  // so even a query that somehow blocks server-side gets killed.
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  statement_timeout: 10_000,
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
  // `license_key` already has an index (the UNIQUE constraint builds
  // one), which is what /verify looks up by - these two are for the
  // admin dashboard's own queries, which had no index behind them at
  // all: the status filter / stats grouping, and the unfiltered list's
  // `ORDER BY created_at DESC` (a sequential scan plus a sort on every
  // page load once the table is more than a few hundred rows).
  await pool.query(`CREATE INDEX IF NOT EXISTS licenses_status_idx ON licenses (status);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS licenses_created_at_idx ON licenses (created_at DESC);`);

  // Key expiry (56th pass). Added as a nullable column via ALTER rather
  // than being folded into the CREATE TABLE above, so an existing
  // deployment picks it up on its next boot without losing the keys it
  // already has. NULL means "never expires", which is what every key
  // issued before this existed is - so the feature arrives switched off
  // for all of them rather than silently expiring anyone.
  await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;`);
  await pool.query(`CREATE INDEX IF NOT EXISTS licenses_expires_at_idx ON licenses (expires_at);`);
}

/// Resolves the expiry an admin request is asking for into either a
/// Date, null ("never expires"), or an error string.
///
/// Accepts `expires_in_days` (a number - what the dashboard's duration
/// picker sends) or `expires_at` (an ISO timestamp, for anything
/// scripting this directly). Absent/null/0 days means no expiry.
function resolveExpiry(body) {
  if (!body || typeof body !== "object") return { value: null };

  if (body.expires_at !== undefined && body.expires_at !== null && body.expires_at !== "") {
    const when = new Date(body.expires_at);
    if (Number.isNaN(when.getTime())) return { error: "expires_at isn't a valid date." };
    return { value: when };
  }

  if (body.expires_in_days !== undefined && body.expires_in_days !== null && body.expires_in_days !== "") {
    const days = Number(body.expires_in_days);
    if (!Number.isFinite(days) || days < 0) {
      return { error: "expires_in_days must be a non-negative number." };
    }
    // 0 is an explicit "no expiry" rather than "expires immediately",
    // which would otherwise be an easy way to issue a dead key by
    // accident.
    if (days === 0) return { value: null };
    if (days > 3650) return { error: "expires_in_days is more than 10 years - that's probably a typo." };
    return { value: new Date(Date.now() + days * 24 * 60 * 60 * 1000) };
  }

  return { value: null };
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

/// Railway (like most PaaS) terminates TLS in front of the app and
/// forwards the client IP via X-Forwarded-For, so `req.ip` on its own
/// is just Railway's internal proxy address.
///
/// This used to take the LEFT-most entry, which is a real
/// vulnerability, not a style choice: X-Forwarded-For is a list that
/// each hop *appends* to, so the left-most entry is whatever the
/// caller sent - a header they control completely. Anyone could put
/// `1.2.3.4` (or any string at all) there and that is what landed in
/// `last_seen_ip`, and it would equally have defeated anything keyed
/// off this value, rate limiting included. The RIGHT-most entry is the
/// one Railway's own proxy appended, which is the only hop in that
/// list this process has any reason to believe.
///
/// Also normalised and length-capped: this value is persisted and
/// later rendered in the admin dashboard, so it should only ever be
/// IP-shaped characters, never arbitrary header bytes.
function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  let ip = req.ip;
  if (typeof xff === "string" && xff.length > 0) {
    const hops = xff.split(",");
    ip = hops[hops.length - 1].trim();
  }
  return String(ip || "").replace(/[^0-9a-fA-F.:\[\]]/g, "").slice(0, 45) || null;
}

// ---------- Rate limiting ----------
//
// There was none at all before this, on either endpoint that matters:
// `/admin/*` accepted one ADMIN_SECRET guess per request as fast as
// anyone cared to send them, and `/verify` let anyone walk the license
// keyspace at full line rate. Both are the kind of thing you only get
// to notice once.
//
// Deliberately a small in-process fixed-window counter rather than a
// dependency: this runs as a single Railway instance, the whole state
// is a Map of counters, and adding `express-rate-limit` + a Redis to
// share state across replicas would be a much bigger change than the
// problem warrants. If this service is ever scaled past one replica,
// that is the point to swap this for a shared store - each replica
// enforcing its own window means the effective limit multiplies by the
// replica count.
const rateBuckets = new Map();

function rateLimit({ windowMs, max, keyOf, message }) {
  return (req, res, next) => {
    const key = keyOf(req);
    // No usable key (no IP at all) - fail closed rather than handing
    // out an unlimited lane to anything that manages to hide itself.
    if (!key) return res.status(429).json({ error: message });

    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateBuckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      res.setHeader("Retry-After", String(Math.ceil((bucket.resetAt - now) / 1000)));
      return res.status(429).json({ success: false, error: message, message });
    }
    next();
  };
}

// Sweeps expired buckets so a long-running process doesn't accumulate
// one Map entry per IP that has ever called this, forever. `unref()` so
// this timer can never be the thing keeping the process alive during a
// shutdown.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (now >= bucket.resetAt) rateBuckets.delete(key);
  }
}, 60_000).unref();

// Generous enough that a real client never notices: the desktop app
// calls /verify on launch, on Start, and once every 5 minutes while
// running (see poller.rs's LICENSE_RECHECK_SECS), so even several
// installs behind one household NAT sit far under this - while a
// keyspace walk from one address gets cut off almost immediately.
const verifyLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  keyOf: (req) => `verify:${clientIp(req)}`,
  message: "Too many license checks from this address - wait a minute and try again.",
});

// Much tighter, because the thing being guessed here is a single
// long-lived secret: 10 attempts a minute makes brute force hopeless
// while leaving the dashboard (which fires a handful of calls per page
// load) comfortable.
const adminLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  keyOf: (req) => `admin:${clientIp(req)}`,
  message: "Too many admin requests from this address - wait a minute and try again.",
});

const app = express();

// Express advertises itself in a response header by default; there is
// no reason to tell the internet what this is running on.
app.disable("x-powered-by");

// `express.json()`'s own default limit is 100kb, which is already far
// more than {key, hwid} needs - tightened to 4kb so an oversized body
// is rejected before it is parsed and buffered at all.
app.use(express.json({ limit: "4kb" }));

// The admin dashboard is the only HTML this serves, and it holds the
// admin secret in sessionStorage - so it should not be framable by
// anyone else's page, should not sniff content types, and should not
// leak its URL as a referrer to third parties.
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

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
app.use(
  "/updates",
  express.static(path.join(__dirname, "updates"), {
    // The manifest must never be cached - it is the one file whose
    // whole job is to change when a release ships, and a CDN or
    // webview holding a stale copy is exactly how "I published an
    // update and nobody got it" happens. The installers it points at
    // are the opposite: their URLs carry the version, so once
    // published they never change and can be cached hard.
    setHeaders: (res, filePath) => {
      if (filePath.endsWith("latest.json")) {
        res.setHeader("Cache-Control", "no-store");
      } else {
        res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      }
    },
  })
);

// Express 4 (unlike 5) does NOT automatically catch a rejected promise
// from an async route handler - an unhandled rejection in one of the
// `async (req, res) => {...}` handlers below would otherwise just hang
// the request forever instead of reaching the error-handling middleware
// at the bottom of this file. Every async handler is wrapped in this so
// a thrown/rejected error always becomes a real `next(err)` call.
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Reports "ok" only if Postgres actually answers - a healthcheck that
// just proves the Node process is up would report healthy during
// exactly the outage worth catching (database unreachable, every
// /verify failing), which is also what makes it useless as Railway's
// configured healthcheck path.
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "ok" });
  } catch (e) {
    console.error("Healthcheck failed - database unreachable:", e);
    res.status(503).json({ status: "degraded", database: "unreachable" });
  }
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
// Longest value either field can legitimately be: a license key is 23
// characters (four groups of five plus three hyphens) and a hwid is a
// 36-character UUID (see license.rs's `device_id`). Capped generously
// rather than exactly, but capped - without this, a multi-kilobyte
// "key" was handed straight to Postgres as a query parameter on an
// unauthenticated-by-anything-but-a-shared-secret endpoint.
const MAX_FIELD_LEN = 128;

// The rate limiter runs BEFORE requireClientSecret on purpose: an
// attacker without the client secret should be throttled too, and
// putting the cheap counter first also means a flood never reaches the
// sha256 work requireClientSecret does per request.
app.post("/verify", verifyLimiter, requireClientSecret, ah(async (req, res) => {
  const key = typeof req.body.key === "string" ? req.body.key.trim() : "";
  const hwid = typeof req.body.hwid === "string" ? req.body.hwid.trim() : "";
  if (!key || !hwid) {
    return res.status(400).json({ success: false, message: "Missing key or hwid." });
  }
  if (key.length > MAX_FIELD_LEN || hwid.length > MAX_FIELD_LEN) {
    return res.status(400).json({ success: false, message: "Malformed key or hwid." });
  }

  // One round trip instead of the SELECT-then-UPDATE this used to do.
  // /verify is the hottest endpoint this service has (every launch,
  // every Start, and every 5 minutes for every running install), and
  // the old shape paid two sequential network hops to Postgres for
  // every single call - with a race in the gap between them, where two
  // launches of the same key on two different devices could both read
  // `hwid IS NULL` and both then bind, handing out two activations for
  // a one-device key.
  //
  // This does the whole decision in a single statement:
  //   - `found`  reads the license's pre-update state, so the response
  //              can still say *why* a check failed.
  //   - `upd`    applies the update only when the license is active AND
  //              the device either matches or isn't bound yet. The
  //              `COALESCE(l.hwid, $2)` is the first-device bind.
  //
  // Note that `upd`'s guard tests `l.status`/`l.hwid` - the live row -
  // and NOT the values `found` read, even though `found` has them
  // sitting right there. That is the whole race fix and it is subtle:
  // under READ COMMITTED, when two concurrent binds collide, the
  // second UPDATE blocks on the first's row lock and then re-evaluates
  // its WHERE clause against the *updated* tuple. That re-check only
  // re-reads columns of the target row; a value already materialised
  // in a CTE is from the original snapshot and would still say
  // "unbound", so gating on `(SELECT hwid FROM found)` would let the
  // second device bind straight over the first. `found` is therefore
  // used for one thing only: knowing which message to return.
  // `updated = 0` with a row present therefore means "the key exists
  // and is active, but this is the wrong device".
  const { rows } = await pool.query(
    `WITH found AS (
       SELECT id, hwid, status, expires_at FROM licenses WHERE license_key = $1
     ), upd AS (
       UPDATE licenses l
          SET last_seen_at = now(),
              last_seen_ip = $3,
              hwid = COALESCE(l.hwid, $2)
        WHERE l.id = (SELECT id FROM found)
          AND l.status = 'active'
          AND (l.expires_at IS NULL OR l.expires_at > now())
          AND (l.hwid IS NULL OR l.hwid = $2)
       RETURNING l.id
     )
     SELECT f.status,
            (f.hwid IS NULL) AS was_unbound,
            (f.expires_at IS NOT NULL AND f.expires_at <= now()) AS is_expired,
            f.expires_at,
            (SELECT count(*) FROM upd)::int AS updated
       FROM found f`,
    [key, hwid, clientIp(req)]
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
  // Checked before the device branch below, because an expired key that
  // also happens to be on the wrong device should say it expired - that
  // is the thing the person has to act on, and "already activated on
  // another device" would send them to support for the wrong reason.
  //
  // Note the expiry is enforced by the UPDATE's own guard above, not by
  // this branch: an expired key never reaches the bind, so it can
  // neither claim a new device nor refresh last_seen_at. This branch
  // only decides what to *tell* the client.
  if (license.is_expired) {
    return res.json({ success: false, message: "This license key has expired." });
  }
  if (license.updated === 0) {
    // Active key, but bound to a different device - the "device
    // locked" rejection. Note this is decided here, server-side,
    // against this server's own database: nothing the client sends
    // about its own state can talk its way past it.
    return res.json({
      success: false,
      message: "This license key is already activated on another device. Contact support to reset it.",
    });
  }
  return res.json({ success: true, message: "Device unlocked." });
}));

// ---------- Admin routes - never called by the desktop app itself ----------
// Manage these with curl, Postman, a tiny internal tool, or a storefront's
// own backend after a sale goes through - not meant to be exposed to
// customers directly. All require X-Admin-Secret.

// `note` was removed from this API in the 56th pass - it was never
// used in practice and the dashboard no longer shows it. The database
// column is deliberately left in place rather than dropped: dropping
// it would irreversibly destroy any notes already stored. To actually
// remove it, run `ALTER TABLE licenses DROP COLUMN note;` by hand once
// you are sure nothing in there matters.
app.post("/admin/licenses", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const expiry = resolveExpiry(req.body);
  if (expiry.error) return res.status(400).json({ error: expiry.error });
  // Collisions are astronomically unlikely (32^20 keyspace) but checked
  // and retried anyway rather than trusting that away - a crash here
  // would be a strange way to fail to sell a key.
  for (let attempt = 0; attempt < 5; attempt++) {
    const key = generateLicenseKey();
    try {
      const { rows } = await pool.query(
        `INSERT INTO licenses (license_key, expires_at) VALUES ($1, $2)
         RETURNING id, license_key, status, created_at, expires_at`,
        [key, expiry.value]
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
app.get("/admin/licenses", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const status = LICENSE_STATUSES.includes(req.query.status) ? req.query.status : null;
  const q = typeof req.query.q === "string" && req.query.q.trim() ? req.query.q.trim() : null;

  const conditions = [];
  const params = [];
  // "expired" is offered as a pseudo-status in the dashboard's filter
  // because that is how a person thinks about it, but it is not a value
  // of the `status` column - expiry is orthogonal to active/revoked/
  // banned (a key can be active AND expired). So it filters on the
  // timestamp instead.
  if (req.query.status === "expired") {
    conditions.push(`expires_at IS NOT NULL AND expires_at <= now()`);
  } else if (status) {
    params.push(status);
    conditions.push(`status = $${params.length}`);
  }
  if (q) {
    // Key only now that `note` is gone from this API.
    params.push(`%${q}%`);
    conditions.push(`license_key ILIKE $${params.length}`);
  }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  params.push(limit);
  const limitPlaceholder = `$${params.length}`;
  params.push(offset);
  const offsetPlaceholder = `$${params.length}`;

  const { rows } = await pool.query(
    `SELECT id, license_key, hwid, status, created_at, expires_at, last_seen_at, last_seen_ip
     FROM licenses ${where} ORDER BY created_at DESC LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder}`,
    params
  );
  res.json(rows);
}));

// Summary counts for the dashboard's stat cards - one grouped query
// rather than making the dashboard fetch every page just to count
// them itself.
app.get("/admin/stats", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT status,
            COUNT(*)::int AS count,
            COUNT(hwid)::int AS bound,
            (COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at <= now()))::int AS expired
       FROM licenses
      GROUP BY status`
  );
  const byStatus = { active: 0, revoked: 0, banned: 0 };
  let total = 0;
  let bound = 0;
  let expired = 0;
  for (const row of rows) {
    byStatus[row.status] = row.count;
    total += row.count;
    bound += row.bound;
    expired += row.expired;
  }
  // `expired` deliberately overlaps the byStatus counts rather than
  // being a fourth bucket - a key can be active and expired at once,
  // and the dashboard needs to show both facts.
  res.json({ total, bound, unbound: total - bound, expired, byStatus });
}));

app.post("/admin/licenses/:key/revoke", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'revoked' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

app.post("/admin/licenses/:key/unrevoke", adminLimiter, requireAdminSecret, ah(async (req, res) => {
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
app.post("/admin/licenses/:key/ban", adminLimiter, requireAdminSecret, ah(async (req, res) => {
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
app.post("/admin/licenses/:key/unban", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const { rowCount } = await pool.query(
    "UPDATE licenses SET status = 'active' WHERE license_key = $1",
    [req.params.key]
  );
  if (rowCount === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

// Sets or clears one key's expiry after the fact - renewing a key
// someone re-bought, extending a trial, or taking the expiry off
// entirely. Body is the same shape `POST /admin/licenses` accepts
// (`expires_in_days` or `expires_at`); send neither, or 0 days, to
// clear it back to "never expires".
app.post("/admin/licenses/:key/expiry", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const expiry = resolveExpiry(req.body);
  if (expiry.error) return res.status(400).json({ error: expiry.error });

  const { rows } = await pool.query(
    "UPDATE licenses SET expires_at = $1 WHERE license_key = $2 RETURNING license_key, expires_at",
    [expiry.value, req.params.key]
  );
  if (rows.length === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true, expires_at: rows[0].expires_at });
}));

app.post("/admin/licenses/:key/reset-hwid", adminLimiter, requireAdminSecret, ah(async (req, res) => {
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

app.delete("/admin/licenses/:key", adminLimiter, requireAdminSecret, ah(async (req, res) => {
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
    const server = app.listen(PORT, () => {
      console.log(`afkstrike license server listening on :${PORT}`);
    });

    // Railway sends SIGTERM and then kills the container shortly
    // after, on every redeploy. Without handling it, in-flight
    // requests are severed mid-response and Postgres connections are
    // dropped rather than closed - so each deploy showed up as a
    // handful of client-side errors (a desktop app's /verify failing
    // closed, which is a locked-out user) for no reason. Finish what
    // is in flight, close the pool, then exit.
    const shutdown = (signal) => {
      console.log(`${signal} received - shutting down.`);
      server.close(async () => {
        try {
          await pool.end();
        } catch (e) {
          console.error("Error closing the database pool:", e);
        }
        process.exit(0);
      });
      // Backstop: if something refuses to let go, don't hang until the
      // platform SIGKILLs us anyway.
      setTimeout(() => process.exit(0), 10_000).unref();
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  })
  .catch((e) => {
    console.error("Failed to run startup migration:", e);
    process.exit(1);
  });
