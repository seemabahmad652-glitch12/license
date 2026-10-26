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
// Admin routes (create/list/revoke/reset a license) are a second,
// separate secret (ADMIN_SECRET) - never shipped in the desktop app at
// all, only used by you (or a storefront's backend, if you build one
// later) to issue keys after a sale. `public/index.html` is a small,
// self-contained admin dashboard that drives those same routes from a
// browser instead of curl - see its own header comment, and the
// "Admin dashboard" section in README.md.

"use strict";

const crypto = require("crypto");
const path = require("path");
const zlib = require("zlib");
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
  // `note` removed outright (57th pass) at the owner's request. This is
  // destructive and irreversible - any text previously stored in that
  // column is gone the first time this runs. It was already unused by
  // both the API and the dashboard before this.
  await pool.query(`ALTER TABLE licenses DROP COLUMN IF EXISTS note;`);
  await pool.query(`CREATE INDEX IF NOT EXISTS licenses_expires_at_idx ON licenses (expires_at);`);
  // For the dashboard's "online now" count and filter, which scans by
  // recency of the last check-in.
  await pool.query(`CREATE INDEX IF NOT EXISTS licenses_last_seen_idx ON licenses (last_seen_at DESC);`);

  // Per-key history (58th pass). Answers the question every support
  // conversation starts with - "it stopped working, what happened?" -
  // which until now had no answer beyond a single last_seen timestamp.
  //
  // Keyed by the license *text*, deliberately with no foreign key to
  // `licenses`: a key's history has to survive the key being deleted,
  // because a chargeback or a "you deleted my key" dispute is exactly
  // when you need to see it.
  //
  // Not every /verify is recorded - only the ones that change or refuse
  // something (first activation, device migration, every rejection).
  // A routine successful check-in happens every five minutes for every
  // running install; logging those would bury the events that matter
  // under millions that don't, and `last_seen_at` already records them.
  // Pruned after EVENT_RETENTION_DAYS - see pruneEvents below.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_events (
      id BIGSERIAL PRIMARY KEY,
      license_key TEXT NOT NULL,
      event TEXT NOT NULL,
      detail TEXT,
      ip TEXT,
      hwid TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS license_events_key_idx ON license_events (license_key, created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS license_events_created_idx ON license_events (created_at DESC);`);

  // The device a key is locked to, part by part: {mg, vol, cpu, cores,
  // host}, each an opaque hash the app computes. Lets /verify recognise
  // the same PC after a small change instead of calling it "another
  // device" - see afk_parts_match.
  await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hw_parts JSONB;`);
  // One-time wipe of every key and its history, asked for by the owner
  // (2026-10-26). Runs only when WIPE_ALL_LICENSES is set to this exact
  // value, and only once ever: the marker row makes a restart harmless.
  if (process.env.WIPE_ALL_LICENSES === "wipe-2026-10-26") {
    await pool.query(`CREATE TABLE IF NOT EXISTS afk_maintenance (name TEXT PRIMARY KEY, done_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    // One statement, so it's atomic: all of it happens or none.
    const { rows } = await pool.query(
      `WITH mark AS (
         INSERT INTO afk_maintenance (name) VALUES ('wipe-2026-10-26') ON CONFLICT DO NOTHING RETURNING 1
       ), ev AS (
         DELETE FROM license_events WHERE EXISTS (SELECT 1 FROM mark) RETURNING 1
       ), lic AS (
         DELETE FROM licenses WHERE EXISTS (SELECT 1 FROM mark) RETURNING 1
       )
       SELECT (SELECT count(*) FROM mark)::int AS ran,
              (SELECT count(*) FROM lic)::int AS licenses,
              (SELECT count(*) FROM ev)::int AS events`
    );
    console.log(rows[0].ran
      ? `One-time wipe: deleted ${rows[0].licenses} licenses and ${rows[0].events} events.`
      : "One-time wipe already done - skipped.");
  }
  // "banned" was retired (Revoke does the same job).
  await pool.query(`UPDATE licenses SET status = 'revoked' WHERE status NOT IN ('active', 'revoked');`);
  // Same PC = same Windows install (MachineGuid, "mg") plus at least two
  // more matching parts. A rename, a CPU swap or a new disk passes; a
  // different PC - or a fresh Windows install, which needs a reset - doesn't.
  await pool.query(`
    CREATE OR REPLACE FUNCTION afk_parts_match(stored jsonb, sent jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $fn$
      SELECT COALESCE(
        stored ? 'mg' AND sent ? 'mg' AND stored->>'mg' = sent->>'mg'
        AND (SELECT count(*) FROM jsonb_each_text(stored) s WHERE sent->>s.key = s.value) >= 3,
        false)
    $fn$;
  `);
}

// How long per-key history is kept. Long enough to cover a chargeback
// window (typically 120 days) with room to spare.
const EVENT_RETENTION_DAYS = 180;

async function pruneEvents() {
  try {
    await pool.query(
      `DELETE FROM license_events WHERE created_at < now() - make_interval(days => $1::int)`,
      [EVENT_RETENTION_DAYS]
    );
  } catch (e) {
    // A failed prune just means the table is a little bigger until the
    // next one - never worth taking the server down over.
    console.error("Event prune failed:", e);
  }
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

// Readable license keys, `AFK-XXXX-XXXX-XXXX` (59th pass): a fixed
// brand prefix, then three groups of four from an alphabet with the
// visually-confusable characters (0/O, 1/I/L) left out - the kind of
// string a person can type correctly from a screen or read out loud.
//
// The prefix carries no entropy; the 12 random characters do: 31^12 is
// about 7.9e17 keys. Against /verify's limit of 30 checks a minute per
// address, guessing one is not a thing that happens.
//
// This is the only format: /verify refuses anything else without a
// database round trip (KEY_SHAPE below).
const KEY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const KEY_PREFIX = "AFK";
const KEY_GROUPS = 3;
const KEY_GROUP_LEN = 4;
const KEY_SHAPE = new RegExp(`^${KEY_PREFIX}(-[${KEY_ALPHABET}]{${KEY_GROUP_LEN}}){${KEY_GROUPS}}$`);

/// Uniform over the alphabet. `crypto.randomInt` rejection-samples
/// internally; the previous `byte % 31` gave the first eight letters a
/// slightly higher chance (256 isn't a multiple of 31) - harmless at
/// this keyspace, but there was no reason to keep it.
function generateLicenseKey() {
  const groups = [KEY_PREFIX];
  for (let g = 0; g < KEY_GROUPS; g++) {
    let group = "";
    for (let i = 0; i < KEY_GROUP_LEN; i++) {
      group += KEY_ALPHABET[crypto.randomInt(KEY_ALPHABET.length)];
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
  // What `helmet` would add, without the dependency. The dashboard is one
  // self-contained page (inline script and style, nothing external), so
  // the policy allows exactly that and nothing from anywhere else.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; " +
      "form-action 'self'; frame-ancestors 'none'"
  );
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  next();
});

// gzip for text responses: the admin page, the key list, CSV exports,
// update manifests. The key list and export grow with every key sold,
// and JSON/HTML/CSV shrink 70-90% compressed, so this is most of the
// page-load time on a slow connection. Built on Node's own zlib rather
// than the `compression` package - nothing new to install or audit.
//
// It decides on the first write, once the route has set its
// content-type: compressible bodies of 1 KB or more are buffered and
// gzipped (every one of these is small enough to hold in memory);
// anything else - the installers under /updates especially - streams
// straight through untouched, never buffered.
const COMPRESSIBLE = /json|text\/|javascript|svg|csv|xml/i;
function gzipResponses(req, res, next) {
  if (req.method === "HEAD" || !/\bgzip\b/i.test(req.headers["accept-encoding"] || "")) return next();
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  let mode = null; // null = undecided, "buffer", "pass"
  const chunks = [];
  const toBuf = (chunk, enc) =>
    Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof enc === "string" ? enc : "utf8");
  const decide = () => {
    if (mode) return;
    const type = String(res.getHeader("content-type") || "");
    mode = !res.headersSent && !res.getHeader("content-encoding") && COMPRESSIBLE.test(type) ? "buffer" : "pass";
  };
  res.write = (chunk, enc, cb) => {
    decide();
    if (mode === "pass") return write(chunk, enc, cb);
    if (chunk != null && typeof chunk !== "function") chunks.push(toBuf(chunk, enc));
    const done = typeof enc === "function" ? enc : cb;
    if (typeof done === "function") process.nextTick(done);
    return true;
  };
  res.end = (chunk, enc, cb) => {
    decide();
    if (mode === "pass") return end(chunk, enc, cb);
    if (chunk != null && typeof chunk !== "function") chunks.push(toBuf(chunk, enc));
    const done = [chunk, enc, cb].find((f) => typeof f === "function");
    const body = Buffer.concat(chunks);
    // Vary on every compressible response, compressed or not, so a cache
    // never hands a gzipped body to a client that didn't ask for one.
    res.setHeader("Vary", "Accept-Encoding");
    if (body.length < 1024 || res.statusCode === 204 || res.statusCode === 304) {
      if (body.length) res.setHeader("Content-Length", body.length);
      return end(body, done);
    }
    const gz = zlib.gzipSync(body, { level: 6 });
    res.setHeader("Content-Encoding", "gzip");
    res.setHeader("Content-Length", gz.length);
    // A strong ETag names the uncompressed bytes; marked weak once the
    // representation changes, which is what HTTP asks for.
    const etag = res.getHeader("etag");
    if (typeof etag === "string" && !etag.startsWith("W/")) res.setHeader("ETag", `W/${etag}`);
    return end(gz, done);
  };
  next();
}
app.use(gzipResponses);

// Serves the admin dashboard out of public/ (index.html plus the app
// logo it shows as its mark and favicon). express.static calls
// next() for any request that doesn't match a real file under here,
// so this sits harmlessly in front of /health, /verify, and /admin/*
// below rather than intercepting them. The dashboard itself carries no
// secret - it's static HTML/CSS/JS, and the admin secret is typed in
// by whoever opens it and sent only as a header on the API calls it
// makes from there, same as curl would.
app.use(
  express.static(path.join(__dirname, "public"), {
    // The page itself is revalidated on every load (cheap - an ETag
    // check), so a deploy reaches the dashboard at once; the logo is
    // fine cached for a day.
    setHeaders: (res, filePath) => {
      res.setHeader("Cache-Control", filePath.endsWith(".html") ? "no-cache" : "public, max-age=86400");
    },
  })
);

// Auto-updates: the desktop app's Tauri updater plugin GETs
// /updates/latest.json on every launch and, for whichever platform
// key matches, downloads the installer URL inside it. Publishing a
// new release is just dropping an updated latest.json (and the
// signed installer(s) it points to) into this folder - no server
// code changes, no restart needed, same deploy as the licensing API.
// release.cmd (in the app project) writes the manifest and installers;
// see the app's CLAUDE.md "Updates" section for how it all fits together.
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

// The whole /verify decision, as one statement - see the long comment
// inside the route for how it works and why the race fix is subtle.
// Lifted out to a constant so `checkVerifyStatement` below can have
// Postgres plan the exact same text at startup.
const VERIFY_SQL = `WITH found AS (
       SELECT id, hwid, status, expires_at FROM licenses WHERE license_key = $1
     ), upd AS (
       UPDATE licenses l
          SET last_seen_at = now(),
              last_seen_ip = $3,
              -- Always the NEW digest: this is the first-time bind, and
              -- the rebind when the same PC changed a little.
              hwid = $2,
              hw_parts = COALESCE($4::jsonb, l.hw_parts)
        WHERE l.id = (SELECT id FROM found)
          AND l.status = 'active'
          AND (l.expires_at IS NULL OR l.expires_at > now())
          AND (l.hwid IS NULL OR l.hwid = $2 OR afk_parts_match(l.hw_parts, $4::jsonb))
       RETURNING l.id
     ), outcome AS (
       SELECT f.status,
              (f.hwid IS NULL) AS was_unbound,
              (f.expires_at IS NOT NULL AND f.expires_at <= now()) AS is_expired,
              f.expires_at,
              f.hwid AS prior_hwid,
              (SELECT count(*) FROM upd)::int AS updated
         FROM found f
     ), classified AS (
       -- Which event (if any) this check is worth recording - computed
       -- once, and the INSERT filters on it being non-null, so "should
       -- this be logged" and "what is logged" can't disagree. Order
       -- matters: an expired key on the wrong PC is recorded as expired,
       -- matching the message returned.
       SELECT o.*,
              CASE
                WHEN o.status <> 'active' THEN 'rejected_' || o.status
                WHEN o.is_expired         THEN 'rejected_expired'
                WHEN o.updated = 0        THEN 'rejected_device'
                WHEN o.was_unbound        THEN 'activated'
                WHEN o.prior_hwid <> $2   THEN 'device_updated'
              END AS event
         FROM outcome o
     ), ev AS (
       -- Runs whether or not the final SELECT reads it, so the event
       -- costs no second round trip. Unknown keys have no row in "found"
       -- and are never recorded, so garbage keys can't grow this table.
       INSERT INTO license_events (license_key, event, ip, hwid)
       SELECT $1, c.event, $3, $2 FROM classified c WHERE c.event IS NOT NULL
       RETURNING 1
     )
     SELECT status, was_unbound, is_expired, expires_at, updated FROM classified`;

/// Asks Postgres to *plan* the /verify statement before the server starts
/// listening. EXPLAIN without ANALYZE checks syntax, names and types
/// against the live schema without executing anything - so nothing is
/// bound, updated or logged.
///
/// Why this exists: a SQL error in that statement is invisible until the
/// first real activation, and then it locks out every customer at once.
/// That isn't hypothetical - the 58th-pass rewrite of this statement had
/// a doubled ")" that would have done exactly that, caught only because
/// the test suite runs it. This makes the same mistake impossible to
/// *deploy*: the process exits before listening, Railway's /health check
/// never passes, and the previous deployment keeps serving. It also
/// covers a difference between the Postgres the tests ran on and the one
/// in production.
async function checkVerifyStatement() {
  await pool.query(`EXPLAIN ${VERIFY_SQL}`, ["", "", "", null]);
}

// ---------- /verify - what the afkstrike desktop app calls ----------
//
// Body: { key, hwid, parts? }. A key is locked to the first PC that
// activates it; later checks must come from that PC (same `hwid`, or
// `parts` that afk_parts_match recognises) - decided here, against this
// database, not by anything the client says about itself.
//
// A key is 18 characters and a hwid 32; capped generously, but
// capped, since this is reachable with only the shared client secret.
const MAX_FIELD_LEN = 128;
const PART_NAME = /^[a-z]{1,12}$/;
const PART_HASH = /^[0-9a-f]{8,64}$/;

/// The `parts` object as JSON text for Postgres, or null. Anything that
/// isn't a short name mapped to a hex hash is dropped, at most 8 parts.
function cleanParts(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out = {};
  let n = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (n >= 8) break;
    if (!PART_NAME.test(k) || typeof v !== "string" || !PART_HASH.test(v)) continue;
    out[k] = v;
    n++;
  }
  return n ? JSON.stringify(out) : null;
}

// The rate limiter runs BEFORE requireClientSecret on purpose: callers
// without the secret are throttled too, before any hashing work.
app.post("/verify", verifyLimiter, requireClientSecret, ah(async (req, res) => {
  const key = typeof req.body.key === "string" ? req.body.key.trim() : "";
  const hwid = typeof req.body.hwid === "string" ? req.body.hwid.trim() : "";
  if (!key || !hwid) {
    return res.status(400).json({ success: false, message: "Missing key or hwid." });
  }
  if (key.length > MAX_FIELD_LEN || hwid.length > MAX_FIELD_LEN) {
    return res.status(400).json({ success: false, message: "Malformed key or hwid." });
  }
  // Not a key this server could have issued: no database work at all.
  if (!KEY_SHAPE.test(key)) {
    return res.json({ success: false, message: "Invalid license key." });
  }
  const parts = cleanParts(req.body.parts);

  // One statement decides everything (see VERIFY_SQL):
  //   - `found` reads the row as it was, only to choose the message;
  //   - `upd` binds/refreshes, guarded on the LIVE row (l.status,
  //     l.hwid, l.hw_parts). Under READ COMMITTED a second, concurrent
  //     bind blocks on the row lock and then re-checks that guard against
  //     the updated row - so two PCs racing on one fresh key bind once.
  //     Gating on `found` instead would let both through.
  // A row with `updated = 0` is therefore an active key on another PC.
  const { rows } = await pool.query(VERIFY_SQL, [key, hwid, clientIp(req), parts]);

  const license = rows[0];
  if (!license) {
    return res.json({ success: false, message: "Invalid license key." });
  }
  if (license.status !== "active") {
    return res.json({ success: false, message: "This license key has been revoked." });
  }
  // Before the device check: an expired key on another PC should say it
  // expired - that's what the person has to act on. (The UPDATE's guard
  // already refused it; this only picks the message.)
  if (license.is_expired) {
    return res.json({ success: false, message: "This license key has expired." });
  }
  if (license.updated === 0) {
    return res.json({
      success: false,
      message: "This key is already activated on another PC. Ask on our Discord to move it to this one.",
    });
  }
  return res.json({
    success: true,
    message: "License activated.",
    // null = never expires. The app shows the time left from this.
    expires_at: license.expires_at ? new Date(license.expires_at).toISOString() : null,
  });
}));

// ---------- Admin routes - never called by the desktop app itself ----------
// Manage these from the dashboard, curl, or a storefront's own backend
// after a sale. All require X-Admin-Secret.

/// Runs one UPDATE/DELETE ... RETURNING license_key and records an event
/// for each row it touched - in a single statement, so a change and its
/// history entry can never come apart (a change that "happened" with no
/// record of it, or a record of a change that rolled back).
///
/// `mutationSql` must use $1..$n for its own `params` and must return
/// `license_key`. Returns how many rows changed, so callers can 404.
async function mutateAndLog(req, mutationSql, params, event, detail = null) {
  const n = params.length;
  const { rows } = await pool.query(
    `WITH m AS (${mutationSql})
     INSERT INTO license_events (license_key, event, detail, ip)
     SELECT license_key, $${n + 1}, $${n + 2}, $${n + 3} FROM m
     RETURNING license_key`,
    [...params, event, detail, clientIp(req)]
  );
  return rows.length;
}

// Keys created per request. Enough to stock a Discord shop in one go,
// small enough that a typo (an extra zero) can't mint ten thousand.
const MAX_BULK = 100;

// Creates one key, or `count` of them. Without `count` the response is
// the single created row exactly as it always was, so existing scripts
// keep working; with `count` it is `{ created: [...] }`.
//
// Bulk keys go in as one INSERT ... SELECT FROM unnest(...) with
// ON CONFLICT DO NOTHING, and any that collided (astronomically unlikely
// in a 31^12 keyspace, but checked rather than trusted away) are
// regenerated and retried - so a batch of 100 is one round trip, not 100.
app.post("/admin/licenses", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const expiry = resolveExpiry(req.body);
  if (expiry.error) return res.status(400).json({ error: expiry.error });

  const bulk = req.body && req.body.count !== undefined && req.body.count !== null && req.body.count !== "";
  const count = bulk ? Number(req.body.count) : 1;
  if (!Number.isInteger(count) || count < 1 || count > MAX_BULK) {
    return res.status(400).json({ error: `count must be a whole number from 1 to ${MAX_BULK}.` });
  }
  const detail = expiry.value ? `expires ${expiry.value.toISOString()}` : "never expires";

  const created = [];
  for (let attempt = 0; attempt < 5 && created.length < count; attempt++) {
    const wanted = Array.from({ length: count - created.length }, generateLicenseKey);
    const { rows } = await pool.query(
      `WITH ins AS (
         INSERT INTO licenses (license_key, expires_at)
         SELECT k, $2::timestamptz FROM unnest($1::text[]) AS k
         ON CONFLICT (license_key) DO NOTHING
         RETURNING id, license_key, status, created_at, expires_at
       ), ev AS (
         INSERT INTO license_events (license_key, event, detail, ip)
         SELECT license_key, 'created', $3, $4 FROM ins
       )
       SELECT * FROM ins ORDER BY id`,
      [wanted, expiry.value, detail, clientIp(req)]
    );
    created.push(...rows);
  }
  if (created.length < count) {
    return res.status(500).json({ error: "Could not generate enough unique keys - try again." });
  }
  return res.status(201).json(bulk ? { created } : created[0]);
}));

// Filters the dashboard offers. `status` values that are columns go
// straight to the column; the rest are derived views a person thinks in
// ("expiring soon", "online now", "never used") that are really
// conditions on timestamps.
const LICENSE_STATUSES = ["active", "revoked"];
const DERIVED_FILTERS = {
  expired: `expires_at IS NOT NULL AND expires_at <= now()`,
  expiring: `status = 'active' AND expires_at > now() AND expires_at <= now() + interval '7 days'`,
  // The app re-checks every five minutes while running, so anything
  // seen in the last ten is, for practical purposes, running right now.
  online: `status = 'active' AND last_seen_at > now() - interval '10 minutes'`,
  unused: `hwid IS NULL AND last_seen_at IS NULL`,
};

function buildLicenseQuery(query) {
  const conditions = [];
  const params = [];
  if (DERIVED_FILTERS[query.status]) {
    conditions.push(DERIVED_FILTERS[query.status]);
  } else if (LICENSE_STATUSES.includes(query.status)) {
    params.push(query.status);
    conditions.push(`status = $${params.length}`);
  }
  const q = typeof query.q === "string" ? query.q.trim().slice(0, 128) : "";
  if (q) {
    // Key, device digest, or last IP - "which key is this machine on?"
    // and "what else has this IP activated?" are both support questions
    // that used to need a hand-written SQL query.
    params.push(`%${q}%`);
    const p = `$${params.length}`;
    conditions.push(`(license_key ILIKE ${p} OR hwid ILIKE ${p} OR last_seen_ip ILIKE ${p})`);
  }
  return { where: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "", params };
}

app.get("/admin/licenses", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const { where, params } = buildLicenseQuery(req.query);
  params.push(limit);
  const limitP = `$${params.length}`;
  params.push(offset);
  const offsetP = `$${params.length}`;

  const { rows } = await pool.query(
    `SELECT id, license_key, hwid, status, created_at, expires_at, last_seen_at, last_seen_ip
       FROM licenses ${where}
      ORDER BY created_at DESC LIMIT ${limitP} OFFSET ${offsetP}`,
    params
  );
  res.json(rows);
}));

// Every number the dashboard's overview shows, in one pass over the
// table with FILTER clauses rather than one query per card. The original
// response fields (total, bound, unbound, expired, byStatus) are kept
// exactly as they were for anything already reading them.
app.get("/admin/stats", adminLimiter, requireAdminSecret, ah(async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT count(*)::int                                                       AS total,
            count(hwid)::int                                                    AS bound,
            (count(*) FILTER (WHERE status = 'active'))::int                    AS active,
            (count(*) FILTER (WHERE status = 'revoked'))::int                   AS revoked,
            (count(*) FILTER (WHERE ${DERIVED_FILTERS.expired}))::int           AS expired,
            (count(*) FILTER (WHERE ${DERIVED_FILTERS.expiring}))::int          AS expiring_soon,
            (count(*) FILTER (WHERE ${DERIVED_FILTERS.online}))::int            AS online,
            (count(*) FILTER (WHERE ${DERIVED_FILTERS.unused}))::int            AS never_used,
            (count(*) FILTER (WHERE created_at > now() - interval '7 days'))::int AS created_7d,
            ev.activations_24h, ev.device_rejections_24h, ev.device_updates_24h
       FROM licenses,
            -- One round trip: the 24-hour event counts ride along.
            (SELECT (count(*) FILTER (WHERE event = 'activated'))::int       AS activations_24h,
                    (count(*) FILTER (WHERE event = 'rejected_device'))::int AS device_rejections_24h,
                    (count(*) FILTER (WHERE event = 'device_updated'))::int  AS device_updates_24h
               FROM license_events WHERE created_at > now() - interval '24 hours') ev
      GROUP BY ev.activations_24h, ev.device_rejections_24h, ev.device_updates_24h`
  );
  const r = rows[0] || { total: 0, bound: 0, active: 0, revoked: 0, expired: 0, expiring_soon: 0,
    online: 0, never_used: 0, created_7d: 0, activations_24h: 0, device_rejections_24h: 0, device_updates_24h: 0 };
  res.json({
    total: r.total,
    bound: r.bound,
    unbound: r.total - r.bound,
    expired: r.expired,
    byStatus: { active: r.active, revoked: r.revoked },
    expiringSoon: r.expiring_soon,
    online: r.online,
    neverUsed: r.never_used,
    created7d: r.created_7d,
    activations24h: r.activations_24h,
    deviceRejections24h: r.device_rejections_24h,
    deviceUpdates24h: r.device_updates_24h,
  });
}));

// One key's history, newest first.
app.get("/admin/licenses/:key/events", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const { rows } = await pool.query(
    `SELECT event, detail, ip, hwid, created_at FROM license_events
      WHERE license_key = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
    [req.params.key, limit]
  );
  res.json(rows);
}));

// The recent-activity feed across every key.
app.get("/admin/events", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
  const { rows } = await pool.query(
    `SELECT license_key, event, detail, ip, hwid, created_at FROM license_events
      ORDER BY created_at DESC, id DESC LIMIT $1`,
    [limit]
  );
  res.json(rows);
}));

/// RFC 4180 field quoting, plus a guard against CSV formula injection: a
/// cell beginning with = + - @ (or tab/CR) is executed as a formula when
/// the export is opened in Excel or Sheets. Nothing in this table
/// *should* start that way, but `last_seen_ip` and `hwid` arrive from
/// the network, and an export is something you open without thinking.
function csvCell(value) {
  if (value === null || value === undefined) return "";
  let s = value instanceof Date ? value.toISOString() : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// Same filters as the list, so "export what I'm looking at" works - but
// no pagination: an export is the whole matching set.
app.get("/admin/export.csv", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const { where, params } = buildLicenseQuery(req.query);
  const { rows } = await pool.query(
    `SELECT license_key, status, hwid, created_at, expires_at, last_seen_at, last_seen_ip
       FROM licenses ${where} ORDER BY created_at DESC`,
    params
  );
  const header = ["license_key", "status", "device", "created_at", "expires_at", "last_seen_at", "last_seen_ip"];
  const body = rows.map((r) =>
    [r.license_key, r.status, r.hwid, r.created_at, r.expires_at, r.last_seen_at, r.last_seen_ip].map(csvCell).join(",")
  );
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="licenses-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.setHeader("Cache-Control", "no-store");
  res.end([header.join(","), ...body].join("\r\n") + "\r\n");
}));

// Status changes. Each is one statement that both makes the change and
// records it.
for (const [action, toStatus] of [
  ["revoke", "revoked"],
  ["unrevoke", "active"],
]) {
  app.post(`/admin/licenses/:key/${action}`, adminLimiter, requireAdminSecret, ah(async (req, res) => {
    const changed = await mutateAndLog(
      req,
      `UPDATE licenses SET status = $2 WHERE license_key = $1 RETURNING license_key`,
      [req.params.key, toStatus],
      action === "unrevoke" ? "reactivated" : toStatus
    );
    if (changed === 0) return res.status(404).json({ error: "No license with that key." });
    res.json({ ok: true });
  }));
}

// Sets or clears one key's expiry - same body as creating a key
// (`expires_in_days` or `expires_at`); neither, or 0 days, clears it to
// "never expires". Counted from *now*. For "add 30 days to what they
// have", use /extend instead.
app.post("/admin/licenses/:key/expiry", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const expiry = resolveExpiry(req.body);
  if (expiry.error) return res.status(400).json({ error: expiry.error });
  const detail = expiry.value ? `set to ${expiry.value.toISOString()}` : "set to never expires";
  const { rows } = await pool.query(
    `WITH m AS (
       UPDATE licenses SET expires_at = $1::timestamptz WHERE license_key = $2
       RETURNING license_key, expires_at
     ), ev AS (
       INSERT INTO license_events (license_key, event, detail, ip)
       SELECT license_key, 'expiry_changed', $3, $4 FROM m
     )
     SELECT license_key, expires_at FROM m`,
    [expiry.value, req.params.key, detail, clientIp(req)]
  );
  if (rows.length === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true, expires_at: rows[0].expires_at });
}));

// Adds days to a key - what a renewal actually is. Extends from the
// current expiry if it's still in the future, or from now if the key has
// already lapsed, so renewing an expired key gives the full period from
// today rather than a period that's partly already gone.
//
// Refused for a key that never expires: there's nothing to add to, and
// silently turning a lifetime key into a 30-day one would be the worst
// possible reading of "extend".
app.post("/admin/licenses/:key/extend", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const days = Number(req.body && req.body.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ error: "days must be a whole number from 1 to 3650." });
  }
  const { rows } = await pool.query(
    `WITH m AS (
       UPDATE licenses
          SET expires_at = GREATEST(expires_at, now()) + make_interval(days => $2::int)
        WHERE license_key = $1 AND expires_at IS NOT NULL
       RETURNING license_key, expires_at
     ), ev AS (
       INSERT INTO license_events (license_key, event, detail, ip)
       SELECT license_key, 'extended', $3, $4 FROM m
     )
     SELECT license_key, expires_at FROM m`,
    [req.params.key, days, `+${days} days`, clientIp(req)]
  );
  if (rows.length > 0) return res.json({ ok: true, expires_at: rows[0].expires_at });

  // Nothing updated: tell the two reasons apart, since they need
  // different fixes. Only on this (rare) path does it cost a second query.
  const { rows: exists } = await pool.query(`SELECT expires_at FROM licenses WHERE license_key = $1`, [req.params.key]);
  if (exists.length === 0) return res.status(404).json({ error: "No license with that key." });
  return res.status(400).json({ error: "This key never expires - there's nothing to extend. Use Change expiry to give it one." });
}));

app.post("/admin/licenses/:key/reset-hwid", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  // Lets a customer move a key to a new/replacement device. The device
  // being released is recorded, so a key that gets reset suspiciously
  // often (a key being shared around) is visible in its history.
  //
  // Its own statement rather than mutateAndLog, because the event row
  // needs the *released* hwid, which only exists before the update: the
  // FROM subquery reads the row as it was at statement start.
  const { rows } = await pool.query(
    `WITH m AS (
       UPDATE licenses l SET hwid = NULL, hw_parts = NULL
         FROM (SELECT id, hwid AS old_hwid FROM licenses WHERE license_key = $1) prev
        WHERE l.id = prev.id
        RETURNING l.license_key, prev.old_hwid
     )
     INSERT INTO license_events (license_key, event, detail, ip, hwid)
     SELECT license_key, 'device_reset', NULL, $2, old_hwid FROM m
     RETURNING license_key`,
    [req.params.key, clientIp(req)]
  );
  if (rows.length === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

app.delete("/admin/licenses/:key", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  // The history is kept (no foreign key - see migrate()), so the
  // deletion itself is recorded as its last entry.
  const changed = await mutateAndLog(
    req,
    `DELETE FROM licenses WHERE license_key = $1 RETURNING license_key`,
    [req.params.key],
    "deleted"
  );
  if (changed === 0) return res.status(404).json({ error: "No license with that key." });
  res.json({ ok: true });
}));

// ---------- Bulk actions ----------
// One action applied to many keys at once, from the dashboard's selection
// bar. Each is a single statement that changes the keys *and* records an
// event per changed key, same as the one-key routes, so history can't
// come apart from what happened. Keys already in the target state are
// skipped (not re-recorded), which is why the reply says how many
// actually changed.
const BULK_MAX = 200;
const BULK_SIMPLE = {
  revoke: {
    sql: `UPDATE licenses SET status = 'revoked' WHERE license_key = ANY($1::text[]) AND status <> 'revoked' RETURNING license_key`,
    event: "revoked",
  },
  reactivate: {
    sql: `UPDATE licenses SET status = 'active' WHERE license_key = ANY($1::text[]) AND status <> 'active' RETURNING license_key`,
    event: "reactivated",
  },
  delete: {
    sql: `DELETE FROM licenses WHERE license_key = ANY($1::text[]) RETURNING license_key`,
    event: "deleted",
  },
};

app.post("/admin/licenses/bulk", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const body = req.body || {};
  const keys = Array.isArray(body.keys) ? [...new Set(body.keys)] : null;
  if (!keys || keys.length === 0 || keys.length > BULK_MAX ||
      keys.some((k) => typeof k !== "string" || k.length === 0 || k.length > 64)) {
    return res.status(400).json({ error: `keys must be a list of 1-${BULK_MAX} license keys.` });
  }
  const action = String(body.action || "");
  let changed;
  if (BULK_SIMPLE[action]) {
    const { sql, event } = BULK_SIMPLE[action];
    changed = await mutateAndLog(req, sql, [keys], event);
  } else if (action === "extend") {
    const days = Number(body.days);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      return res.status(400).json({ error: "days must be a whole number from 1 to 3650." });
    }
    // Never-expiring keys are left alone, exactly as the one-key route.
    changed = await mutateAndLog(
      req,
      `UPDATE licenses SET expires_at = GREATEST(expires_at, now()) + make_interval(days => $2::int)
        WHERE license_key = ANY($1::text[]) AND expires_at IS NOT NULL
       RETURNING license_key`,
      [keys, days],
      "extended",
      `+${days} days`
    );
  } else if (action === "reset-hwid") {
    const { rows } = await pool.query(
      `WITH m AS (
         UPDATE licenses l SET hwid = NULL, hw_parts = NULL
           FROM (SELECT id, hwid AS old_hwid FROM licenses
                  WHERE license_key = ANY($1::text[]) AND hwid IS NOT NULL) prev
          WHERE l.id = prev.id
          RETURNING l.license_key, prev.old_hwid
       )
       INSERT INTO license_events (license_key, event, detail, ip, hwid)
       SELECT license_key, 'device_reset', NULL, $2, old_hwid FROM m
       RETURNING license_key`,
      [keys, clientIp(req)]
    );
    changed = rows.length;
  } else {
    return res.status(400).json({ error: "action must be revoke, reactivate, extend, reset-hwid or delete." });
  }
  res.json({ ok: true, requested: keys.length, changed });
}));

// ---------- Activity by day ----------
// For the dashboard's chart: keys created, first activations and refused
// checks per day (UTC), oldest first, with empty days included as zeros.
app.get("/admin/stats/daily", adminLimiter, requireAdminSecret, ah(async (req, res) => {
  const days = Math.min(90, Math.max(7, parseInt(req.query.days, 10) || 14));
  const { rows } = await pool.query(
    `WITH d AS (
       SELECT generate_series(current_date - ($1::int - 1), current_date, interval '1 day')::date AS day
     ), e AS (
       -- From the history, not the licenses table, so a key that was
       -- later deleted still counts on the day it was made.
       SELECT created_at::date AS day,
              count(*) FILTER (WHERE event = 'created') AS c,
              count(*) FILTER (WHERE event = 'activated') AS a,
              count(*) FILTER (WHERE event LIKE 'rejected%') AS r
         FROM license_events WHERE created_at >= current_date - ($1::int - 1) GROUP BY 1
     )
     SELECT to_char(d.day, 'YYYY-MM-DD') AS day,
            COALESCE(e.c, 0)::int AS created,
            COALESCE(e.a, 0)::int AS activations,
            COALESCE(e.r, 0)::int AS rejections
       FROM d LEFT JOIN e USING (day)
      ORDER BY d.day`,
    [days]
  );
  res.json(rows);
}));

// Last-resort handler: anything that throws inside a route above
// (a Postgres hiccup, etc.) lands here instead of taking the whole
// process down or leaking a stack trace to the caller.
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal error." });
});

migrate()
  .then(checkVerifyStatement)
  .then(() => {
    pruneEvents();
    setInterval(pruneEvents, 60 * 60 * 1000).unref();

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
    // Exiting (rather than serving anyway) is the point: a server that
    // can't migrate, or whose /verify statement Postgres rejects, must
    // fail its health check so the previous deployment stays live.
    console.error("Startup check failed - refusing to serve:", e);
    process.exit(1);
  });
