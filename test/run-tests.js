// License server test suite - runs the real server.js against a real
// Postgres and exercises it over HTTP, the way the desktop app does.
//
//   TEST_DATABASE_URL=postgres://user:pass@localhost:5432/afkstrike_test npm test
//
// SAFETY: this deletes every row in `licenses` and `license_events` in
// the database it is given, before it starts. It therefore refuses to
// run unless the database name contains "test", and unless that URL is
// different from DATABASE_URL. Never point it at production.
//
// What it covers that nothing else ever has: the /verify statement's
// atomic device bind under genuine contention. The race test installs a
// trigger that holds the row lock for 150ms, so twenty concurrent
// activations really do queue behind one another - without that, each
// UPDATE commits in microseconds and the test passes even against the
// known-broken query (verified: the broken version lets 10 of 20 bind).
"use strict";

const { spawn } = require("child_process");
const path = require("path");
const { Pool } = require("pg");

const DB = process.env.TEST_DATABASE_URL;
if (!DB) {
  console.error("Set TEST_DATABASE_URL to a throwaway Postgres database (its name must contain 'test').");
  process.exit(2);
}
const dbName = new URL(DB).pathname.replace(/^\//, "");
if (!/test/i.test(dbName) || DB === process.env.DATABASE_URL) {
  console.error(`Refusing to run against "${dbName}": the database name must contain "test" and must not be DATABASE_URL. This suite deletes every license in the database it's given.`);
  process.exit(2);
}

const PORT = 39000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
const CLIENT = "test-client-secret";
// A throwaway signing key for this run; the public half checks the tokens.
const crypto = require("crypto");
const SIGN_SEED = crypto.randomBytes(32);
const SIGN_PUB = crypto.createPublicKey(crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SIGN_SEED]), format: "der", type: "pkcs8",
}));
function readToken(token) {
  const [payload, sig] = String(token || "").split(".");
  if (!payload || !sig) return null;
  const fromB64 = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (!crypto.verify(null, Buffer.from(payload), SIGN_PUB, fromB64(sig))) return null;
  return JSON.parse(fromB64(payload).toString("utf8"));
}
const ADMIN = "test-admin-secret";
const pool = new Pool({ connectionString: DB, max: 2 });
const sql = async (q, p) => (await pool.query(q, p)).rows;

let ipSeq = 1;
const freshIp = () => `10.${Math.floor(ipSeq / 62500) % 250}.${Math.floor(ipSeq / 250) % 250}.${(ipSeq++ % 250) + 1}`;

async function verify(key, hwid, extra = {}, ip = freshIp()) {
  const r = await fetch(BASE + "/verify", {
    method: "POST",
    headers: { "content-type": "application/json", "x-client-secret": CLIENT, "x-forwarded-for": ip },
    body: JSON.stringify({ key, hwid, ...extra }),
  });
  return { status: r.status, body: await r.json() };
}
async function admin(method, p, body) {
  const r = await fetch(BASE + p, {
    method,
    headers: { "content-type": "application/json", "x-admin-secret": ADMIN, "x-forwarded-for": freshIp() },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, body: json, headers: r.headers };
}
const events = async (k) => (await admin("GET", `/admin/licenses/${k}/events`)).body.map((e) => e.event);

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (detail !== undefined ? "  -> " + JSON.stringify(detail) : "")); }
}
const section = (t) => console.log(`\n${t}`);

async function startServer() {
  const child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, DATABASE_URL: DB, CLIENT_SHARED_SECRET: CLIENT, ADMIN_SECRET: ADMIN, LICENSE_SIGNING_KEY: SIGN_SEED.toString("base64"), PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  for (let i = 0; i < 40; i++) {
    try { if ((await fetch(BASE + "/health")).ok) return { child, log: () => log }; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  child.kill();
  throw new Error("server did not start:\n" + log);
}

async function main() {
  // The server creates the tables itself on boot; clear them only after.
  const srv = await startServer();
  await sql("DELETE FROM license_events");
  await sql("DELETE FROM licenses");

  try {
    section("Auth and input handling");
    check("health reports the database", (await (await fetch(BASE + "/health")).json()).database === "ok");
    const noSecret = await fetch(BASE + "/verify", { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": freshIp() }, body: "{}" });
    check("verify without the client secret -> 401", noSecret.status === 401);
    check("admin with a wrong secret -> 401", (await fetch(BASE + "/admin/stats", { headers: { "x-admin-secret": "nope", "x-forwarded-for": freshIp() } })).status === 401);
    const big = await fetch(BASE + "/verify", { method: "POST", headers: { "content-type": "application/json", "x-client-secret": CLIENT, "x-forwarded-for": freshIp() }, body: JSON.stringify({ key: "x".repeat(5000), hwid: "y" }) });
    check("oversized body rejected", big.status === 413 || big.status === 400, big.status);

    section("Signed tokens");
    {
      const tk = (await admin("POST", "/admin/licenses", { expires_in_days: 5 })).body.license_key;
      const nonce = crypto.randomBytes(16).toString("hex");
      const r = await verify(tk, "a".repeat(32), { nonce });
      const t = r.body && readToken(r.body.token);
      check("a yes carries a token signed by the server's key", !!t, r.body);
      check("the token names this device and this request's nonce", t && t.hwid === "a".repeat(32) && t.nonce === nonce, t);
      check("the token carries the key's hash, not the key", t && t.kh === crypto.createHash("sha256").update(tk).digest("hex") && !JSON.stringify(t).includes(tk), t);
      check("the token carries the expiry and a current issue time", t && t.exp && Math.abs(t.iat - Date.now() / 1000) < 60, t);
      const forged = r.body.token.slice(0, -4) + (r.body.token.endsWith("AAAA") ? "BBBB" : "AAAA");
      check("a tampered token fails verification", readToken(forged) === null);
      const bad = await verify(tk, "a".repeat(32), { nonce: "not-a-nonce" });
      check("a malformed nonce is left out, not echoed", readToken(bad.body.token).nonce === null);
      const no = await verify(tk, "b".repeat(32));
      check("a refusal carries no token", no.body.success === false && !no.body.token, no.body);
      await admin("DELETE", `/admin/licenses/${tk}`);
    }

    section("Device binding");
    const one = await admin("POST", "/admin/licenses", {});
    const key = one.body.license_key;
    check("create -> 201, key in AFK-XXXX-XXXX-XXXX form", one.status === 201 && /^AFK(-[A-HJKMNP-Z2-9]{4}){3}$/.test(key), one.body);
    check("single create returns the bare row (backward compatible)", !one.body.created);
    check("first device binds", (await verify(key, "device-A")).body.success === true);
    const b1 = (await verify(key, "device-B")).body;
    check("second device refused", b1.success === false && /another PC/.test(b1.message), b1);
    check("first device still accepted", (await verify(key, "device-A")).body.success === true);
    check("unknown key refused", (await verify("AFK-ZZZZ-ZZZZ-ZZZZ", "x")).body.success === false);
    await admin("POST", `/admin/licenses/${key}/revoke`);
    check("revoked key refused", /revoked/.test((await verify(key, "device-A")).body.message));
    await admin("POST", `/admin/licenses/${key}/unrevoke`);
    await admin("POST", `/admin/licenses/${key}/reset-hwid`);
    check("after a device reset, a new device can bind", (await verify(key, "device-B")).body.success === true);
    check("success message", (await verify(key, "device-B")).body.message === "License activated.");

    section("Key format");
    check("an old-format key is refused", (await verify("H7K2M-QW9XP-3NBVT-R4ZCD", "pc")).body.message === "Invalid license key.");
    check("lowercase / wrong-alphabet keys are refused", (await verify(key.toLowerCase(), "pc")).body.success === false && (await verify("AFK-0000-1111-IIII", "pc")).body.success === false);
    const keySet = new Set();
    for (const r of (await admin("POST", "/admin/licenses", { count: 100 })).body.created) keySet.add(r.license_key);
    check("100 new keys: all AFK- format, all distinct, no look-alikes",
      keySet.size === 100 && [...keySet].every((k) => /^AFK(-[A-HJKMNP-Z2-9]{4}){3}$/.test(k)));

    section("The bind race (row lock held 150ms by a test trigger)");
    await sql(`CREATE OR REPLACE FUNCTION afk_test_slow_bind() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$ LANGUAGE plpgsql`);
    await sql(`DROP TRIGGER IF EXISTS afk_test_slow_bind ON licenses`);
    await sql(`CREATE TRIGGER afk_test_slow_bind BEFORE UPDATE ON licenses FOR EACH ROW EXECUTE FUNCTION afk_test_slow_bind()`);
    try {
      const race = (await admin("POST", "/admin/licenses", {})).body.license_key;
      const res = await Promise.all(Array.from({ length: 20 }, (_, i) => verify(race, `racer-${i}`)));
      const winners = res.filter((r) => r.body.success === true).length;
      check("exactly one of 20 simultaneous devices binds", winners === 1, { winners });
      const ev = await events(race);
      check("history agrees: 1 activation, 19 device refusals",
        ev.filter((e) => e === "activated").length === 1 && ev.filter((e) => e === "rejected_device").length === 19,
        { activated: ev.filter((e) => e === "activated").length, refused: ev.filter((e) => e === "rejected_device").length });
    } finally {
      await sql(`DROP TRIGGER IF EXISTS afk_test_slow_bind ON licenses`);
      await sql(`DROP FUNCTION IF EXISTS afk_test_slow_bind()`);
    }

    section("Same PC after a small hardware change");
    const P = { mg: "a1a1a1a1a1a1a1a1", vol: "b2b2b2b2b2b2b2b2", cpu: "c3c3c3c3c3c3c3c3", cores: "d4d4d4d4d4d4d4d4", host: "e5e5e5e5e5e5e5e5" };
    const hk = (await admin("POST", "/admin/licenses", {})).body.license_key;
    check("activates with parts", (await verify(hk, "fp-1", { parts: P })).body.success === true);
    let stored = (await sql("SELECT hw_parts FROM licenses WHERE license_key = $1", [hk]))[0].hw_parts;
    if (typeof stored === "string") stored = JSON.parse(stored);
    check("parts are stored", Object.keys(P).every((k) => stored[k] === P[k]) && Object.keys(stored).length === 5, stored);
    check("renamed PC (new host, new digest) still works", (await verify(hk, "fp-2", { parts: { ...P, host: "ffffffffffffffff" } })).body.success === true);
    check("...and the key is rebound to the new digest", (await sql("SELECT hwid FROM licenses WHERE license_key = $1", [hk]))[0].hwid === "fp-2");
    check("...recorded as device_updated", (await events(hk)).includes("device_updated"));
    check("CPU swap too (mg + vol + host match)", (await verify(hk, "fp-3", { parts: { ...P, host: "ffffffffffffffff", cpu: "0000000000000000", cores: "1111111111111111" } })).body.success === true);
    check("another PC (different Windows install) is refused", (await verify(hk, "fp-x", { parts: { ...P, mg: "9999999999999999" } })).body.success === false);
    check("only mg matching is not enough", (await verify(hk, "fp-y", { parts: { mg: P.mg, vol: "1", cpu: "2", cores: "3", host: "4" } })).body.success === false);
    check("no parts sent = exact digest only", (await verify(hk, "fp-z")).body.success === false && (await verify(hk, "fp-3")).body.success === true);
    check("junk parts are ignored, not stored", (await verify(hk, "fp-3", { parts: { mg: "<script>", "bad key": "aaaaaaaa", vol: 5 } })).body.success === true
      && String(JSON.stringify((await sql("SELECT hw_parts FROM licenses WHERE license_key = $1", [hk]))[0].hw_parts)).includes(P.mg)
      && !String(JSON.stringify((await sql("SELECT hw_parts FROM licenses WHERE license_key = $1", [hk]))[0].hw_parts)).includes("script"));
    await admin("POST", `/admin/licenses/${hk}/reset-hwid`);
    check("device reset clears the parts too", (await sql("SELECT hw_parts FROM licenses WHERE license_key = $1", [hk]))[0].hw_parts === null);

    section("Expiry");
    const exp = (await admin("POST", "/admin/licenses", { expires_at: new Date(Date.now() - 60000).toISOString() })).body.license_key;
    check("expired key refused as expired", /expired/.test((await verify(exp, "d")).body.message));
    const ext = (await admin("POST", "/admin/licenses", { expires_in_days: 30 })).body;
    const e1 = await admin("POST", `/admin/licenses/${ext.license_key}/extend`, { days: 10 });
    check("extend adds to the current expiry", Math.abs((new Date(e1.body.expires_at) - new Date(ext.expires_at)) / 864e5 - 10) < 0.01);
    const e2 = await admin("POST", `/admin/licenses/${exp}/extend`, { days: 7 });
    check("extending a lapsed key counts from today", Math.abs((new Date(e2.body.expires_at) - Date.now()) / 864e5 - 7) < 0.01);
    check("...and it works again", (await verify(exp, "d")).body.success === true);
    const e3 = await admin("POST", `/admin/licenses/${key}/extend`, { days: 30 });
    check("extend refuses a never-expiring key", e3.status === 400);
    check("...and leaves it never-expiring", (await sql("SELECT expires_at FROM licenses WHERE license_key = $1", [key]))[0].expires_at === null);

    section("Bulk keys");
    const bulk = await admin("POST", "/admin/licenses", { count: 25, expires_in_days: 30 });
    const keys = (bulk.body.created || []).map((r) => r.license_key);
    check("25 distinct keys in one request", keys.length === 25 && new Set(keys).size === 25);
    check("count above 100 refused", (await admin("POST", "/admin/licenses", { count: 101 })).status === 400);
    check("count 0 refused", (await admin("POST", "/admin/licenses", { count: 0 })).status === 400);

    section("History");
    const k = keys[0];
    await verify(k, "dev-1"); await verify(k, "dev-1"); await verify(k, "dev-2");
    let ev = await events(k);
    check("creation and activation recorded", ev.includes("created") && ev.includes("activated"));
    check("routine check-ins are NOT recorded", ev.filter((e) => e === "activated").length === 1, ev);
    const rej = (await admin("GET", `/admin/licenses/${k}/events`)).body.find((e) => e.event === "rejected_device");
    check("a refusal records which device tried", rej && rej.hwid === "dev-2");
    const before = (await sql("SELECT count(*)::int AS n FROM license_events"))[0].n;
    await verify("AFK-ZZZZ-YYYY-XXXX", "x");
    check("unknown keys never grow the table", (await sql("SELECT count(*)::int AS n FROM license_events"))[0].n === before);
    await admin("POST", `/admin/licenses/${k}/revoke`);
    await admin("POST", `/admin/licenses/${k}/unrevoke`);
    await admin("POST", `/admin/licenses/${k}/reset-hwid`);
    ev = await events(k);
    check("admin changes recorded", ["revoked", "reactivated", "device_reset"].every((e) => ev.includes(e)), ev);
    const reset = (await admin("GET", `/admin/licenses/${k}/events`)).body.find((e) => e.event === "device_reset");
    check("a device reset records the released device", reset && reset.hwid === "dev-1");
    await admin("DELETE", `/admin/licenses/${keys[1]}`);
    check("deleting a key keeps its history", (await events(keys[1]))[0] === "deleted");

    section("Stats, filters, search, export");
    const st = (await admin("GET", "/admin/stats")).body;
    check("original stats fields kept", ["total", "bound", "unbound", "expired", "byStatus"].every((f) => f in st));
    check("byStatus sums to total", st.byStatus.active + st.byStatus.revoked === st.total);
    check("online / neverUsed / activations24h present", st.online >= 1 && st.neverUsed >= 1 && st.activations24h >= 1, st);
    const soon = (await admin("POST", "/admin/licenses", { expires_in_days: 3 })).body.license_key;
    check("expiring filter", (await admin("GET", "/admin/licenses?status=expiring")).body.some((r) => r.license_key === soon));
    const sk = (await admin("POST", "/admin/licenses", {})).body.license_key;
    await verify(sk, "searchable-pc-77");
    check("search by device", (await admin("GET", "/admin/licenses?q=searchable-pc-77")).body.length === 1);
    const csv = await admin("GET", "/admin/export.csv");
    check("CSV export with header", /text\/csv/.test(csv.headers.get("content-type")) && csv.body.startsWith("license_key,status"));
    await sql("UPDATE licenses SET last_seen_ip = '=HYPERLINK(1)' WHERE license_key = $1", [soon]);
    check("CSV neutralises formula injection", (await admin("GET", "/admin/export.csv")).body.includes("'=HYPERLINK(1)"));

    section("Rate limiting");
    let limited = 0;
    for (let i = 0; i < 32; i++) if ((await verify("AAAAA-BBBBB-CCCCC-DDDDD", "x", {}, "203.0.113.9")).status === 429) limited++;
    check("30 checks/min per address, then 429", limited === 2, limited);
    let spoofed = 0;
    for (let i = 0; i < 32; i++) if ((await verify("AAAAA-BBBBB-CCCCC-DDDDD", "x", {}, `${i}.${i}.${i}.${i}, 198.51.100.7`)).status === 429) spoofed++;
    check("a spoofed left-most X-Forwarded-For doesn't evade it", spoofed === 2, spoofed);
    // On Railway the edge sets X-Real-IP; X-Forwarded-For is whatever the caller sent.
    let rotated = 0;
    for (let i = 0; i < 32; i++) {
      const r = await fetch(BASE + "/verify", {
        method: "POST",
        headers: { "content-type": "application/json", "x-client-secret": CLIENT, "x-real-ip": "198.51.100.42", "x-forwarded-for": `192.0.2.${i + 1}` },
        body: JSON.stringify({ key: "AAAAA-BBBBB-CCCCC-DDDDD", hwid: "x" }),
      });
      if (r.status === 429) rotated++;
    }
    check("X-Real-IP wins: rotating X-Forwarded-For doesn't evade it", rotated === 2, rotated);

    section("Bulk actions");
    const made = (await admin("POST", "/admin/licenses", { count: 4, expires_in_days: 10 })).body.created.map((l) => l.license_key);
    const lifetime = (await admin("POST", "/admin/licenses", {})).body.license_key;
    let br = await admin("POST", "/admin/licenses/bulk", { action: "revoke", keys: [...made, made[0]] });
    check("bulk revoke changes each key once (duplicates ignored)", br.status === 200 && br.body.changed === 4 && br.body.requested === 4, br.body);
    br = await admin("POST", "/admin/licenses/bulk", { action: "revoke", keys: made });
    check("already-revoked keys are skipped", br.body.changed === 0);
    check("revoked keys refuse to verify", (await verify(made[1], "bulk-dev")).body.success === false);
    br = await admin("POST", "/admin/licenses/bulk", { action: "reactivate", keys: made });
    check("bulk reactivate", br.body.changed === 4 && (await verify(made[1], "bulk-dev")).body.success === true);
    const expBefore = (await admin("GET", `/admin/licenses?q=${made[2]}`)).body[0].expires_at;
    br = await admin("POST", "/admin/licenses/bulk", { action: "extend", days: 30, keys: [made[2], lifetime] });
    const expAfter = (await admin("GET", `/admin/licenses?q=${made[2]}`)).body[0].expires_at;
    check("bulk extend adds 30 days and skips a never-expiring key",
      br.body.changed === 1 && Math.round((new Date(expAfter) - new Date(expBefore)) / 86400000) === 30, { b: br.body, expBefore, expAfter });
    br = await admin("POST", "/admin/licenses/bulk", { action: "reset-hwid", keys: made });
    check("bulk reset only touches bound keys", br.body.changed === 1);
    const evs = (await admin("GET", `/admin/licenses/${made[1]}/events`)).body.map((e) => e.event);
    check("bulk changes are in each key's history", ["revoked", "reactivated", "device_reset"].every((e) => evs.includes(e)), evs);
    br = await admin("POST", "/admin/licenses/bulk", { action: "ban", keys: made });
    check("unknown bulk action refused", br.status === 400);
    check("the retired /ban route is gone", (await admin("POST", `/admin/licenses/${made[0]}/ban`)).status === 404);
    br = await admin("POST", "/admin/licenses/bulk", { action: "revoke", keys: [] });
    check("empty key list refused", br.status === 400);
    br = await admin("POST", "/admin/licenses/bulk", { action: "revoke", keys: Array.from({ length: 201 }, (_, i) => `K${i}`) });
    check("more than 200 keys refused", br.status === 400);
    br = await admin("POST", "/admin/licenses/bulk", { action: "delete", keys: [made[3]] });
    check("bulk delete keeps history", br.body.changed === 1 && (await admin("GET", `/admin/licenses/${made[3]}/events`)).body[0].event === "deleted");

    section("Activity by day");
    const daily = (await admin("GET", "/admin/stats/daily?days=14")).body;
    check("14 days, oldest first, today last", Array.isArray(daily) && daily.length === 14 && daily[13].day === new Date().toISOString().slice(0, 10), daily.slice(-2));
    check("today counts keys created and activations", daily[13].created >= 5 && daily[13].activations >= 1, daily[13]);
    check("days clamp to 7..90", (await admin("GET", "/admin/stats/daily?days=2")).body.length === 7 && (await admin("GET", "/admin/stats/daily?days=500")).body.length === 90);

    section("Compression and caching");
    const raw = (p, headers = {}) => new Promise((resolve, reject) => {
      require("http").get(`${BASE}${p}`, { headers }, (r) => {
        const chunks = [];
        r.on("data", (c) => chunks.push(c));
        r.on("end", () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks) }));
      }).on("error", reject);
    });
    const zlib = require("zlib");
    for (let i = 0; i < 30; i++) await admin("POST", "/admin/licenses", { note: `bulk filler ${i}` });
    const plainList = await raw("/admin/licenses", { "x-admin-secret": ADMIN });
    const gzList = await raw("/admin/licenses", { "x-admin-secret": ADMIN, "accept-encoding": "gzip" });
    check("key list is gzipped when asked", gzList.headers["content-encoding"] === "gzip");
    check("...and decompresses to the same JSON", zlib.gunzipSync(gzList.body).equals(plainList.body));
    check("...with a matching Content-Length", Number(gzList.headers["content-length"]) === gzList.body.length);
    check("...much smaller", gzList.body.length < plainList.body.length / 3, [gzList.body.length, plainList.body.length]);
    check("not gzipped when not asked", !plainList.headers["content-encoding"] && JSON.parse(plainList.body).length > 30);
    check("Vary: Accept-Encoding set", /accept-encoding/i.test(gzList.headers["vary"] || ""));
    const page = await raw("/", { "accept-encoding": "gzip" });
    check("admin page gzipped", page.headers["content-encoding"] === "gzip" && zlib.gunzipSync(page.body).toString().includes("<html"));
    check("admin page revalidates (no-cache)", page.headers["cache-control"] === "no-cache");
    const logo = await raw("/logo.png", { "accept-encoding": "gzip" });
    check("logo not gzipped (already compressed), cached a day", !logo.headers["content-encoding"] && logo.headers["cache-control"] === "public, max-age=86400" && logo.body[1] === 0x50);
    const small = await raw("/health", { "accept-encoding": "gzip" });
    check("tiny responses left uncompressed", !small.headers["content-encoding"] && JSON.parse(small.body).status === "ok");
    const manifest = await raw("/updates/latest.json", { "accept-encoding": "gzip" });
    check("update manifest still no-store", manifest.headers["cache-control"] === "no-store" && manifest.status === 200);
    const v = await verify("AFK-ZZZZ-ZZZZ-ZZZZ", "nope");
    check("verify still answers with parsed JSON through the gzip layer", v.body && v.body.success === false && v.body.message === "Invalid license key.", v);

    const errs = srv.log().split("\n").filter((l) => /error/i.test(l));
    check("server logged no errors", errs.length === 0, errs.slice(0, 3));
  } finally {
    srv.child.kill();
    await pool.end();
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
