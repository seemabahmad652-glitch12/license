# AfkStrike license server

The self-hosted license check behind AfkStrike's key screen, plus the files the app's
auto-updater downloads. A small Node/Express app on Postgres, deployed on Railway at
**https://license.lootbloxy.com**. It isn't part of the desktop app's build.

| Route | Who calls it |
| --- | --- |
| `POST /verify` | The desktop app: `{key, hwid, parts}`, validates a key and locks it to one PC |
| `GET /updates/latest.json` + installers | The app's auto-updater. `release.cmd` in the app project writes these (see its `UPDATING.md`) |
| `GET /` | Admin dashboard (you, in a browser) |
| `/admin/*` | The dashboard, or you with curl (needs `ADMIN_SECRET`) |
| `GET /health` | Railway's healthcheck: `{"status":"ok","database":"ok"}`, 503 if Postgres is down |

## Deployment

| | |
| --- | --- |
| GitHub | `seemabahmad652-glitch12/license`, branch `main`, files at the repo root (**public repo**) |
| Railway | project `lootbloxy` → service `license-server` → env `production` |
| Database | Railway Postgres, attached as `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` |
| Domain | `license.lootbloxy.com` (CNAME to Railway; Railway issues TLS) |
| Variables | `DATABASE_URL`, `CLIENT_SHARED_SECRET`, `ADMIN_SECRET` (`PORT` is injected) |

**To update the server, push to `main`.** Railway builds `npm start` (`node server.js`),
waits for `/health` to pass and only then swaps it in. A build that can't start never
replaces the running one. To roll back, go to Railway → Deployments → the previous
green one → **Redeploy**.

Tables are created and migrated automatically on boot (`migrate()`). At startup the
server also runs `EXPLAIN` on the verify statement, so broken SQL fails the deploy
instead of locking customers out.

### Secrets

- **`CLIENT_SHARED_SECRET`**
  - Sent by the app as `X-Client-Secret`. It's compiled into `src-tauri/src/license.rs`
    and must be identical on both sides, or every app gets "Unauthorized client".
  - It ships inside the app, so it's only a filter against random traffic, not a real
    boundary.
- **`ADMIN_SECRET`**
  - The real boundary. Never put it in the app, this repo or a chat.
  - The dashboard keeps it only in that browser tab's `sessionStorage`.

## Data

**`licenses`**

| Column | Meaning |
| --- | --- |
| `license_key` | `AFK-XXXX-XXXX-XXXX`, the only format. `/verify` refuses any other shape without touching the database |
| `hwid` | The PC fingerprint it's locked to; `NULL` until first activation |
| `hw_parts` | The same PC part by part (`mg`, `vol`, `cpu`, `cores`, `host`, each an opaque hash), so a small hardware change isn't "another PC" |
| `status` | `active` or `revoked` |
| `expires_at` | `NULL` = never expires |
| `created_at`, `last_seen_at`, `last_seen_ip` | Bookkeeping |

**`license_events`**

- **Recorded:** creation, first activation, `device_updated` (same PC after a hardware
  change), every refusal (wrong device, expired, revoked) with the device that tried, and
  every admin action.
- **Not recorded:** routine successful check-ins, and unknown keys.
- History survives a deleted key (there's no foreign key). Events are pruned after
  180 days.

### How `/verify` decides

- One SQL statement does everything: it looks up the key, binds an unbound key to this
  device, and writes the event.
- Twenty simultaneous activations of one fresh key bind exactly once (the race test
  covers this).
- **Same PC after a change:** if the digest differs but `afk_parts_match` recognises
  the PC, the check passes and the key is rebound to the new digest. That means the same
  Windows install (`mg`) plus at least two more matching parts, so a renamed PC, a CPU
  swap or a new disk still works. A different PC, or a fresh Windows install, needs
  **Reset device**.
- **Responses:** `"License activated."` with `expires_at`, or a refusal message
  (wrong device, expired, revoked, unknown).

## Admin dashboard

Open https://license.lootbloxy.com/ and enter `ADMIN_SECRET` once per tab. The lock icon
clears it.

- **Overview:**
  - active/revoked bar;
  - tiles for online now, expiring within 7 days, never used, activations and
    wrong-device attempts in the last 24 h (each tile filters the table).
- **Last 14 days chart:** activations, keys created and refused checks per day.
- **Search** by key, device or IP. **Filter** by status, expiring, online or never used.
  25 per page.
- **Create keys:** 1–100 at once with an optional duration, plus **Copy all** and
  **Download .txt**.
- **Per key:**
  - inline: Revoke / Reactivate, expiry;
  - in the ⋯ menu: History, Extend +30 days / +1 year (keys that expire), Reset device,
    Delete.
- **Bulk:** tick keys (or the header box for the page), then Copy keys, Revoke,
  Reactivate, Extend +30 days, Reset device or Delete.
- **Activity:** recent activity across all keys. **Export CSV** of the current view.
- **Auto-refresh** every 30 s (remembered per browser, paused while you work), with an
  "Updated Xs ago" label.
- **Shortcuts:** `/` search, `N` new key, `R` refresh, `Esc` close. Click any key to copy it.

## Admin API

Every call needs the header `X-Admin-Secret: $ADMIN_SECRET`. Replace `$K` with a key.

```bash
S=https://license.lootbloxy.com
H="X-Admin-Secret: $ADMIN_SECRET"
J="Content-Type: application/json"

# create one key (optional expires_in_days or expires_at) / many (count 1-100)
curl -X POST $S/admin/licenses -H "$H" -H "$J" -d '{"expires_in_days":30}'
curl -X POST $S/admin/licenses -H "$H" -H "$J" -d '{"count":25,"expires_in_days":30}'

# list (limit, offset, status=active|revoked|expired|expiring|online|unused, q=key/device/ip)
curl -H "$H" "$S/admin/licenses?limit=50&status=online&q=203.0.113"

# stats / per-day activity (days 7-90, UTC) / CSV export (same filters as list)
curl -H "$H" $S/admin/stats
curl -H "$H" "$S/admin/stats/daily?days=30"
curl -H "$H" "$S/admin/export.csv?status=expiring" -o expiring.csv

# one key
curl -X POST   $S/admin/licenses/$K/revoke     -H "$H"
curl -X POST   $S/admin/licenses/$K/unrevoke   -H "$H"   # back to active
curl -X POST   $S/admin/licenses/$K/reset-hwid -H "$H"   # let it activate on a new PC
curl -X POST   $S/admin/licenses/$K/extend     -H "$H" -H "$J" -d '{"days":30}'
curl -X POST   $S/admin/licenses/$K/expiry     -H "$H" -H "$J" -d '{"expires_in_days":30}'  # or {"expires_at":null}
curl           $S/admin/licenses/$K/events     -H "$H"
curl -X DELETE $S/admin/licenses/$K            -H "$H"

# recent activity, all keys
curl -H "$H" "$S/admin/events?limit=50"

# many keys at once (up to 200): revoke | reactivate | extend (+days) | reset-hwid | delete
curl -X POST $S/admin/licenses/bulk -H "$H" -H "$J" \
  -d '{"action":"extend","days":30,"keys":["AFK-AAAA-BBBB-CCCC"]}'
```

**Details:**

- **Extend** adds days to the current expiry, or to today if the key has lapsed. It
  refuses never-expiring keys.
- **Bulk** replies `{ok, requested, changed}`. Keys already in the target state are
  skipped.
- **CSV** cells that start with `= + - @` are prefixed with `'` (formula-injection guard).

## Hardening

- The client IP is the right-most `X-Forwarded-For` hop (the one Railway appended),
  normalised and length-capped.
- **Rate limits:** `/verify` 30/min/IP, `/admin/*` 60/min/IP. They're in-process; if this
  is ever scaled past one replica, move them to a shared store such as Redis.
- **Requests:** 4 kb body limit; key and hwid length caps.
- **Responses:** `X-Frame-Options: DENY`, `nosniff`, `no-referrer` and gzip.
- **Caching:** `latest.json` is `no-store`; installers get long immutable caching.
- **Database:** bounded pool with timeouts.
- **Shutdown:** SIGTERM drains in-flight requests on redeploy.

## Testing

`test/run-tests.js` starts the real `server.js` against a real Postgres and drives it over
HTTP. It covers device binding, the bind race, same-PC-after-a-change matching, both key formats, expiry
and extend, bulk actions, history, stats and daily stats, export, rate limits and gzip.
**Run it before every push. It must end with 0 failures.**

```bash
npm install
createdb afkstrike_test
TEST_DATABASE_URL=postgresql://localhost:5432/afkstrike_test npm test
```

It deletes every license in the database it's given, so it refuses to run unless the
database name contains `test` and differs from `DATABASE_URL`.

## Running locally

```bash
npm install
export DATABASE_URL=postgresql://localhost:5432/afkstrike_license_dev
export CLIENT_SHARED_SECRET=dev-secret
export ADMIN_SECRET=dev-admin-secret
npm start            # http://localhost:3000
```

The server reads `process.env` only. `.env.example` is just a template.
