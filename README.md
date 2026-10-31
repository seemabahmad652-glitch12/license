# AfkStrike license server

The self-hosted license check behind AfkStrike's key screen, plus the files the app's
auto-updater downloads. A small Node/Express app on Postgres, deployed on Railway at
**https://afkstrikelicense.up.railway.app**. It isn't part of the desktop app's build.

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
| Railway | project `afkstrike-license` → service `license-server` → env `production` |
| Database | Railway Postgres, attached as `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` |
| Domain | `afkstrikelicense.up.railway.app` (Railway's own domain and TLS) |
| Variables | `DATABASE_URL`, `CLIENT_SHARED_SECRET`, `ADMIN_SECRET`, `LICENSE_SIGNING_KEY` (`PORT` is injected) |

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
- **`LICENSE_SIGNING_KEY`**
  - Base64 of a 32-byte Ed25519 seed. Every "yes" from `/verify` includes a `token`
    signed with it: the key's hash, the device, the expiry, the issue time and the
    app's one-time nonce. Every "no" includes a `denial` signed the same way: the key's
    hash, the device, the nonce and the reason. The app checks both with the public key
    compiled into `license.rs`, so a fake server can neither unlock the app nor lock a
    customer out, and a replayed answer or an edited offline stamp is refused. The server
    won't start without it, and logs its public key at boot.
  - Changing it means releasing the app with the new public key.
- **`ADMIN_SECRET`**
  - The real boundary. Never put it in the app, this repo or a chat.
  - The dashboard keeps it in that browser tab's `sessionStorage`, or in `localStorage`
    if "Keep me signed in" is ticked.

## Data

**`licenses`**

| Column | Meaning |
| --- | --- |
| `license_key` | `AFK-XXXX-XXXX-XXXX`, the only format. `/verify` refuses any other shape without touching the database |
| `hwid` | The PC fingerprint it's locked to; `NULL` until first activation |
| `hw_parts` | The same PC part by part (`mg`, `vol`, `cpu`, `cores`, `host`, each an opaque hash), so a small hardware change isn't "another PC" |
| `status` | `active` or `revoked` |
| `expires_at` | When it stops working. `NULL` = never, unless `duration_days` is set |
| `duration_days` | The length of time it was sold for. With `expires_at` `NULL` the key is **waiting**: its first activation sets `expires_at` to that many days later |
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
- **Responses:** `"License activated."` with `expires_at` and the signed `token`, or a refusal
  message (wrong device, expired, revoked, unknown) with the signed `denial`.

## Admin dashboard

Open https://afkstrikelicense.up.railway.app/ and sign in with `ADMIN_SECRET`. The lock icon
signs out. The top bar's **New keys** creates 1–100 keys: pick **1d, 7d, 30d, 90d, 365d,
Lifetime** or a custom number of days, and whether the clock starts **on first activation**
(the default) or **right now**.

- **Overview:** a tile per count (each opens the filtered list), activity by day over 14, 30
  or 90 days, **Needs a look** (keys another PC keeps trying, or whose device keeps being
  reset), recent activity.
- **Keys:** search by key, device or IP, filter, sort, 25/50/100 per page, **Export CSV**.
  Click a key to copy it; click its row for its details: time left, first activation,
  wrong-device tries, PCs seen, history, and every action on it.
- **Bulk:** tick keys (or the header box for the page), then Copy, Add time, Set duration,
  Revoke, Reactivate, Reset device or Delete.
- **Activity:** every key's history, filtered by Activations, Refused or Admin changes, or by key.
- **Backup & system:** download every key; restoring only adds keys that are missing, so it
  can't undo a revoke or give back used time. Database and uptime figures, and the signing
  public key to compare with the app's.
- **Refresh** every 30 s, paused while you work. **Shortcuts:** `/` search, `N` new keys,
  `R` refresh, `Esc` close.

## Admin API

Every call needs the header `X-Admin-Secret: $ADMIN_SECRET`. Replace `$K` with a key.

```bash
S=https://afkstrikelicense.up.railway.app
H="X-Admin-Secret: $ADMIN_SECRET"
J="Content-Type: application/json"

# create one key / many (count 1-100). duration: "30d" or "lifetime".
# starts: "activation" (default here) or "now".
curl -X POST $S/admin/licenses -H "$H" -H "$J" -d '{"duration":"30d"}'
curl -X POST $S/admin/licenses -H "$H" -H "$J" -d '{"count":25,"duration":"7d","starts":"now"}'

# list (limit, offset, sort=created|expires|seen, q=key/device/ip,
# status=active|revoked|expired|expiring|online|unused|waiting|lifetime).
# How many match in all is in the X-Total-Count header.
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
curl -X POST   $S/admin/licenses/$K/expiry     -H "$H" -H "$J" -d '{"duration":"90d"}'  # starts defaults to "now" here
curl           $S/admin/licenses/$K            -H "$H"   # the row plus its history's totals
curl           $S/admin/licenses/$K/events     -H "$H"
curl -X DELETE $S/admin/licenses/$K            -H "$H"

# recent activity, all keys (type=activations|refused|admin, key=..., before=<id> for older)
curl -H "$H" "$S/admin/events?limit=50"

# keys worth a look / server figures
curl -H "$H" $S/admin/attention
curl -H "$H" $S/admin/system

# backup, and restore (adds missing keys only)
curl -H "$H" $S/admin/backup.json -o backup.json
curl -X POST $S/admin/restore -H "$H" -H "$J" --data-binary @backup.json

# many keys at once (up to 200): revoke | reactivate | extend (+days) | set-duration | reset-hwid | delete
curl -X POST $S/admin/licenses/bulk -H "$H" -H "$J" \
  -d '{"action":"extend","days":30,"keys":["AFK-AAAA-BBBB-CCCC"]}'
```

**Details:**

- **Extend** adds days to the current expiry, or to today if the key has lapsed. A waiting
  key gets a longer duration. It refuses never-expiring keys.
- **Bulk** replies `{ok, requested, changed}`. Keys already in the target state are
  skipped.
- **CSV** cells that start with `= + - @` are prefixed with `'` (formula-injection guard).

## Hardening

- The client IP is Railway's `X-Real-IP` header, normalised and length-capped.
  `X-Forwarded-For` is only a fallback for local runs: on Railway a caller can set it to
  anything. This is only right while nothing sits in front of Railway: put Cloudflare or
  another proxy in front and every customer behind it would share one rate-limit bucket.
- **Rate limits:** `/verify` 30/min/IP, `/admin/*` 300/min/IP, and 10 wrong admin secrets per
  5 min/IP lock that address out. They're in-process; if this is ever scaled past one
  replica, move them to a shared store such as Redis.
- **Requests:** body limits of 4 kb, 64 kb for `/admin/*` and 8 mb for `/admin/restore`; key
  and hwid length caps.
- **Responses:** `X-Frame-Options: DENY`, `nosniff`, `no-referrer` and gzip.
- **Caching:** `latest.json`, `/verify` and `/admin/*` are `no-store`; installers get long
  immutable caching.
- **Database:** bounded pool with timeouts.
- **Shutdown:** SIGTERM drains in-flight requests on redeploy.

## Testing

`test/run-tests.js` starts the real `server.js` against a real Postgres and drives it over
HTTP. It covers device binding, the bind race, same-PC-after-a-change matching, the key format,
durations, signed refusals, expiry and extend, bulk actions, history, key details, backup and
restore, stats and daily stats, export, rate limits, the admin lockout and gzip.
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
