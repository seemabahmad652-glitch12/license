# afkstrike license server

A small, self-hosted replacement for the KeyAuth-backed "Device
locked" gate the afkstrike desktop app shows before anything else. This
is a standalone Node/Express app, **not** part of the Tauri build - it
runs as its own service (on Railway, or anywhere else that runs Node +
Postgres) and the desktop app talks to it over HTTPS.

See the main project's `README.md` ("Licensing" section) for how this
fits into the bigger picture (which commands in the desktop app call
this, when, and why). This file is just about running and operating
*this* folder.

## What it does

One table (`licenses`) in Postgres:

| column | meaning |
| --- | --- |
| `license_key` | unique, generated server-side, `XXXXX-XXXXX-XXXXX-XXXXX` format |
| `hwid` | the device this key is bound to - `NULL` until the first successful check, then locked to that value |
| `status` | `active` (default), `revoked`, or `banned` |
| `note` | free text for your own records (who bought it, order id, etc.) |
| `created_at` / `last_seen_at` / `last_seen_ip` | bookkeeping |

**`POST /verify`** is the only *licensing* route the desktop app calls.
Every other `/admin/*` route is one you call yourself - either with
curl (see below) or through the built-in **admin dashboard** at this
server's root URL (see "Admin dashboard" below). Separately, the
desktop app's auto-updater also `GET`s `/updates/latest.json` on every
launch - see `updates/README.md` for that (publishing a release, not
license management, so it's documented on its own over there rather
than mixed into the table/routes below).

## Live deployment (as of the 55th pass)

This is already deployed - the section below ("Deploying on Railway")
is the from-scratch procedure and is kept for reference, but you do
not need to run it again for the existing service.

| | |
|---|---|
| Railway project | `lootbloxy` |
| Service | `license-server` |
| Environment | `production` |
| Database | Railway Postgres (`Postgres` service), attached as `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` |
| Railway URL | `https://license-server-production-c2f5.up.railway.app` |
| Intended URL | `https://license.lootbloxy.com` (see "Custom domain") |
| Healthcheck | `/health` (now checks Postgres too, not just "is Node up") |

`CLIENT_SHARED_SECRET` and `ADMIN_SECRET` are set as Railway variables
on that service. `CLIENT_SHARED_SECRET` is also compiled into the
desktop app (`src-tauri/src/license.rs`) and the two must stay
identical - changing one without the other locks every client out with
"Unauthorized client." `ADMIN_SECRET` is never shipped in the client;
it is only typed into the admin dashboard or passed to curl.

### Custom domain

The desktop app points at `license.lootbloxy.com`, not the
`*.up.railway.app` hostname, so that Railway can be swapped out later
without rebuilding and reshipping the client. The domain is already
registered on the Railway service; it needs these two DNS records at
whoever hosts lootbloxy.com's DNS before it will serve traffic:

| Type | Name | Value |
|---|---|---|
| CNAME | `license` | `wrcsq3ab.up.railway.app` |
| TXT | `_railway-verify.license` | `railway-verify=328fbbeed328ad782ec0401d4e5479dbe58225896d7405e973ed01a32e25ec28` |

The TXT record proves ownership so Railway will issue the TLS
certificate; the CNAME is what actually routes traffic. Until both
resolve, `https://license.lootbloxy.com/verify` will not answer and
the app's license gate will fail closed (which is the correct
behaviour - it is not a bug in the client).

### Redeploying

The service builds from a connected GitHub repository, so shipping a
change to this folder is `git push` - Railway rebuilds and redeploys on
its own. No client rebuild is needed for a server-side change, and no
restart is needed to publish an app update (see `updates/README.md`).

## Hardening applied in the 55th pass

Worth knowing about because two of these change observable behaviour:

- **`X-Forwarded-For` is read from the right-most hop, not the
  left-most.** This was a real vulnerability, not a preference.
  `X-Forwarded-For` is a list each proxy *appends* to, so the
  left-most entry is whatever the caller sent - fully attacker
  controlled. Every `last_seen_ip` recorded before this change is
  therefore untrustworthy, and anything keyed off that value would
  have been trivially bypassable. The right-most entry is the one
  Railway's own proxy appended. The value is also now normalised to
  IP-shaped characters and length-capped before being stored.
- **Rate limiting on `/verify` (30/min/IP) and `/admin/*`
  (60/min/IP).** There was none before: `ADMIN_SECRET` could be
  guessed as fast as requests could be sent, and the license keyspace
  could be walked at full speed. This is an in-process fixed-window
  counter, not a dependency - **if this service is ever scaled past
  one replica, it must be replaced with a shared store (Redis), since
  each replica would otherwise enforce its own window and the
  effective limit would multiply by the replica count.**
- **`/verify` is one database round trip instead of two**, and the
  first-device bind now happens inside the same statement that tests
  for it. The old SELECT-then-UPDATE had a window where two launches
  of the same key on two different machines could both observe
  "unbound" and both bind - handing out two activations for a
  one-device key.
- `/health` now fails with 503 if Postgres is unreachable, so it is
  usable as Railway's healthcheck.
- Indexes on `status` and `created_at` for the dashboard's own
  queries; bounded connection pool with explicit timeouts; a 4kb body
  limit and length caps on `key`/`hwid`; `X-Frame-Options: DENY`,
  `nosniff` and `no-referrer` on responses; `no-store` on
  `updates/latest.json` and long immutable caching on the installers
  beside it; and SIGTERM handling so a redeploy drains in-flight
  requests instead of severing them.

## Key expiry (56th pass)

Keys can now carry an optional expiry. `expires_at IS NULL` means
"never expires", which is what every key issued before this feature
existed is - so it arrived switched off for all of them rather than
silently expiring anyone.

Expiry is **orthogonal to `status`**: a key can be `active` and expired
at the same time. That is deliberate - it keeps "I revoked this" and
"this lapsed" as separate facts you can tell apart later. The dashboard
shows both (an `Active` pill next to an `Expired` pill), and its status
filter offers `expired` as a pseudo-status that filters on the
timestamp rather than the `status` column.

Enforcement lives in `/verify`'s own UPDATE guard
(`AND (l.expires_at IS NULL OR l.expires_at > now())`), not in a
separate check afterwards. That matters: an expired key never reaches
the bind, so it can neither claim a new device nor refresh
`last_seen_at` - it is rejected before touching anything.

Setting an expiry, on create or afterwards, takes either
`expires_in_days` or `expires_at` (ISO timestamp):

```bash
# a key valid for 30 days
curl -X POST "$BASE/admin/licenses" \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{"expires_in_days":30}'

# extend (or set) an existing key's expiry
curl -X POST "$BASE/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/expiry" \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{"expires_in_days":365}'

# remove the expiry entirely (back to "never expires")
curl -X POST "$BASE/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/expiry" \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{"expires_in_days":0}'
```

`0` days means "no expiry" rather than "expires immediately" - issuing
a dead key by accident should not be one keystroke away.

### `note` was removed

The `note` field is gone from this API and from the dashboard: create
no longer accepts it, the list no longer returns it, and `?q=` now
searches the key only.

**The database column is deliberately still there.** Dropping it would
irreversibly destroy any notes already stored, so that is left as a
decision for you rather than something a deploy did silently. Once you
are sure nothing in there matters:

```sql
ALTER TABLE licenses DROP COLUMN note;
```

## Hardware-bound device lock (57th pass)

The device lock used to compare a random UUID the client persisted in
`device_id.txt`. That was the weak point of the whole scheme: the id
was not derived from anything, so copying one small text file onto a
second PC alongside the key gave that PC the same identity, and the
server - which can only compare what it is sent - had no way to tell
them apart. One purchased key could be shared indefinitely.

Clients now send a SHA-256 fingerprint of machine-stable values
(Windows `MachineGuid`, the system volume serial, CPU identifier and
core count, computer name). Only the digest is sent, so this database
stores nothing identifying about a customer's hardware.

**Existing customers are migrated, not locked out.** A client that
still has the old file sends it as `legacy_hwid` alongside the new
`hwid`; a stored value matching *either* is accepted, and the row is
then rebound to the new fingerprint. After that one migration the old
value no longer unlocks anything - verified in testing, including that
replaying a migrated key's old UUID from a different machine is
rejected.

Deliberately excluded from the fingerprint: MAC addresses, IP, and
anything else that legitimately changes on a machine the customer
still owns (docks, VPNs, Wi-Fi vs ethernet). A fingerprint that drifts
locks out paying customers, which is a worse failure than a determined
sharer getting through.

`/verify` also now returns `expires_at` on success, so the desktop app
can render its own "License time left" readout without a second
endpoint.

### `note` is now fully removed

Earlier the column was left in place. It is now dropped outright by the
startup migration (`ALTER TABLE licenses DROP COLUMN IF EXISTS note`).
**This is irreversible** - any text that was stored there is gone.

## Deploying on Railway

1. **Push this repo to GitHub** if it isn't already there (Railway
   deploys from a GitHub repo).
2. **New Railway project → Deploy from GitHub repo**, pick this repo.
3. **Set the service's Root Directory to `license-server`.** This repo
   has the Tauri app at its root and this server in a subfolder -
   without this setting Railway will try to build the wrong thing (or
   fail to find `package.json`). In the Railway dashboard: select the
   service → **Settings** → **Root Directory** → `license-server`.
4. **Attach Postgres**: in the project, click **+ New** → **Database**
   → **Add PostgreSQL**. Railway provisions it and exposes its own
   `DATABASE_URL`.
5. **Wire the database to this service**: on the license-server
   service's **Variables** tab, click **New Variable** → **Add
   Reference** → pick the Postgres service's `DATABASE_URL`. Don't
   paste a connection string by hand - a reference stays correct if
   Railway ever rotates credentials.
6. **Set the two secrets** on the same Variables tab:
   - `CLIENT_SHARED_SECRET` - any long random string (e.g. the output
     of `openssl rand -hex 32`). This must be copied *exactly* into the
     `CLIENT_SHARED_SECRET` constant in
     `src-tauri/src/license.rs` on the desktop app side.
   - `ADMIN_SECRET` - a **different** long random string. Keep this
     one to yourself - it's what lets you create/revoke/manage license
     keys. Never put it in the desktop app.
   Don't set `PORT` - Railway injects it automatically, and the server
   reads it from the environment.
7. **Deploy.** Railway builds from `package.json`'s `start` script
   (`node server.js`). Once it's up, Railway shows you a public URL
   (Settings → Networking → Generate Domain if one isn't assigned
   yet).
8. **Optional but recommended - put this on your own domain.** Since
   lootbloxy.com is already owned, point a subdomain at this service
   instead of shipping the raw `*.up.railway.app` URL in the desktop
   app: Settings → Networking → Custom Domain → enter
   `license.lootbloxy.com` (or similar) → Railway gives you a CNAME
   target → add that CNAME record at your DNS provider. This makes the
   backend swappable later without rebuilding the client - only the
   DNS record changes. Check it's alive (swap in the raw
   `*.up.railway.app` URL instead if skipping the custom domain for
   now):
   ```bash
   curl https://license.lootbloxy.com/health
   # {"status":"ok"}
   ```
   The `licenses` table is created automatically on first boot (see
   `migrate()` in `server.js`) - there's no separate migration step to
   run by hand.
9. **Point the desktop app at it**: in `src-tauri/src/license.rs`, set
   - `LICENSE_SERVER_URL` to `https://license.lootbloxy.com/verify`
     (or the raw `*.up.railway.app` URL + `/verify` if skipping the
     custom domain) - note the `/verify` suffix, the constant is the
     full endpoint URL, not just the host
   - `CLIENT_SHARED_SECRET` to the exact same string you set in step 6
   then rebuild the app (`cargo tauri build`). These are compiled-in
   constants, read once at compile time - changing the Railway-side
   value later means rebuilding the client too, same as rotating any
   other embedded secret.

## Running it locally (optional, for testing)

```bash
cd license-server
npm install
# set env vars - either export them or use a tool like `dotenv-cli`;
# this server does NOT read a .env file on its own, only
# process.env - .env.example is a template for your own tooling, not
# consumed automatically
export DATABASE_URL=postgresql://localhost:5432/afkstrike_license_dev
export CLIENT_SHARED_SECRET=dev-secret-change-me
export ADMIN_SECRET=dev-admin-secret-change-me
npm start
```

Needs a real Postgres reachable at `DATABASE_URL` - a local Postgres
install, Docker (`docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres`),
or a free-tier hosted instance all work.

## Admin dashboard

A small, self-contained admin page (`public/index.html`, plain
HTML/CSS/JS, no build step) is served at this server's **root URL** -
open `https://license.lootbloxy.com/` (or your Railway URL) in a
browser and it's right there. It drives the exact same `/admin/*`
routes documented below, just with buttons instead of curl:

- **Stat cards** - total keys, active/revoked/banned counts,
  device-bound count.
- **Search + status filter** - search by key or note, filter to
  active/revoked/banned, paginated 25 at a time.
- **Create a key** (with an optional note) - shows the new key once,
  click to copy.
- **Per-key actions** - Revoke/Unrevoke, Ban/Unban, Reset device
  (clears a bound hwid so the customer can activate elsewhere),
  Delete (asks for confirmation first).
- Click any key in the table to copy it to the clipboard.

It asks for the `ADMIN_SECRET` once per browser tab (kept in that
tab's `sessionStorage` only - gone on tab close, never sent anywhere
but this server) and sends it as the `X-Admin-Secret` header on every
call, same as the curl examples below. The page itself has nothing
sensitive in it; without the real secret every action just gets a 401.
Use the lock icon (top right) to clear it and switch secrets.

## Admin API (curl examples)

All of these require `X-Admin-Secret: <your ADMIN_SECRET>`. None of
them are called by the desktop app - these are for you (or a
storefront's backend, if you build one later) to run after a sale, or
by the admin dashboard above if you'd rather click than type.

**Create a key:**
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"note": "order #1234, buyer@example.com"}'
```
Returns `{"id", "license_key", "status", "note", "created_at"}`. The
`license_key` is what the customer types into the app's gate.

**List keys** (paginated, newest first; optional `status` and `q`
filters - `status` is one of `active`/`revoked`/`banned`, `q` matches
the key or note, case-insensitive, same params the dashboard's search
box and status dropdown use):
```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" \
  "https://license.lootbloxy.com/admin/licenses?limit=50&offset=0&status=active&q=order%20%231234"
```

**Summary counts** (total/active/revoked/banned/device-bound - what the
dashboard's stat cards show):
```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" https://license.lootbloxy.com/admin/stats
```

**Revoke a key** (customer's app stops working immediately on its next
check - within `LICENSE_RECHECK_SECS` (5 minutes) even if the bot is
already running, or instantly on the next launch/Start click):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/revoke \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

**Un-revoke a key** (back to `active`):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/unrevoke \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

**Ban a key** (same effect on `/verify` as revoke - rejected either
way - but its own status and its own rejection message, for a harder,
more deliberate block like abuse or a shared/leaked key rather than an
ordinary refund):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/ban \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

**Un-ban a key** (back to `active` - functionally identical to
`/unrevoke`, kept as its own endpoint so the dashboard's "Unban" button
has a route of its own name to call):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/unban \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

**Reset a key's bound device** (lets a customer activate on a new PC
after a reinstall or hardware change - without this there's no
legitimate way back in short of you editing the database by hand):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/reset-hwid \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

**Delete a key entirely** (permanent - prefer `revoke` unless you
specifically want the row gone):
```bash
curl -X DELETE https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

## Security notes

- `CLIENT_SHARED_SECRET` is **not** the real security boundary - it
  ships inside the desktop app binary, so anyone can extract it the
  same way they could extract a KeyAuth app secret. It's a cheap filter
  against random internet traffic hitting `/verify`, nothing more. The
  actual boundary is this server deciding, against its own database,
  whether a key is valid - that decision never leaves this process.
- `ADMIN_SECRET` **is** a real security boundary - it's never shipped
  anywhere, so keep it as secret as you'd keep a database password.
  The admin dashboard asks for it client-side and keeps it only in
  that browser tab's `sessionStorage`; it's never written into the
  page's own source or sent anywhere but this server's `/admin/*`
  routes. Anyone with the server's URL can *load* the dashboard page,
  but without the real secret every action it tries still 401s - the
  page itself holds nothing worth protecting on its own.
- The dashboard is served over plain HTTP from this app's point of
  view (TLS is terminated by Railway in front of it, same as every
  other route here - see below), so the secret you type into it is
  encrypted in transit the same way a curl call to `/admin/*` already
  is.
- This server does not implement its own rate limiting. Railway's
  platform-level protections aside, consider adding a rate limiter
  (e.g. `express-rate-limit`) on `/verify` if you expect this to be a
  target for key-cracking attempts at any real volume.
- TLS: Railway terminates HTTPS for you at the edge - this app itself
  speaks plain HTTP on `PORT`, which is the normal pattern for a
  service running behind Railway's proxy.
