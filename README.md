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

## Key format: `AFK-XXXX-XXXX-XXXX` (59th pass)

New keys are a fixed `AFK` prefix and three groups of four, from the same
alphabet as before (no `0 1 I L O`). The prefix carries no entropy; the 12
random characters give about 7.9 × 10¹⁷ keys, which against `/verify`'s 30
checks a minute per address is not guessable. Generation now uses
`crypto.randomInt`, which is exactly uniform - the previous `byte % 31`
slightly favoured the first eight letters.

**Keys sold before this (`XXXXX-XXXXX-XXXXX-XXXXX`) keep working
unchanged.** `/verify` matches the stored string exactly and never parses
a key's shape, so the format is only ever decided at creation. Nothing is
migrated. The test suite inserts an old-format key the way the old
generator stored it and checks it still activates, device-locks and can
be managed. The desktop app accepts both: its key box draws the `AFK-`
prefix itself, and switches to the old layout when an old key is pasted.

## Key history, bulk keys and renewals (58th pass)

**Per-key history.** A new `license_events` table records everything
that *changes or refuses* something: creation, first activation, the
legacy-id migration, every rejection (wrong device, expired, revoked,
banned) - with the device that tried - and every admin action (revoke,
ban, reactivate, device reset - with the device released - expiry
change, extend, delete). It answers the question every support
conversation starts with, "it stopped working, what happened?", which
previously had no answer beyond a single `last_seen_at`.

Three deliberate choices:

- **Routine successful check-ins are not recorded.** Every running
  install checks in every five minutes; logging those would bury the
  events that matter, and `last_seen_at` already has them.
- **Unknown keys are never recorded**, so nobody can grow the table by
  sending garbage keys.
- **No foreign key to `licenses`**, so a key's history survives the key
  being deleted - which is exactly when a chargeback or a "you deleted
  my key" dispute needs it. The deletion is itself the last entry.

Events are pruned after 180 days, which covers a typical chargeback
window with room to spare.

**/verify is still one round trip.** The event is written by a
data-modifying CTE inside the same statement that does the bind, not by
a second query. The event name is computed once from the outcome and
the INSERT filters on it being non-null, so "should this be logged" and
"what is logged" can't disagree - a mismatch there would be a NOT NULL
violation that fails the whole statement, i.e. locks a customer out over
a logging bug. Admin actions likewise write the change and its history
entry in one statement, so the two can never come apart.

**Bulk keys.** `POST /admin/licenses` takes an optional `count` (1-100)
and returns `{ "created": [...] }`. Without `count` the response is the
single bare row exactly as before, so existing scripts are unaffected.
A batch is one `INSERT ... SELECT FROM unnest(...) ON CONFLICT DO
NOTHING`, with any collision regenerated, so 100 keys is one round trip.

**Renewals.** `POST /admin/licenses/:key/extend` with `{"days": N}` adds
days to the *current* expiry, or to today if the key has already lapsed
- so renewing an expired key gives the full period from now, not a
period partly already gone. It refuses a key that never expires: there's
nothing to add to, and silently turning a lifetime key into a 30-day one
would be the worst possible reading of "extend". (`/expiry` still sets
an absolute expiry, counted from now.)

**Richer stats, filters and search.** `/admin/stats` adds `online`
(checked in within 10 minutes - the app re-checks every 5),
`expiringSoon` (≤ 7 days), `neverUsed`, `created7d`, `activations24h` and
`deviceRejections24h`, all from one pass with `FILTER` clauses; the
original fields are unchanged. `/admin/licenses?status=` also takes
`expiring`, `online` and `unused`, and `?q=` now matches the device
digest and last IP as well as the key - "which key is this PC on?" used
to need hand-written SQL.

**CSV export.** `GET /admin/export.csv` takes the same `status`/`q`
filters and returns every matching key (no pagination). Cells starting
with `= + - @` are prefixed with `'`: `last_seen_ip` and `hwid` arrive
from the network, and an export is something you open in Excel without
thinking - that's formula injection waiting to happen.

The verify success message is now `"License activated."` (was `"Device
unlocked."`), matching the desktop app's new key-entry screen.

## Testing

`npm test` runs the real `server.js` against a real Postgres and drives
it over HTTP, the way the desktop app does - checks across device
binding, the bind race, legacy migration, expiry, bulk keys, history,
stats, export, rate limiting and both key formats (48 checks).

```bash
createdb afkstrike_test
TEST_DATABASE_URL=postgresql://localhost:5432/afkstrike_test npm test
```

**It deletes every license in the database it's given**, so it refuses
to run unless the database name contains `test` and differs from
`DATABASE_URL`. Never point it at production.

The race test is the one that matters most and is the subtle one. It
fires twenty activations of one fresh key at once and requires exactly
one to bind. On its own that proves nothing: each UPDATE commits in
microseconds, so the requests never actually overlap and the test passes
even against the known-broken query. So it installs a trigger that holds
the row lock for 150 ms, making the other nineteen take their snapshots,
see "unbound", and queue behind the lock - the exact condition under
which gating on a CTE snapshot lets a second device bind. **Verified
both ways:** against the real query, 1 of 20 binds; against the broken
one planted in a copy, 10 of 20 do and the test fails.

This suite has been run, all passing - the first time this server's SQL
had ever executed. It caught a real bug before it shipped: a doubled
`)` in the new `/verify` statement that made **every** activation
return "Internal error". Deployed, that would have locked out every
customer at once. It parsed fine as JavaScript; only running the SQL
against Postgres could show it.

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

- **Overview** - the key population as one bar (active/revoked;
  banned only appears while an older banned key exists) plus health tiles: online now, expiring within 7 days, never
  used, activations and wrong-device attempts in the last 24 hours.
  Each tile is also a shortcut to that filter on the table.
- **Search + filter** - search by key, device digest or IP; filter by
  status or by expiring / online / never used; 25 per page.
- **Create keys** - one, or up to 100 at once with **Copy all** and
  **Download .txt** (one key per line, ready to paste into Discord).
- **Per-key actions** - Revoke/Unrevoke and Expiry inline; History,
  Extend +30 days / +1 year (only offered for keys that expire), Reset
  device and Delete behind the ⋯ menu. **No Ban** - Revoke does the same
  job; a key banned before that change shows "Reactivate key" instead.
- **Select several keys** (checkboxes, or the header box for the whole
  page) and act on them at once: Copy keys, Revoke, Reactivate, Extend
  +30 days, Reset device, Delete - via `POST /admin/licenses/bulk`. The
  toast says how many changed and how many were skipped (already in that
  state, never-expiring, unbound).
- **Last 14 days** chart - activations, keys created and refused checks
  per day (`GET /admin/stats/daily`), from the history so deleted keys
  still count; hover a day for its numbers.
- **Auto-refresh** (top right, remembered per browser) - every 30 s,
  paused while a dialog is open, keys are selected or you're typing in
  search. "Updated Xs ago" beside it.
- **Shortcuts** - `/` search, `N` new key, `R` refresh, `Esc` close.
- **Key history** - a timeline of everything that happened to a key.
- **Recent activity** - the same timeline across every key.
- **Export CSV** - whatever the current filter and search show.
- Click any key to copy it.

Restyled in the 58th pass from magenta to the desktop app's own indigo
(`#7c5cfc`), so the two read as one product. Tested end to end in a real
browser against a real server and database - 20 checks, including the
batch download, history, extend, export and a phone-width layout.

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

**Create a key** (body optional; `expires_in_days` or `expires_at`):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"expires_in_days": 30}'
```
Returns `{"id", "license_key", "status", "created_at", "expires_at"}`.
The `license_key` (`AFK-XXXX-XXXX-XXXX`) is what the customer types into the app.

**Create many** (1-100; returns `{"created": [...]}`):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H "Content-Type: application/json" \
  -d '{"count": 25, "expires_in_days": 30}'
```

**Extend a key** (adds to the current expiry, or to today if lapsed;
refused for a never-expiring key):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/extend \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H "Content-Type: application/json" \
  -d '{"days": 30}'
```

**A key's history / recent activity across all keys:**
```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" https://license.lootbloxy.com/admin/licenses/XXXXX-XXXXX-XXXXX-XXXXX/events
curl -H "X-Admin-Secret: $ADMIN_SECRET" "https://license.lootbloxy.com/admin/events?limit=50"
```

**Export as CSV** (same `status`/`q` filters as the list):
```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" "https://license.lootbloxy.com/admin/export.csv?status=expiring" -o expiring.csv
```

**List keys** (paginated, newest first; optional `status` - one of
`active`/`revoked`/`banned`/`expired`/`expiring`/`online`/`unused` - and
`q`, which matches the key, device digest or last IP, case-insensitive):
```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" \
  "https://license.lootbloxy.com/admin/licenses?limit=50&offset=0&status=online&q=203.0.113"
```

**Summary counts** (what the dashboard's overview shows - the original
totals plus `online`, `expiringSoon`, `neverUsed`, `created7d`,
`activations24h`, `deviceRejections24h`):
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

**Ban a key** - still accepted by the API for compatibility, but no
longer offered in the dashboard: revoke does the same job (`/verify`
rejects either way). Only its rejection message differs:
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

**Act on many keys at once** (up to 200; `action` is `revoke`,
`reactivate`, `extend` (with `days`), `reset-hwid` or `delete`; replies
`{ ok, requested, changed }`, each changed key recorded in its history):
```bash
curl -X POST https://license.lootbloxy.com/admin/licenses/bulk \
  -H "X-Admin-Secret: $ADMIN_SECRET" -H "Content-Type: application/json" \
  -d '{"action":"extend","days":30,"keys":["AFK-AAAA-BBBB-CCCC","AFK-DDDD-EEEE-FFFF"]}'
```

**Activity per day** (`days` 7-90, default 14; UTC days, oldest first):
```bash
curl "https://license.lootbloxy.com/admin/stats/daily?days=30" -H "X-Admin-Secret: $ADMIN_SECRET"
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
