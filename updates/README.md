# Publishing an update

This folder is served as-is at `https://license.lootbloxy.com/updates/`
(see the `/updates` static mount in `server.js`). The desktop app's
updater checks `latest.json` here on every launch - see the main
project README's "Auto-updates" section for how that works from the
Rust/UI side. This file is just about producing and publishing a new
release.

## One-time setup: a signing keypair

Tauri's updater refuses to install anything that isn't signed with a
minisign keypair you control - this is what stops `latest.json` (or
the installer it points to) from being a way to push arbitrary code
if this server, or the DNS for its domain, were ever compromised.

```bash
cargo tauri signer generate -w ~/.tauri/afkstrike-update.key
```

This prints a **public key** - paste it into
`src-tauri/tauri.conf.json`'s `plugins.updater.pubkey` and rebuild the
app once. The matching **private key** is written to the `-w` path
above; back it up somewhere safe (a password manager, not this repo)
and never commit it. Every future release is signed with this same
private key - losing it means every installed copy of the app can
never accept another update, short of everyone manually reinstalling
with a new pubkey baked in.

## Every release after that: `release.ps1`

From the AfkStrike project folder, in PowerShell:

```powershell
.\release.ps1 -Version 0.2.0 -Notes "Auto replies and a faster sniper" -Push
```

It bumps the version in `tauri.conf.json` and `Cargo.toml`, runs
`cargo tauri build` (which signs the installer itself - `tauri.conf.json`
has `"createUpdaterArtifacts": true`), copies
`AfkStrike_<version>_x64-setup.exe` into this folder, writes
`latest.json` with the signature, keeps only the last two installers,
and with `-Push` commits and pushes this repo. Railway redeploys, and
every installed copy offers the update the next time it starts.

- The signing key is read from `~/.tauri/afkstrike-update.key` (or
  `-KeyPath`, or an existing `TAURI_SIGNING_PRIVATE_KEY`). It asks for
  the key's password.
- `-LicenseRepo` is your clone of this repo; it defaults to a
  `license` folder next to the project.
- Leave out `-Push` to look at the files first; it prints the three git
  commands to run.
- The version must be higher than the current one - an installed copy
  only ever moves up.

### By hand, if you'd rather

1. Bump `version` in `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`
   (they must match).
2. Set `TAURI_SIGNING_PRIVATE_KEY` (the key file's contents or path) and
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, then `cargo tauri build`. You get
   `src-tauri/target/release/bundle/nsis/AfkStrike_<version>_x64-setup.exe`
   and, next to it, `...setup.exe.sig`.
3. Copy the `.exe` into this folder.
4. Update `latest.json` here - the `signature` is the text inside the
   `.sig` file, not its path:
   ```json
   {
     "version": "<new version, no leading v>",
     "notes": "<one line shown in the update window>",
     "pub_date": "<UTC, e.g. 2026-11-01T12:00:00Z>",
     "platforms": {
       "windows-x86_64": {
         "signature": "<contents of the .sig file>",
         "url": "https://license.lootbloxy.com/updates/<installer filename>"
       }
     }
   }
   ```
   Save it as UTF-8 **without** a byte-order mark (Notepad's "UTF-8", not
   "UTF-8 with BOM") - the updater won't read a manifest that starts with
   one.
5. Commit and push this repo; Railway redeploys.

## Testing locally

Point `src-tauri/tauri.conf.json`'s `plugins.updater.endpoints` at a
local file server (e.g. `python3 -m http.server` in this folder)
temporarily, or just lower the `version` in this `latest.json` below
whatever your dev build reports, to confirm the modal appears - then
set it back before deploying for real.
