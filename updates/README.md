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

## Every release after that

1. **Bump the version** in `src-tauri/Cargo.toml` (`version = "..."`)
   and `src-tauri/tauri.conf.json` (`"version": "..."`) - these two
   must match.
2. **Build the installer**:
   ```bash
   cargo tauri build
   ```
   This produces an `.exe` (NSIS) and/or `.msi` under
   `src-tauri/target/release/bundle/`.
3. **Sign it** with the private key from setup:
   ```bash
   cargo tauri signer sign -k ~/.tauri/afkstrike-update.key \
     path/to/AfkStrike_<version>_x64-setup.exe
   ```
   This writes a `.sig` file next to the installer - its contents are
   the `signature` value for the manifest below (not the file path,
   the actual text inside the `.sig` file).
4. **Upload the installer itself** into this `updates/` folder (so it
   ends up at `https://license.lootbloxy.com/updates/<filename>`) -
   commit it to the repo (if this folder is small/occasional) or
   upload it directly to the running Railway volume/deploy, whichever
   this project's deploy process already uses for `license-server`.
5. **Update `latest.json`** in this folder:
   ```json
   {
     "version": "<new version, no leading v>",
     "notes": "<short changelog line shown in the update modal>",
     "pub_date": "<UTC timestamp, e.g. 2026-03-01T12:00:00Z>",
     "platforms": {
       "windows-x86_64": {
         "signature": "<contents of the .sig file from step 3>",
         "url": "https://license.lootbloxy.com/updates/<installer filename>"
       }
     }
   }
   ```
   The `windows-x86_64` key must match the target the installer was
   built for - this project only ships Windows builds (`nsis`/`msi` in
   `tauri.conf.json`'s `bundle.targets`), so that's the only platform
   key this manifest needs.
6. **Deploy** (push/redeploy `license-server` the same way as any
   other change to it). The next time anyone launches the app, their
   copy's `current_version` (whatever they're running) will be older
   than this `version`, and the update modal will offer it.

## Testing locally

Point `src-tauri/tauri.conf.json`'s `plugins.updater.endpoints` at a
local file server (e.g. `python3 -m http.server` in this folder)
temporarily, or just lower the `version` in this `latest.json` below
whatever your dev build reports, to confirm the modal appears - then
set it back before deploying for real.
