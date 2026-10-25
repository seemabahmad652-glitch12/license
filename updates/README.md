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

## Lost the private key?

`.\release.cmd -NewKey` makes a new keypair and puts its public half
into `tauri.conf.json`. Any copy already installed with the old public
key will refuse updates signed by the new one, so those users install
the next version by hand, once; everything built from then on updates
normally. Back the new key up somewhere that isn't this repo.

## Every release: double-click `release.cmd`

In the AfkStrike project folder, double-click **`release.cmd`**. It asks
one thing - **what's new** (one line; separate items with `;` and each
becomes a tick in the update window). The version is automatic:

- **Nothing published yet:** it releases the version the app already has
  (0.1.0) - no bump.
- **After that:** the next number after what's live (0.1.0 -> 0.1.1 ->
  0.1.2 ...). To jump further, change `version` in `tauri.conf.json` (and
  `Cargo.toml`) first, or run `release.cmd -Version 0.2.0`.

Then it sets the version, builds and signs the installer, copies it
here with a fresh `latest.json`, and pushes this repo. Railway redeploys
in about a minute, and every installed copy offers the update the next
time it starts. It asks for the signing key's password during the build.

The first time it runs it also:
- downloads this repo next to the project (and remembers where, in
  `release.config.json`), and
- offers to make a signing key if there isn't one at
  `~/.tauri/afkstrike-update.key`.

Needs: Rust + `cargo install tauri-cli --version "^2.12" --locked`, and
Git signed in to GitHub.

Command-line form, same thing without the questions:

```powershell
.\release.cmd -Version 0.2.0 -Notes "Auto replies and a faster sniper" -Push
```

`release.cmd` runs `release.ps1` with Windows' downloaded-script check
bypassed for that one run ("is not digitally signed" otherwise), without
changing any system setting. Leave out `-Push` to look at the files
before publishing.

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
