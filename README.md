# SoundTrail ServerSide

Self-hosted sync and audio server for the **SoundTrail** Android app, which saves songs as
private, location-based pins. It was moved out of the app repository
([`mob5824m-wq/Soundtrail`](https://github.com/mob5824m-wq/Soundtrail)) so it can be
deployed, versioned, and released on its own; the Android client still speaks the API
described below, and its `/v1/youtube/audio` request is served from here.

The service provides Soundtrail account sessions, an end-to-end-encrypted sync log with encrypted checkpoints, and an optional audio-only YouTube extraction endpoint. Deploy it on infrastructure you control, behind HTTPS.

The repository is flat: the service entry point is [`app.py`](app.py), the launcher is
[`run.py`](run.py), managed backups live in [`backup.py`](backup.py), and the API tests are
`test_app.py` and `test_backup.py`. There is no build step and no Docker requirement.

## What the server can see

For cloud sync, the Android app encrypts each entity event and checkpoint on-device with AES-256-GCM. The server cannot decrypt pins, coordinates, playlist details, automation rules, song links, or the recovery key. It does see account email addresses, salted password hashes, session metadata, event IDs/sequences, ciphertext sizes, client IPs in proxy/server logs, and request timing.

The separate YouTube audio endpoint is **not end-to-end encrypted**: when used, the server receives a video ID, requests a public audio-only stream, and temporarily stores the resulting audio in a per-request directory under `/tmp` while returning it to the app. Temporary files are removed when the response finishes or fails, and folders left behind by a crash are swept at the next start; only directories the service created and that are older than an hour in the system temp folder are removed. The server does not receive YouTube cookies, Google OAuth tokens, or a YouTube Music app session. Extraction uses the third-party `yt-dlp` project and is unofficial; it may break when YouTube changes. It does not handle private/age-restricted videos, logins, cookies, DRM, or access-control bypasses. Use it only for audio you own or have explicit permission to download, and follow the rules that apply to your content and location. Soundtrail asks the user to confirm permission before requesting extraction; the server cannot independently verify rights.

Keep the machine, database volume, TLS proxy, backups, logs, and `/tmp` storage secured. The database has a **64 MiB per-account quota** for encrypted sync events and checkpoints. Event rows are pruned into an encrypted client checkpoint after sync; retry-receipt metadata is also pruned at that point. Old delivery IDs may therefore be accepted again after compaction, but encrypted entity clocks and tombstones make duplicate old versions harmless. Snapshots are limited to 8 MiB.

The server applies in-process sliding-window limits to account creation, login, sync reads/writes, checkpoints, account deletion, and extraction; extraction also has a two-job concurrency cap. Current defaults are 5 account creations/hour/IP, 20 logins/minute/IP, 600 sync reads and writes/minute/IP, 10 checkpoints/minute/IP, 5 account deletions/hour/IP, and 30 extraction requests/minute/IP plus 20/minute/account. In-process limits reset on restart and are per instance, so keep the API behind a reverse proxy with its own request/body limits and rate limiting, especially if you run multiple workers. Each connection is also limited to 30 seconds of inactivity: a client that opens a request and stalls while sending its body gets `408 Request Timeout` and the socket is closed, so slow clients cannot hold worker threads open. Normal requests are small and complete far sooner; a very slow link uploading an 8 MiB snapshot may need a proxy with a larger upstream timeout. The app trusts `X-Forwarded-For` only when its direct peer is private/loopback; configure the proxy to overwrite or sanitize client-supplied forwarding headers before passing them upstream. Sign-in failures are also tracked per submitted address (10 failures in 15 minutes locks that address for 15 minutes, returning `429` with `Retry-After`), keyed on the address even when no account exists so the lockout cannot be used to discover which addresses are registered. The IP limits alone cannot stop a distributed attempt against one account. There is no email verification or password-reset service. An authenticated account-deletion endpoint is available.

## Run natively (no Docker, any OS and CPU)

The server is plain Python. It runs on Linux, macOS, Windows, and BSD, on x86-64, ARM64, and other CPUs with a Python 3.10+ interpreter. Docker is not required.

1. Point a DNS name such as `sync.example.net` at your server.
2. Install Python 3.10 or newer (`python3 --version`, or `py -3 --version` on Windows).
3. Optional, for YouTube audio extraction only: install [FFmpeg](https://ffmpeg.org/download.html) and make `ffmpeg` available on `PATH`.
4. Clone this repository and start the service from its root folder:

   ```bash
   git clone https://github.com/mob5824m-wq/SoundTrail-ServerSide.git
   cd SoundTrail-ServerSide
   python3 run.py          # Windows: py -3 run.py
   ```

   `run.py` creates a private `.venv`, installs the pinned dependencies, and starts the API. The first run downloads packages; later runs start immediately. Other commands:

   - `python3 run.py --setup` prepares the environment without starting the server.
   - `python3 run.py --test` runs the API test suite.

5. Put a reverse proxy with TLS in front of it. The API listens on `127.0.0.1:8080` by default. Keep that loopback default and proxy to it, for example with [`Caddyfile.example`](Caddyfile.example) (Caddy runs on the same machine, so the upstream is `127.0.0.1:8080`). The example needs Caddy 2.5 or newer for `request_body`; it caps uploads at the edge and overwrites `X-Forwarded-For` with the proxy's own view of the client. Do not expose port 8080 directly.

The SQLite database is created at `data/soundtrail.sqlite3`. Set `SOUNDTRAIL_DB` to store it elsewhere (for example on a dedicated disk). Schema changes are versioned in a `schema_meta` table and run once per database; startup work is skipped on later starts instead of rescanning the stored event log every time.

## Managed backups

The service backs up its own database. A daemon thread takes a consistent copy through SQLite's
online backup API at startup and then every 24 hours, verifies it with `PRAGMA integrity_check`,
writes a SHA-256 sidecar, and deletes older snapshots beyond the retention count. The snapshot and its
rename into place are fsynced, so a crash just after a backup reports success cannot lose it. Snapshot
files are named `soundtrail-YYYYmmdd-HHMMSS-ffffff.sqlite3` and live in `<database folder>/backups` by
default.

At startup the thread reuses an existing snapshot when it is already newer than the interval **and**
newer than every database file, instead of writing another. Restarting the service repeatedly (a deploy
loop, a crash loop, a reboot storm) would otherwise produce one full copy per restart and prune away the
real history, keeping only the last few restarts under the retention count. A database that was written
to or recreated after the snapshot still gets a fresh copy, so a restored or replaced database is never
mistaken for a recent backup.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SOUNDTRAIL_BACKUP_DIR` | `<database folder>/backups` | Where snapshots and their `.sha256` sidecars are written. |
| `SOUNDTRAIL_BACKUP_INTERVAL_SECONDS` | `86400` | Seconds between automatic snapshots. `0` turns the thread off (for example when an external backup tool owns the database). |
| `SOUNDTRAIL_BACKUP_KEEP` | `7` | How many snapshots remain after a successful backup. |

The same code works from the command line, with or without the virtual environment:

```bash
python3 run.py backup                 # write and verify a snapshot now
python3 run.py list                   # newest first, with sizes and checksum state
python3 run.py verify                 # verify the newest snapshot
python3 run.py verify soundtrail-20261019-120000-000000.sqlite3
python3 run.py restore NAME --yes     # replace the live database (see below)
```

`restore` verifies the snapshot's checksum and integrity first, takes a safety snapshot of the
current database, then replaces it. **Stop the service before restoring** and start it again
afterwards. The command refuses to run without `--yes`, and a name that is not a bare snapshot
file in the backup folder is rejected, so it cannot read or overwrite an arbitrary path.
Pass the exact name that `list` printed.

A snapshot is the whole database, not the decrypted library: sync payloads stay AES-256-GCM
ciphertext. It still contains account email addresses, password hashes, session metadata, event
metadata, and ciphertext sizes, exactly as the live database does. Treat the backup folder as
sensitive (`0o700` is applied where the platform supports it), keep it on a volume only the
service user can read, and copy snapshots off-host. Backups on the same disk do not survive a
lost volume or a hosting account closure.

### Run as a background service

Use your platform's service manager so the API restarts after reboots. Run it as a dedicated, unprivileged user.

**Linux (systemd)**: save as `/etc/systemd/system/soundtrail-sync.service`, adjusting `User`, `WorkingDirectory`, and the paths:

```ini
[Unit]
Description=Soundtrail encrypted sync API
After=network-online.target
Wants=network-online.target

[Service]
User=soundtrail
Group=soundtrail
WorkingDirectory=/opt/soundtrail
Environment=SOUNDTRAIL_HOST=127.0.0.1
Environment=PORT=8080
Environment=SOUNDTRAIL_DB=/var/lib/soundtrail/soundtrail.sqlite3
ExecStart=/usr/bin/python3 /opt/soundtrail/run.py
Restart=on-failure
# systemd sends SIGTERM first (handled as a graceful stop) and only escalates after this.
TimeoutStopSec=30

# Optional hardening. These keep the service to its own folder and a private /tmp, where
# YouTube extraction writes; nothing else on the host becomes writable to it.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/var/lib/soundtrail

[Install]
WantedBy=multi-user.target
```

Then run `sudo systemctl daemon-reload && sudo systemctl enable --now soundtrail-sync`.

Create the data folder first and give it to the service user (`sudo install -d -o soundtrail -g soundtrail -m 700 /var/lib/soundtrail`),
and keep the repository readable but not writable by that user. Because `ReadWritePaths` lists only the data
folder, snapshots written elsewhere (`SOUNDTRAIL_BACKUP_DIR`) would fail under `ProtectSystem=strict` unless
they are also under `/var/lib/soundtrail` or added to `ReadWritePaths`.

`SIGTERM` and `SIGINT` close the listener, then give requests already in progress up to ten seconds to
finish, so an upload in flight is answered instead of dropped. After that the background backup thread is
asked to stop (waiting up to five seconds for a snapshot in progress) and the process exits with status 0,
so `systemctl stop`, `docker stop`, and Ctrl-C all shut down cleanly. New connections are refused as soon
as the stop begins, and the unit's `TimeoutStopSec` caps the whole sequence.

**macOS (launchd)** and **Windows** (Task Scheduler, or a service wrapper such as NSSM): run `python3 run.py` (or `py -3 run.py`) from the repository folder at boot, with the working directory set to it, and set `SOUNDTRAIL_HOST`/`SOUNDTRAIL_DB` as environment variables for that task.

### Back up the database

The service already writes and verifies its own snapshots — see [Managed backups](#managed-backups)
above. Those copies are taken through SQLite's online backup API, so the service does not need to
be stopped, and each one is checksummed and pruned.

A whole-folder archive is still useful before an upgrade or when moving hosts. Stop the service
and archive the database plus its WAL side-files:

```bash
# Linux/macOS, from the server folder, with the service stopped
mkdir -p /secure/offsite && chmod 700 /secure/offsite
tar -czf /secure/offsite/soundtrail-data.tar.gz -C . data
```

On Windows, stop the task and copy the `data` folder to a safe location. To restore an archive,
stop the service, keep a copy of the current folder, and replace the `data` folder (or the
`SOUNDTRAIL_DB` location) with the archived contents. Test restoration, and keep an off-host copy
outside the server's own volume.

The `/health` endpoint reports liveness only and does not read or write the database, so it is safe
for proxy and container health checks; there is no readiness or metrics endpoint. On startup the service
also removes leftover extraction folders older than an hour from the system temp folder. Extraction needs
outbound network access to YouTube and enough temporary disk space for up to two concurrent 250 MiB
downloads plus working files.

### Dependencies

- `requirements.txt` — `yt-dlp` (pure Python), used only by the optional YouTube audio endpoint.
- `requirements-js.txt` — `deno`, a JavaScript runtime for yt-dlp's YouTube challenge solver. It is optional: Deno publishes wheels for Linux x86-64/ARM64 (glibc), macOS x86-64/ARM64, and Windows x86-64 only. On other platforms `run.py` skips it; install Deno or Node.js yourself and it will be used from `PATH`.
- FFmpeg — installed separately (see step 3).

Update the pins deliberately, then re-test extraction after upstream changes.

## HTTP API

`/health` is a public liveness endpoint; the application endpoints are under `/v1`:

- `POST /accounts` — `{ "email": "…", "password": "…" }`, creates the account and returns `accountId`, `email`, `token`, and `expiresAt`.
- `POST /sessions` — same body, authenticates and returns a new bearer token.
- `DELETE /sessions/current` — revokes the current bearer session.
- `DELETE /account/current` — deletes the authenticated account, sessions, sync events, receipts, and checkpoint. This cannot be undone.
- `GET /events?after=<sequence>&limit=<1..500>` — returns opaque encrypted events, cursor information, and (when the caller is behind) the latest encrypted checkpoint plus events after it.
- `POST /events` — `{ "events": [{ "id": "UUID", "iv": "base64url", "ciphertext": "base64url" }] }`.
- `POST /snapshots` — stores a client-encrypted full-state checkpoint through a server cursor, then prunes covered event rows.
- `POST /youtube/audio` — authenticated JSON `{ "videoId": "…", "authorized": true }`; after the user's rights confirmation, returns a raw audio-only file. Only one YouTube video ID is accepted; playlists and video downloads are not supported.

Each account's cursor is independent and every sync read/write is scoped to that account. Checkpoints are encrypted and authenticated by the client; the server cannot inspect their contents. Event delivery is idempotent until a checkpoint compacts the corresponding receipt metadata. Passwords are stored as per-account salted scrypt hashes (`scrypt$32768$8$1$32` by default: 32 MiB and roughly 0.1 s per hash, so 128 MiB peak across the four hashes allowed at once); the work factor is recorded per account, so raising it applies to existing accounts at their next successful login instead of locking anyone out. Random session tokens expire after 30 days and are stored server-side only as SHA-256 hashes. Responses carry `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `default-src 'none'` content policy, and `Cache-Control: no-store`.

## Configuration

- `PORT` — listen port (default `8080`).
- `SOUNDTRAIL_HOST` — listen address (default `127.0.0.1`; keep it on loopback behind a TLS proxy).
- `SOUNDTRAIL_DB` — SQLite file (default `data/soundtrail.sqlite3`).
- `SOUNDTRAIL_BACKUP_DIR` — snapshot folder (default `<database folder>/backups`).
- `SOUNDTRAIL_BACKUP_INTERVAL_SECONDS` — seconds between automatic snapshots (default `86400`; `0` disables the background thread).
- `SOUNDTRAIL_BACKUP_KEEP` — snapshots retained after a successful backup (default `7`).
- `SOUNDTRAIL_PASSWORD_KDF_LOG2` — scrypt work factor for new passwords, as log2(N) (default `15`, clamped to `12`–`17`). Each step doubles the memory and time per hash: 2^15 is 32 MiB and about 0.1 s, 2^17 is 128 MiB and about 0.4 s. Existing accounts keep their recorded factor and are upgraded on next login.
- `SOUNDTRAIL_PASSWORD_KDF_CONCURRENCY` — how many password hashes may run at once (default `4`, clamped to `1`–`8`). This bounds peak memory: `4 × 32 MiB = 128 MiB` at the default work factor. The startup log prints both the scheme and the peak.

The API intentionally has no password-reset or key-recovery endpoint. If a user loses their 256-bit recovery key, resetting the account password cannot recover encrypted content. Account deletion removes remote encrypted data; it does not erase the user's local device library. If the database is lost, only a database backup can restore the encrypted event log and checkpoints.

## Security

The database, its WAL side-files, and a database folder the service creates itself are tightened to
`0600`/`0700` on startup and on every connection (POSIX), because SQLite otherwise creates them
world-readable under a typical umask and they hold email addresses and password hashes. Snapshots are
written `0600` into a `0700` folder. If you point `SOUNDTRAIL_DB` at a folder that already exists, it is
left alone — check its mode yourself.

Deploy this only on infrastructure you control, behind the TLS proxy described above, and keep the
database, backup folder, logs, and `/tmp` readable only by the service user. The service never needs
root; the running process writes only to its database folder, backup folder, and the system temp folder
(the launcher's first-run virtual environment lives in the repository folder), and makes no outbound
connection except to YouTube for the optional audio endpoint.

Before exposing an instance, check that: the API is bound to loopback and not reachable directly; the
proxy terminates TLS and caps request bodies; the host firewall allows 443 only; backups are copied
off-host; `yt-dlp`/Deno pins are updated deliberately and extraction is re-tested afterwards; the
account-deletion and login rate limits fit your expected traffic; and the password work factor fits the
server's memory (see `SOUNDTRAIL_PASSWORD_KDF_*` above).

Known limits, stated plainly: a self-hosted server sees who syncs when, and a malicious server can
withhold or replay ciphertext — end-to-end encryption protects content, not availability or metadata.
The client is responsible for rejecting rolled-back snapshots and for treating deletions as its own
decision rather than trusting the server's absence of an event. Login lockout and rate limits are
in-process constants, so they reset on restart and are per instance.

The Android client has to match this server's behaviour to get the benefit of it — status codes, the
sign-in lockout, redirects, and the limits above. [`docs/android-client-hardening.md`](docs/android-client-hardening.md)
holds a paste-ready prompt for that repository, written against its actual files.

To report a vulnerability, do **not** open a public issue. Use GitHub's private
[security advisory](https://github.com/mob5824m-wq/SoundTrail-ServerSide/security/advisories/new) form
and include the affected commit, how the instance is deployed, and reproduction steps. There is no
paid bounty and no guaranteed response time, but reports are read and acted on.

## Run the API tests

```bash
python3 run.py --test   # or: python3 -m unittest discover -s . -v
```
