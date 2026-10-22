# SoundTrail-ServerSide

Self-hosted sync and audio server for the SoundTrail Android app. The app's
`/v1/youtube/audio` request is served by [`server/`](server/), which this repo runs
on its own.

## Run the server

```bash
cd server
python3 run.py          # creates .venv, installs pinned deps, starts the API
python3 run.py --test   # runs the API test suite
```

The API listens on `127.0.0.1:8080` by default. For a machine that other devices
reach directly, set `SOUNDTRAIL_HOST=0.0.0.0` and `PORT` as needed. The app requires
HTTPS, so put a TLS reverse proxy in front of the API (see
[`server/Caddyfile.example`](server/Caddyfile.example)). Full documentation, including
the HTTP API, backups, and configuration, is in [`server/README.md`](server/README.md).

Quick check of the YouTube audio endpoint (after signing up and getting a token):

```bash
curl -X POST https://sync.example.net/v1/youtube/audio \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"videoId":"VIDEO_ID","authorized":true}' -o audio.m4a
```

`authorized: true` confirms that you own the audio or have permission to download it.
Only one video ID per request is accepted.

## Point the app at this server

In the SoundTrail app, open the sync settings and enter this server's HTTPS address in
**Sync server URL (HTTPS)**, for example `https://sync.example.net`, then sign in or
create an account there. The app sends `/v1/youtube/audio` requests to that address.

The app's built-in default is the public server `https://soundtrail.duckdns.org`
(`DEFAULT_SYNC_SERVER` in `app/src/main/java/tech/egrie/soundtrail/sync/CloudSyncService.kt`
in the `SoundTrail` repo). Changing that constant to your own address makes it the default
for every install, which is a change to the app repo, not this one.

## Tests

CI (`.github/workflows/server.yml`) runs `python -m unittest discover -s server` on
Python 3.10 and 3.14. The suite uses only the standard library and does not install yt-dlp.
