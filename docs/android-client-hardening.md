# Client hardening: paste-ready prompt for the Android repo

This server's transport, credential, header, and account-session hardening only pays off if the client
matches it. Hand the prompt below to whoever (or whatever agent) works in
[`mob5824m-wq/Soundtrail`](https://github.com/mob5824m-wq/Soundtrail). It is written against that
repository's real code: `sync/CloudSyncService.kt`, `integrations/Http.kt`, `integrations/SecretStore.kt`,
and the two backup-rule XML files.

It assumes this server's current behaviour (status codes, lockout, headers, limits, and the session and
password endpoints) as described in the [HTTP API](../README.md#http-api),
[Configuration](../README.md#configuration), and [Security](../README.md#security) sections. Nothing in it
requires a server change: everything it asks for is supported by the endpoints already deployed.

---

## Prompt (copy everything below this line)

Harden the Soundtrail Android client to match the newly hardened sync server and to close the
remaining client-side gaps. Work on your own branch, keep the existing no-third-party-HTTP-dependency
style, and change no user-visible behaviour except where explicitly listed below. Do not touch the
Jellyfin flow's ability to use plain HTTP on a home network — that is intentional and must keep working.

### Context: what the server now does (already implemented, do not re-add server code)

- All API responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'`, `Cache-Control: no-store`.
- **`429 Too Many Requests`** with a `Retry-After` header (seconds) is now returned for:
  - rate limits (per IP: sign-ups, logins, sync reads/writes, checkpoints, deletions, extraction), and
  - **a new per-address sign-in lockout**: 10 failed sign-ins for the same email in 15 minutes locks
    that address for 15 minutes. The lockout applies even when no account exists for the address, so it
    says nothing about whether the account is real.
- **`408 Request Timeout`** is returned when a request body stalls (30 s socket timeout).
- **`507 Insufficient Storage`** means the account's 64 MiB encrypted-sync quota is full.
- **New account endpoints** (added for this work; the app does not use them yet):
  - `GET /v1/session/current` → `{ accountId, email, sessionId, createdAt, expiresAt }` for the caller.
  - `GET /v1/sessions` → `{ sessions: [{ id, createdAt, expiresAt, current }], maxSessions }`,
    newest first. Ids only — a token is never returned again after sign-in.
  - `DELETE /v1/sessions/<sessionId>` → `{ revoked, signedOut }`. Revokes one device. Another account's
    id answers `404`, exactly like an id that does not exist; a malformed id answers `400`.
  - `POST /v1/sessions/current/renew` → `{ token, expiresAt, sessionId }`. The old token stops working
    immediately and the session id changes.
  - `POST /v1/account/current/password` → body `{ currentPassword, newPassword }`, response
    `{ changed, revokedSessions, token, expiresAt, sessionId }`. **Every** session is signed out,
    including the caller's, and the new token in the response is the only surviving one. `403` means the
    current password is wrong, `400` means the new one is too short or identical to the current one.
- Sign-in and account-creation responses now also carry `sessionId`.
- **`400`** for malformed payloads (including a new "nested too deeply" case), **`401`** expired/refused
  session, **`403`** missing extraction permission, **`409`** email already registered, **`413`** body or
  audio too large, **`422`** extraction failed, **`503`** extractor busy, **`502`** audio source
  unreachable.
- `DELETE /v1/sessions/current` and `DELETE /v1/account/current` are unchanged.
- No response shape changed; `accountId`, `email`, `token`, `expiresAt`, `events`, `nextCursor`,
  `hasMore`, `snapshot`, `snapshotThrough`, `latestSequence`, `eventCount`, `accepted` are as before.

### Required changes

**1. `sync/CloudSyncService.kt` — status-code handling and retries (`api()` and callers)**

- Replace the string-matching quota detection in `sync()`
  (`e.message.orEmpty().contains("storage limit")`) with an explicit signal. Add a typed error, e.g.
  `class CloudSyncException(message: String, val status: Int? = null)`, set `status` from the HTTP code,
  and branch on `status == 507` instead of on message text. Keep the existing behaviour: on 507 push,
  compact the history once and retry the covered events; if compaction does not help, surface the error.
- Handle `429` explicitly: parse `Retry-After` (whole seconds), surface a friendly message that includes
  the wait ("Too many attempts. Try again in N minutes."), and for **sign-in** do not retry
  automatically — return control to the UI. For ordinary sync requests, retry at most twice with the
  server's `Retry-After` honoured (capped at 60 s) plus jitter.
- Retry `408` and `502`/`503`/`504` at most twice with exponential backoff plus jitter (base 1 s, cap 8 s).
- Never retry non-idempotent calls blindly: `POST /v1/accounts` and `POST /v1/sessions` must not be
  retried on ambiguous failures (timeout, no response). `POST /v1/events` may be retried **only** with
  the same event IDs — the server is idempotent per event ID — which is already how `pushPending` works.
- Treat any `3xx` as an error; keep `instanceFollowRedirects = false` in `integrations/Http.kt` and add a
  unit test asserting a redirect response becomes a `CloudSyncException`, never a silent host change.

**2. `sync/CloudSyncService.kt` — registration must never strand the user**

- In `createAccount`, if the request fails **after** the account may have been created (timeout, no
  response, `408`), do not present the error as "wrong password". The account may exist with a recovery
  key the app never received. Return a message that offers both paths: sign in (the app can still adopt a
  new key on the empty-account path in `sync()`) or try another email.
- On `409`, make the message actionable: "That email already has an account on this server. Sign in
  instead." and make sure the UI can switch to sign-in with the email prefilled.
- Never persist a token or key before `acceptAccount` validates that `accountId` and `token` are present
  (already true — add a test that locks it in).

**3. Backup exclusions and secret storage — verify and pin with tests**

- Confirm `soundtrail_secrets.xml`, `soundtrail_cloud_sync.xml`, `soundtrail_google_auth.xml`,
  `soundtrail_youtube.xml`, `soundtrail_settings.xml`, `audio/`, and `managed-backups/` remain excluded in
  **both** `res/xml/backup_rules.xml` and `res/xml/data_extraction_rules.xml` (cloud-backup and
  device-transfer blocks). Adding a new preference file that can hold a credential requires adding an
  exclude in both files — state this in a comment.
- Add a JVM unit test (or a Robolectric-free XML assertion test if that is the existing pattern) that
  fails if a file containing `token`, `secret`, `password`, or `recovery` in its name is ever included
  rather than excluded.
- Confirm `SecretStore` continues to use Keystore-backed encryption with no plaintext fallback, and that
  `disconnect()` / `deleteAccount()` remove the token **and** the recovery key.

**4. Never log credential material**

- Audit for `Log.`/`println` of: `Authorization` headers, request/response bodies of `/v1/sessions` and
  `/v1/accounts`, tokens, recovery keys, and the plaintext of any sync payload. Use `if (BuildConfig.DEBUG)`
  guards for anything diagnostic and redact headers as `Bearer ***`.
- Add a test or a lint-style check that `httpRequest` never logs its `authorization` argument.

**5. Cleartext traffic is scoped in code, not just in the XML**

`res/xml/network_security_config.xml` sets `cleartextTrafficPermitted="true"` for **all** hosts because a
self-hosted Jellyfin server may be plain HTTP on the LAN. Keep that, and add a small helper (e.g.
`integrations/EndpointPolicy.kt`) with a single rule that every **non-Jellyfin** integration — sync
server, Spotify, SoundCloud, YouTube, AudioDB, mood AI, any user-entered URL — must use `https://`, and
that `http://` is allowed only for Jellyfin. Add unit tests for: sync server accepts `https://…`, rejects
`http://…`, rejects `https://user:pass@host`, rejects `..` path segments (already implemented in
`normalizeServer` — keep the tests), and Jellyfin still accepts `http://192.168.1.20:8096`.

**6. Recovery key display hardening**

- The screen that shows the recovery key (`recoveryKeyForDisplay()`) must set `FLAG_SECURE` while the key
  is visible, so it cannot be screenshotted or appear in the recents thumbnail, and must clear the flag
  when leaving.
- Copying the key must mark the clipboard entry sensitive:
  `ClipDescription.EXTRA_IS_SENSITIVE = true` (API 33+) with a graceful fallback, and clear the clip after
  a short timeout if the platform allows.
- Require the user to reauthenticate (BiometricPrompt with device-credential fallback) before re-displaying
  a stored key; show it once at account creation as today.

**7. Detect a rolled-back server history instead of trusting it**

- The pull path already validates cursor ordering and snapshot consistency. Add one more check: persist
  the highest `latestSequence` seen for the current `owner_account_id` + `owner_server` pair, and if a
  later response reports a **lower** `latestSequence` than that, do not silently continue. Server restores
  from backup are legitimate, so present it as a warning — "This server's history is older than this
  device's last sync (it may have been restored from a backup)" — and allow the user to continue, which
  re-pushes the local journal (event IDs make the re-push idempotent).

**8. Respect the server's input limits before sending**

- Assert locally, before upload, that each batch has at most **100** events
  (`PUSH_BATCH_SIZE` already caps this — enforce it with a `require`), each `iv` decodes to exactly 12
  bytes, each ciphertext stays under **1 MiB**, and a snapshot stays under **8 MiB**. A local failure
  message beats a server `400`/`413`.

**9. Sign out other devices, and know your own session (`GET /v1/sessions`, `DELETE /v1/sessions/<id>`)**

- In the Connect tab, list `GET /v1/sessions` with "This device" on the entry where `current` is true and
  the rest labelled by creation date (the server stores no device name, so do not invent one). Offer
  "Sign out" per non-current entry.
- After `DELETE /v1/sessions/<id>`, refresh the list. If the id you revoked was somehow the current one
  (`signedOut: true`), treat it exactly like `DELETE /v1/sessions/current`: clear the token and key, keep
  local data.
- Store the `sessionId` from sign-in/registration so the list can mark the current device without an
  extra request.

**10. Renew the token instead of being logged out mid-use (`POST /v1/sessions/current/renew`)**

- Before a sync (and on app start when `expiresAt` is within 7 days), call
  `GET /v1/session/current`; if the token is close to expiry, renew it and **atomically replace** the
  stored token and `sessionId`. The old token is dead the moment the response is produced, so a crash
  between the call and the write loses the session: write the new token in the same `edit().commit()` as
  the session id, and re-read `GET /v1/session/current` on next start to detect a lost session.
- Do not renew on every request — it invalidates the token each time. Once per day at most, plus when
  `expiresAt` is within 7 days.
- If renewal returns `401`, fall back to the existing "session expired, sign in again" path. Never retry
  it automatically with the old token.

**11. Change the password from the app (`POST /v1/account/current/password`)**

- Add "Change password" to the Connect tab: current password, new password, confirm new password. Enforce
  the server's rules client-side too (10–128 characters, must differ from the current one) so the user
  gets the message before a round trip.
- On success, replace the stored token and `sessionId` with the returned pair **before** showing the
  success message: every other device is now signed out, and the returned token is the only working one.
- Make the consequence explicit in the UI: "All other devices have been signed out." If the user changes
  the password on a device that is *not* the one holding the recovery key, the key is unaffected — the
  password is authentication only, it never decrypts anything. Say so, so nobody thinks a password change
  rotates the encryption key.
- On `403`, say "That is not your current password" (not "wrong password", which reads like a login
  failure) and keep the form open. On `400`, show the server's message.
- If the outcome is unknown (timeout, `408`, connection dropped), do **not** claim success or failure:
  tell the user to sign in again, because the server may have completed the change and revoked this
  device's session. Then check `GET /v1/session/current` and, if it fails, show the sign-in screen with
  the email prefilled.

### Do not

- Do **not** add certificate pinning, a custom `TrustManager`, or a bundled CA. Self-hosted users rotate
  certificates and pinning would brick their installs; correctness here is "system trust store only,
  HTTPS enforced for everything but Jellyfin", which the network security config already expresses.
- Do **not** disable `instanceFollowRedirects = false`, allow user-installed CAs, or lower the
  `useCleartextTraffic` scope in the XML in a way that breaks plain-HTTP Jellyfin.
- Do **not** change payload encryption (`SyncCrypto`), the sync protocol, or the recovery-key format. The
  server changes are transport/credential hardening only.

### Acceptance criteria

1. `./gradlew test` passes, including the new tests, and no existing test is weakened.
2. `./gradlew :app:assembleRelease` succeeds on both the `minSdk` and latest SDK configurations.
3. Manual/unit evidence in the PR body for each numbered item above: the code path, the user-visible
   message for 429/507/408/409, and the test name that proves it.
4. No new third-party dependencies.
5. A short section in the PR body titled "Client ↔ server contract" listing the status codes now handled,
   their messages, and which endpoint each applies to, so the server side can be reviewed against it.
6. For items 9–11, evidence that a crashed or interrupted call cannot leave the app holding a revoked
   token: the code path that replaces the stored token, and the test that proves it.
