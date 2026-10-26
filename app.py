#!/usr/bin/env python3
"""Soundtrail's self-hosted account and encrypted-sync API (Python standard library only).

The service knows account email addresses, authentication hashes, event ids, sequence
numbers, ciphertext sizes and request timing. Sync event contents are encrypted on the
Android device; this server does not receive a decryption key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import tempfile
import threading
import time
import uuid
import backup as managed_backups
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

API_VERSION = "v1"
# Platform-neutral default: a "data" folder next to this file (works on Linux, macOS, Windows, BSD).
# Override with SOUNDTRAIL_DB to keep the database on a dedicated disk or volume.
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "soundtrail.sqlite3"
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_ACCOUNT_SYNC_BYTES = 64 * 1024 * 1024
MAX_YOUTUBE_AUDIO_BYTES = 250 * 1024 * 1024
MAX_BATCH_EVENTS = 100
MAX_PAGE_SIZE = 500
COMPACT_AFTER_EVENTS = 1_000
# How long a connection may sit idle mid-request before the server drops it. This stops a slow
# client from pinning a worker thread, while still leaving room for a large snapshot upload.
REQUEST_TIMEOUT_SECONDS = 30
# How long a stop request waits for requests already in progress before closing them.
GRACEFUL_STOP_SECONDS = 10
EXTRACTION_TMP_PREFIX = "soundtrail-youtube-"
YOUTUBE_VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
SESSION_SECONDS = 30 * 24 * 60 * 60
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class QuotaExceededError(ValueError):
    """The account has reached its configured encrypted-storage allowance."""


class YouTubeExtractionError(Exception):
    """A public, audio-only extraction request could not be completed."""


class RequestTimeoutError(Exception):
    """The client did not finish sending its request before the socket timeout."""


class RateLimiter:
    """Small in-process sliding-window limiter; use a proxy limiter for multi-worker deployments."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, category: str, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[(category, key)]
            cutoff = now - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            if len(self._hits) > 4096:
                for item in list(self._hits):
                    history = self._hits[item]
                    while history and history[0] <= cutoff:
                        history.popleft()
                    if not history:
                        self._hits.pop(item, None)
            return True


from contextlib import contextmanager


@contextmanager
def db_session(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 15000")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize_db(path: str) -> None:
    with db_session(path) as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);
            CREATE TABLE IF NOT EXISTS sync_events (
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                iv TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(account_id, sequence),
                UNIQUE(account_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS sync_event_receipts (
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                event_id TEXT NOT NULL,
                iv_hash BLOB NOT NULL,
                ciphertext_hash BLOB NOT NULL,
                sequence INTEGER NOT NULL,
                PRIMARY KEY(account_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS sync_snapshots (
                account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                through_sequence INTEGER NOT NULL,
                snapshot_id TEXT NOT NULL,
                iv TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        # Keep retry idempotency after old ciphertext rows are compacted away.
        rows = db.execute("SELECT account_id, event_id, iv, ciphertext, sequence FROM sync_events").fetchall()
        for row in rows:
            db.execute(
                "INSERT OR IGNORE INTO sync_event_receipts "
                "(account_id, event_id, iv_hash, ciphertext_hash, sequence) VALUES (?, ?, ?, ?, ?)",
                (
                    row["account_id"], row["event_id"],
                    hashlib.sha256(row["iv"].encode("ascii")).digest(),
                    hashlib.sha256(row["ciphertext"].encode("ascii")).digest(),
                    int(row["sequence"]),
                ),
            )


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8")


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(_password_bytes(password), salt=salt, n=1 << 14, r=8, p=1, dklen=32)


def _validate_email(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("Enter a valid email address.")
    email = raw.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    return email


def _validate_password(raw: Any) -> str:
    if not isinstance(raw, str) or not PASSWORD_MIN_LENGTH <= len(raw) <= PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}–{PASSWORD_MAX_LENGTH} characters.")
    return raw


def _issue_session(db: sqlite3.Connection, account_id: str, now: int | None = None) -> tuple[str, int]:
    issued_at = int(time.time()) if now is None else now
    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (issued_at,))
    token = secrets.token_urlsafe(32)
    expires = issued_at + SESSION_SECONDS
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    db.execute(
        "INSERT INTO sessions(token_hash, account_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token_hash, account_id, expires, issued_at),
    )
    return token, expires


def create_account(db_path: str, raw_email: Any, raw_password: Any) -> dict[str, Any]:
    email = _validate_email(raw_email)
    password = _validate_password(raw_password)
    now = int(time.time())
    account_id = str(uuid.uuid4())
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    try:
        with db_session(db_path) as db:
            db.execute(
                "INSERT INTO accounts(id, email, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (account_id, email, salt, digest, now),
            )
            token, expires = _issue_session(db, account_id, now)
    except sqlite3.IntegrityError as exc:
        raise ValueError("An account with that email already exists.") from exc
    return {"accountId": account_id, "email": email, "token": token, "expiresAt": expires}


def login(db_path: str, raw_email: Any, raw_password: Any) -> dict[str, Any]:
    email = _validate_email(raw_email)
    if not isinstance(raw_password, str) or not 1 <= len(raw_password) <= PASSWORD_MAX_LENGTH:
        raise ValueError("Email or password is incorrect.")
    now = int(time.time())
    with db_session(db_path) as db:
        row = db.execute(
            "SELECT id, password_salt, password_hash FROM accounts WHERE email = ?", (email,)
        ).fetchone()
        # Perform a scrypt even for a missing account, to reduce email enumeration by timing.
        salt = bytes(row["password_salt"]) if row else bytes(16)
        actual = password_digest(raw_password, salt)
        if row is None or not hmac.compare_digest(actual, bytes(row["password_hash"])):
            raise ValueError("Email or password is incorrect.")
        token, expires = _issue_session(db, row["id"], now)
    return {"accountId": row["id"], "email": email, "token": token, "expiresAt": expires}


def authenticate(db_path: str, token: str, now: int | None = None) -> str | None:
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).digest()
    current = int(time.time()) if now is None else now
    with db_session(db_path) as db:
        row = db.execute(
            "SELECT account_id FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (token_hash, current),
        ).fetchone()
    return row["account_id"] if row else None


def revoke_session(db_path: str, token: str) -> None:
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).digest()
    with db_session(db_path) as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_account(db_path: str, account_id: str) -> None:
    with db_session(db_path) as db:
        db.execute("DELETE FROM accounts WHERE id = ?", (account_id,))


def _valid_b64(value: Any, *, max_chars: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= max_chars and bool(BASE64URL_RE.fullmatch(value))


def _latest_sequence(db: sqlite3.Connection, account_id: str) -> int:
    event_row = db.execute(
        "SELECT COALESCE(MAX(sequence), 0) AS sequence FROM sync_events WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    snapshot_row = db.execute(
        "SELECT through_sequence FROM sync_snapshots WHERE account_id = ?", (account_id,)
    ).fetchone()
    return max(int(event_row["sequence"]), int(snapshot_row["through_sequence"]) if snapshot_row else 0)


def append_events(db_path: str, account_id: str, raw_events: Any) -> dict[str, Any]:
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > MAX_BATCH_EVENTS:
        raise ValueError(f"Send between 1 and {MAX_BATCH_EVENTS} events per request.")
    normalized: list[tuple[str, str, str, bytes, bytes]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object.")
        event_id = event.get("id")
        try:
            canonical_id = str(uuid.UUID(event_id)) if isinstance(event_id, str) else ""
        except (ValueError, AttributeError):
            canonical_id = ""
        iv, ciphertext = event.get("iv"), event.get("ciphertext")
        if not canonical_id or not _valid_b64(iv, max_chars=64) or not _valid_b64(ciphertext, max_chars=MAX_EVENT_BYTES * 2):
            raise ValueError("An encrypted event has an invalid id or payload.")
        try:
            iv_bytes = base64.urlsafe_b64decode(iv + "=" * (-len(iv) % 4))
            cipher_bytes = base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
        except Exception as exc:
            raise ValueError("An encrypted event has an invalid payload.") from exc
        if len(iv_bytes) != 12 or not 16 <= len(cipher_bytes) <= MAX_EVENT_BYTES:
            raise ValueError("An encrypted event has an invalid size.")
        normalized.append((
            canonical_id, iv, ciphertext,
            hashlib.sha256(iv.encode("ascii")).digest(),
            hashlib.sha256(ciphertext.encode("ascii")).digest(),
        ))

    now = int(time.time())
    accepted: list[dict[str, Any]] = []
    with db_session(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        used = int(db.execute(
            "SELECT COALESCE(SUM(LENGTH(iv) + LENGTH(ciphertext)), 0) AS size "
            "FROM sync_events WHERE account_id = ?", (account_id,)
        ).fetchone()["size"])
        snapshot = db.execute(
            "SELECT iv, ciphertext FROM sync_snapshots WHERE account_id = ?", (account_id,)
        ).fetchone()
        if snapshot:
            used += len(snapshot["iv"]) + len(snapshot["ciphertext"])
        latest = _latest_sequence(db, account_id)
        for event_id, iv, ciphertext, iv_hash, ciphertext_hash in normalized:
            existing = db.execute(
                "SELECT sequence, iv_hash, ciphertext_hash FROM sync_event_receipts "
                "WHERE account_id = ? AND event_id = ?",
                (account_id, event_id),
            ).fetchone()
            if existing:
                if existing["iv_hash"] != iv_hash or existing["ciphertext_hash"] != ciphertext_hash:
                    raise ValueError("An event id cannot be reused with a different encrypted payload.")
                sequence = int(existing["sequence"])
            else:
                added_size = len(iv) + len(ciphertext)
                if used + added_size > MAX_ACCOUNT_SYNC_BYTES:
                    raise QuotaExceededError("This account has reached its encrypted sync storage limit.")
                latest += 1
                sequence = latest
                db.execute(
                    "INSERT INTO sync_events(account_id, sequence, event_id, iv, ciphertext, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (account_id, sequence, event_id, iv, ciphertext, now),
                )
                db.execute(
                    "INSERT INTO sync_event_receipts(account_id, event_id, iv_hash, ciphertext_hash, sequence) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (account_id, event_id, iv_hash, ciphertext_hash, sequence),
                )
                used += added_size
            accepted.append({"id": event_id, "sequence": sequence})
    return {"accepted": accepted, "latestSequence": latest}


def read_events(db_path: str, account_id: str, after: int, limit: int) -> dict[str, Any]:
    if after < 0:
        raise ValueError("Cursor must be zero or greater.")
    if not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError(f"Page size must be 1–{MAX_PAGE_SIZE}.")
    with db_session(db_path) as db:
        snapshot = db.execute(
            "SELECT through_sequence, snapshot_id, iv, ciphertext FROM sync_snapshots WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        snapshot_through = int(snapshot["through_sequence"]) if snapshot else 0
        effective_after = after
        snapshot_json = None
        if snapshot and after < snapshot_through:
            effective_after = snapshot_through
            snapshot_json = {
                "id": snapshot["snapshot_id"],
                "throughCursor": snapshot_through,
                "iv": snapshot["iv"],
                "ciphertext": snapshot["ciphertext"],
            }
        rows = db.execute(
            "SELECT sequence, event_id, iv, ciphertext FROM sync_events "
            "WHERE account_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?",
            (account_id, effective_after, limit + 1),
        ).fetchall()
        latest = _latest_sequence(db, account_id)
        event_count = int(db.execute(
            "SELECT COUNT(*) AS count FROM sync_events WHERE account_id = ?", (account_id,)
        ).fetchone()["count"])
    has_more = len(rows) > limit
    rows = rows[:limit]
    events = [
        {"sequence": int(row["sequence"]), "id": row["event_id"], "iv": row["iv"], "ciphertext": row["ciphertext"]}
        for row in rows
    ]
    next_cursor = int(rows[-1]["sequence"]) if rows else effective_after
    return {
        "events": events,
        "nextCursor": next_cursor,
        "hasMore": has_more,
        "snapshot": snapshot_json,
        "snapshotThrough": snapshot_through,
        "latestSequence": latest,
        "eventCount": event_count,
    }


def compact_history(db_path: str, account_id: str, raw_snapshot: Any) -> dict[str, Any]:
    if not isinstance(raw_snapshot, dict):
        raise ValueError("A snapshot envelope is required.")
    through = raw_snapshot.get("throughCursor")
    if type(through) is not int or through < 0:
        raise ValueError("Snapshot cursor must be a non-negative integer.")
    snapshot_id = raw_snapshot.get("id")
    try:
        snapshot_id = str(uuid.UUID(snapshot_id)) if isinstance(snapshot_id, str) else ""
    except (ValueError, AttributeError):
        snapshot_id = ""
    iv, ciphertext = raw_snapshot.get("iv"), raw_snapshot.get("ciphertext")
    if not snapshot_id or not _valid_b64(iv, max_chars=64) or not _valid_b64(
        ciphertext, max_chars=((MAX_SNAPSHOT_BYTES + 2) // 3) * 4 + 4
    ):
        raise ValueError("The encrypted snapshot has an invalid id or payload.")
    try:
        iv_bytes = base64.urlsafe_b64decode(iv + "=" * (-len(iv) % 4))
        cipher_bytes = base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
    except Exception as exc:
        raise ValueError("The encrypted snapshot payload is invalid.") from exc
    if len(iv_bytes) != 12 or not 16 <= len(cipher_bytes) <= MAX_SNAPSHOT_BYTES:
        raise ValueError("The encrypted snapshot has an invalid size.")

    with db_session(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute(
            "SELECT through_sequence FROM sync_snapshots WHERE account_id = ?", (account_id,)
        ).fetchone()
        current_through = int(current["through_sequence"]) if current else 0
        latest = _latest_sequence(db, account_id)
        if through < current_through:
            return {"compacted": False, "snapshotThrough": current_through, "prunedEvents": 0}
        if through > latest:
            raise ValueError("Snapshot cursor is ahead of this account's event history.")
        remaining = int(db.execute(
            "SELECT COALESCE(SUM(LENGTH(iv) + LENGTH(ciphertext)), 0) AS size FROM sync_events "
            "WHERE account_id = ? AND sequence > ?", (account_id, through)
        ).fetchone()["size"])
        if remaining + len(iv) + len(ciphertext) > MAX_ACCOUNT_SYNC_BYTES:
            raise QuotaExceededError("The encrypted snapshot would exceed this account's storage limit.")
        db.execute(
            "INSERT INTO sync_snapshots(account_id, through_sequence, snapshot_id, iv, ciphertext, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(account_id) DO UPDATE SET through_sequence = excluded.through_sequence, "
            "snapshot_id = excluded.snapshot_id, iv = excluded.iv, ciphertext = excluded.ciphertext, "
            "created_at = excluded.created_at",
            (account_id, through, snapshot_id, iv, ciphertext, int(time.time())),
        )
        pruned = db.execute(
            "DELETE FROM sync_events WHERE account_id = ? AND sequence <= ?", (account_id, through)
        ).rowcount
        # Old delivery IDs are represented by the authenticated checkpoint now. Keep receipt
        # metadata bounded too; an old retry may be re-appended, but LWW clocks make it harmless.
        db.execute(
            "DELETE FROM sync_event_receipts WHERE account_id = ? AND sequence <= ?", (account_id, through)
        )
    return {"compacted": True, "snapshotThrough": through, "prunedEvents": int(pruned)}


def extract_youtube_audio(video_id: str, output_dir: Path) -> tuple[Path, str]:
    """Fetch a public audio-only stream, without cookies, Google tokens, or DRM handling."""
    if not YOUTUBE_VIDEO_ID_RE.fullmatch(video_id):
        raise ValueError("Enter a single YouTube video id.")
    try:
        import yt_dlp  # Installed only in the self-hosted server image.
    except ImportError as exc:
        raise YouTubeExtractionError("YouTube audio extraction is not installed on this server.") from exc

    def check_download_size(status: dict[str, Any]) -> None:
        if status.get("status") == "downloading" and int(status.get("downloaded_bytes") or 0) > MAX_YOUTUBE_AUDIO_BYTES:
            raise QuotaExceededError("That audio exceeds the 250 MiB offline-download limit.")

    options = {
        "format": "bestaudio[ext=m4a]/bestaudio[ext=webm]/bestaudio",
        "outtmpl": str(output_dir / "youtube-audio.%(ext)s"),
        "noplaylist": True,
        "max_filesize": MAX_YOUTUBE_AUDIO_BYTES,
        "progress_hooks": [check_download_size],
        "socket_timeout": 30,
        "retries": 1,
        "fragment_retries": 1,
        "quiet": True,
        "no_warnings": True,
        "no_color": True,
        "cachedir": False,
        "overwrites": True,
    }
    try:
        with yt_dlp.YoutubeDL(options) as downloader:
            downloader.extract_info(f"https://www.youtube.com/watch?v={video_id}", download=True)
    except QuotaExceededError:
        raise
    except Exception as exc:
        # Avoid returning extractor diagnostics, headers, or upstream URLs to the client/logs.
        raise YouTubeExtractionError(
            "YouTube did not provide a downloadable public audio stream. Login, cookies, and restricted videos are not supported."
        ) from exc

    candidates = [
        path for path in output_dir.glob("youtube-audio.*")
        if path.is_file() and path.suffix.lower() in {".m4a", ".webm", ".mp3", ".opus", ".ogg", ".aac", ".flac"}
    ]
    if len(candidates) != 1:
        raise YouTubeExtractionError("The server did not receive one complete audio-only file.")
    result = candidates[0]
    if result.stat().st_size <= 0:
        raise YouTubeExtractionError("YouTube returned an empty audio file.")
    if result.stat().st_size > MAX_YOUTUBE_AUDIO_BYTES:
        raise QuotaExceededError("That audio exceeds the 250 MiB offline-download limit.")
    content_type = {
        ".m4a": "audio/mp4", ".webm": "audio/webm", ".mp3": "audio/mpeg",
        ".opus": "audio/ogg", ".ogg": "audio/ogg", ".aac": "audio/aac", ".flac": "audio/flac",
    }[result.suffix.lower()]
    return result, content_type


class SyncHTTPServer(ThreadingHTTPServer):
    """Threaded server that can report, and briefly wait for, requests still in progress.

    Handler threads are daemons so a wedged request can never keep the process alive, but a stop
    request still drains work that is already running, so a client is not cut off mid-upload.
    """

    daemon_threads = True

    def __init__(self, server_address: Any, handler: Any) -> None:
        super().__init__(server_address, handler)
        self._active = 0
        self._active_lock = threading.Lock()

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        with self._active_lock:
            self._active += 1
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active -= 1

    def active_request_count(self) -> int:
        with self._active_lock:
            return self._active

    def wait_for_active_requests(self, timeout: float = GRACEFUL_STOP_SECONDS) -> int:
        """Give in-flight requests up to `timeout` seconds; return how many are still running."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.active_request_count() == 0:
                return 0
            time.sleep(0.05)
        return self.active_request_count()


def clean_stale_extraction_dirs(max_age_seconds: int = 3600, root: Path | None = None) -> int:
    """Remove extraction folders left behind by a crash or hard kill.

    Normal requests delete their own per-request directory. If the process dies mid-extraction,
    the audio stays in the system temp folder, so each start sweeps old ones to keep /tmp bounded.
    Only directories this service created (matching its prefix) are touched.
    """
    directory = Path(root) if root is not None else Path(tempfile.gettempdir())
    try:
        candidates = list(directory.glob(EXTRACTION_TMP_PREFIX + "*"))
    except OSError:
        return 0
    cutoff = time.time() - max_age_seconds
    removed = 0
    for candidate in candidates:
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            if candidate.stat().st_mtime > cutoff:
                continue
            shutil.rmtree(candidate, ignore_errors=True)
            removed += 1
        except OSError:
            continue
    return removed


def make_handler(db_path: str):
    limiter = RateLimiter()
    youtube_slots = threading.BoundedSemaphore(2)

    class Handler(BaseHTTPRequestHandler):
        server_version = "SoundtrailSync/1"
        sys_version = ""
        # BaseHTTPRequestHandler applies this as the socket timeout, so a client that stalls
        # mid-request cannot hold a thread open indefinitely.
        timeout = REQUEST_TIMEOUT_SECONDS

        def log_message(self, fmt: str, *args: Any) -> None:
            # Do not print authorization headers or request bodies. The URL contains no tokens.
            print("%s - %s" % (self.address_string(), fmt % args))

        def _send(
            self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdigit():
                raise ValueError("Content-Length is required.")
            length = int(raw_length)
            if length > MAX_BODY_BYTES:
                raise OverflowError("Request body is too large.")
            try:
                body = self.rfile.read(length)
            except TimeoutError as exc:
                self.close_connection = True
                raise RequestTimeoutError(
                    "The request body did not arrive within the server timeout."
                ) from exc
            try:
                parsed = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError("Request body must be valid JSON.") from exc
            if not isinstance(parsed, dict):
                raise ValueError("Request body must be a JSON object.")
            return parsed

        def _bearer(self) -> tuple[str, str] | None:
            header = self.headers.get("Authorization", "")
            prefix, _, token = header.partition(" ")
            if prefix.lower() != "bearer" or not token:
                return None
            account_id = authenticate(db_path, token)
            return (account_id, token) if account_id else None

        def _rate_limit_ip(self) -> str:
            peer = self.client_address[0]
            forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
            if not forwarded:
                return peer
            try:
                address = ipaddress.ip_address(peer)
                forwarded_address = ipaddress.ip_address(forwarded)
                if address.is_private or address.is_loopback:
                    return str(forwarded_address)
            except ValueError:
                pass
            return peer

        def _post_youtube_audio(self) -> None:
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to the self-hosted server first."})
                return
            client_ip = self._rate_limit_ip()
            if (
                not limiter.allow("youtube-ip", client_ip, limit=30, window_seconds=60)
                or not limiter.allow("youtube-account", auth[0], limit=20, window_seconds=60)
            ):
                self._send(429, {"error": "Too many audio extraction requests. Try again shortly."}, {"Retry-After": "60"})
                return
            try:
                body = self._body()
                if body.get("authorized") is not True:
                    self._send(403, {"error": "Confirm you own or have permission to download this audio."})
                    return
                video_id = body.get("videoId")
                if not isinstance(video_id, str) or not YOUTUBE_VIDEO_ID_RE.fullmatch(video_id):
                    self._send(400, {"error": "Enter a single YouTube video id."})
                    return
            except OverflowError as exc:
                self._send(413, {"error": str(exc)})
                return
            except RequestTimeoutError as exc:
                # The socket already timed out; a bare 408 may not reach the client.
                try:
                    self._send(408, {"error": str(exc)})
                except OSError:
                    pass
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return

            if not youtube_slots.acquire(blocking=False):
                self._send(503, {"error": "The audio extractor is busy. Try again shortly."}, {"Retry-After": "30"})
                return
            headers_sent = False
            try:
                # A per-request temporary directory is removed whether the stream completes or fails.
                with tempfile.TemporaryDirectory(prefix=EXTRACTION_TMP_PREFIX) as directory:
                    path, content_type = extract_youtube_audio(video_id, Path(directory))
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(path.stat().st_size))
                    self.send_header("Content-Disposition", f'attachment; filename="youtube-audio{path.suffix.lower()}"')
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    headers_sent = True
                    with path.open("rb") as audio:
                        while True:
                            chunk = audio.read(64 * 1024)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    self.wfile.flush()
            except QuotaExceededError as exc:
                if not headers_sent:
                    self._send(413, {"error": str(exc)})
            except YouTubeExtractionError as exc:
                if not headers_sent:
                    self._send(422, {"error": str(exc)})
            except OSError as exc:
                if headers_sent:
                    print("YouTube audio response ended early: client disconnected")
                else:
                    print(f"YouTube audio request failed: {type(exc).__name__}")
                    self._send(502, {"error": "The audio source could not be reached."})
            finally:
                youtube_slots.release()

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/health":
                self._send(200, {"status": "ok", "version": API_VERSION})
                return
            if parsed.path != "/v1/events":
                self._send(404, {"error": "Not found."})
                return
            if not limiter.allow("events-read", self._rate_limit_ip(), limit=600, window_seconds=60):
                self._send(429, {"error": "Too many sync reads. Try again shortly."}, {"Retry-After": "60"})
                return
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to sync."})
                return
            query = parse_qs(parsed.query)
            try:
                after = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", [str(MAX_PAGE_SIZE)])[0])
                result = read_events(db_path, auth[0], after, limit)
                self._send(200, result)
            except (ValueError, TypeError) as exc:
                self._send(400, {"error": str(exc)})

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/v1/youtube/audio":
                self._post_youtube_audio()
                return
            peer = self._rate_limit_ip()
            limiter_config = {
                "/v1/accounts": ("account-create", 5, 3600),
                "/v1/sessions": ("login", 20, 60),
                "/v1/events": ("events-write", 600, 60),
                "/v1/snapshots": ("snapshot-write", 10, 60),
            }
            if parsed.path not in limiter_config:
                self._send(404, {"error": "Not found."})
                return
            bucket, allowance, window = limiter_config[parsed.path]
            if not limiter.allow(bucket, peer, limit=allowance, window_seconds=window):
                self._send(429, {"error": "Too many requests. Try again shortly."}, {"Retry-After": str(window)})
                return
            auth = None
            if parsed.path in ("/v1/events", "/v1/snapshots"):
                auth = self._bearer()
                if not auth:
                    self._send(401, {"error": "Sign in to sync."})
                    return
            try:
                body = self._body()
                if parsed.path == "/v1/accounts":
                    result = create_account(db_path, body.get("email"), body.get("password"))
                    self._send(201, result)
                elif parsed.path == "/v1/sessions":
                    result = login(db_path, body.get("email"), body.get("password"))
                    self._send(200, result)
                elif parsed.path == "/v1/events":
                    assert auth is not None
                    result = append_events(db_path, auth[0], body.get("events"))
                    self._send(200, result)
                else:
                    assert auth is not None
                    result = compact_history(db_path, auth[0], body.get("snapshot"))
                    self._send(200, result)
            except OverflowError as exc:
                self._send(413, {"error": str(exc)})
            except RequestTimeoutError as exc:
                self.close_connection = True
                try:
                    self._send(408, {"error": str(exc)})
                except OSError:
                    pass
            except QuotaExceededError as exc:
                self._send(507, {"error": str(exc)})
            except ValueError as exc:
                status = 409 if "already exists" in str(exc) else 400
                if str(exc) == "Email or password is incorrect.":
                    status = 401
                self._send(status, {"error": str(exc)})
            except (sqlite3.Error, OSError) as exc:
                print(f"request failed: {type(exc).__name__}")
                self._send(500, {"error": "The sync server could not complete that request."})

        def do_DELETE(self) -> None:
            path = urlsplit(self.path).path
            if path not in ("/v1/sessions/current", "/v1/account/current"):
                self._send(404, {"error": "Not found."})
                return
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to sync."})
                return
            if path == "/v1/account/current" and not limiter.allow(
                "account-delete", self._rate_limit_ip(), limit=5, window_seconds=3600
            ):
                self._send(429, {"error": "Too many account deletion requests."}, {"Retry-After": "3600"})
                return
            if path == "/v1/sessions/current":
                revoke_session(db_path, auth[1])
                self._send(200, {"signedOut": True})
                return
            delete_account(db_path, auth[0])
            self._send(200, {"deleted": True})

        def do_PUT(self) -> None:
            self._send(405, {"error": "Method not allowed."})

        def do_OPTIONS(self) -> None:
            self._send(405, {"error": "Method not allowed."})

    return Handler


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"Ignoring {name}: expected a whole number, got {raw!r}.", flush=True)
        return default


def serve() -> None:
    db_path = os.environ.get("SOUNDTRAIL_DB") or str(DEFAULT_DB_PATH)
    host = os.environ.get("SOUNDTRAIL_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    initialize_db(db_path)

    # Per-request extraction folders are deleted when the request ends; sweep any left by a
    # crash so a failed download cannot slowly fill the temp volume.
    stale = clean_stale_extraction_dirs()
    if stale:
        print(f"Removed {stale} stale YouTube extraction folder(s) from {tempfile.gettempdir()}.", flush=True)

    # Managed backups are part of the service, not an external cron job to remember. The thread
    # takes a verified snapshot at startup and then on the interval, pruning old versions. Set
    # SOUNDTRAIL_BACKUP_INTERVAL_SECONDS=0 to turn it off and manage copies yourself.
    backup_stop = threading.Event()
    backup_interval = max(
        0,
        _env_int("SOUNDTRAIL_BACKUP_INTERVAL_SECONDS", managed_backups.DEFAULT_INTERVAL_SECONDS),
    )
    backup_keep = max(1, _env_int("SOUNDTRAIL_BACKUP_KEEP", managed_backups.DEFAULT_KEEP))
    backup_thread: threading.Thread | None = None
    if backup_interval > 0:
        backup_thread = threading.Thread(
            target=managed_backups.backup_loop,
            args=(db_path, None, backup_keep, backup_interval, backup_stop),
            name="soundtrail-managed-backups",
            daemon=True,
        )
        backup_thread.start()

    httpd = SyncHTTPServer((host, port), make_handler(db_path))

    def request_shutdown(signum: int, _frame: Any) -> None:
        # serve_forever() runs in this thread, so shutdown() must come from another one.
        print(f"Received {_signal_name(signum)}; stopping the listener.", flush=True)
        threading.Thread(target=httpd.shutdown, name="soundtrail-shutdown", daemon=True).start()

    handlers_installed = False
    for name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            signal.signal(signum, request_shutdown)
            handlers_installed = True
        except (ValueError, OSError):
            # Not the main thread, or the platform has no such signal; Ctrl-C still works.
            pass

    print(f"Soundtrail encrypted-sync API listening on {host}:{port}; database={db_path}")
    if backup_interval > 0:
        folder = managed_backups.default_backup_dir(Path(db_path))
        print(
            f"Managed backups: every {backup_interval}s into {folder} "
            f"(keeping {backup_keep}); set SOUNDTRAIL_BACKUP_INTERVAL_SECONDS=0 to disable."
        )
    if not handlers_installed:
        print("Signal handlers were not installed; stop the service with Ctrl-C.", flush=True)
    try:
        httpd.serve_forever()
    finally:
        # Stop accepting connections, then let requests already in progress finish (each one is
        # bounded by the socket timeout) before the process goes away.
        httpd.server_close()
        remaining = httpd.wait_for_active_requests()
        if remaining:
            print(
                f"Stop deadline reached with {remaining} request(s) still running; closing them.",
                flush=True,
            )
        # Give an in-flight backup a moment to finish so a restart finds a complete snapshot.
        backup_stop.set()
        if backup_thread is not None:
            backup_thread.join(timeout=5)
        print("Soundtrail sync API stopped.", flush=True)


if __name__ == "__main__":
    serve()
