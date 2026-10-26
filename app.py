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
# Bumped when initialize_db has to change an existing database. Stored in schema_meta so a
# migration runs once instead of on every start.
SCHEMA_VERSION = 4
YOUTUBE_VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
SESSION_SECONDS = 30 * 24 * 60 * 60
# How many live sessions one account may hold; the oldest are evicted beyond this, so repeated
# sign-ins cannot grow the table without bound (and an attacker cannot bury a stolen session).
MAX_SESSIONS_PER_ACCOUNT = 20
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
# scrypt work factor for new passwords, as log2(N). Each hash needs 128*R*N bytes, so the default
# of 15 costs 32 MiB and ~100 ms; PASSWORD_KDF_CONCURRENCY caps how many run at once, which bounds
# peak memory. Accounts hashed by an older release keep working and are upgraded on next login.
PASSWORD_KDF_LOG2 = 15
PASSWORD_KDF_R = 8
PASSWORD_KDF_P = 1
PASSWORD_KDF_DKLEN = 32
PASSWORD_KDF_CONCURRENCY = 4
LEGACY_PASSWORD_KDF_LOG2 = 14
# Failed sign-ins per identifier before a short lockout. Keyed on the submitted address whether or
# not the account exists, so the response cannot be used to discover which addresses are real.
LOGIN_MAX_FAILURES = 10
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


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


class LoginThrottle:
    """Short lockout after repeated failed sign-ins, keyed on the submitted address.

    The IP limit in RateLimiter cannot stop a distributed attempt against one account, and this is
    keyed on the address even when no account exists, so a locked and an unknown address look the
    same. In-process, like the rest of the limits: it resets on restart.
    """

    def __init__(
        self,
        max_failures: int = LOGIN_MAX_FAILURES,
        window_seconds: int = LOGIN_FAILURE_WINDOW_SECONDS,
        lockout_seconds: int = LOGIN_LOCKOUT_SECONDS,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_for(self, key: str) -> int:
        """Seconds the identifier is still locked for, or 0."""
        now = time.monotonic()
        with self._lock:
            until = self._locked_until.get(key)
            if not until:
                return 0
            if until <= now:
                self._locked_until.pop(key, None)
                return 0
            return int(until - now) + 1

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._failures[key]
            cutoff = now - self.window_seconds
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            attempts.append(now)
            if len(attempts) >= self.max_failures:
                self._locked_until[key] = now + self.lockout_seconds
                attempts.clear()
            if len(self._failures) > 4096:
                for item in [k for k, v in self._failures.items() if not v]:
                    self._failures.pop(item, None)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


from contextlib import contextmanager


def _restrict(path: Path, mode: int) -> None:
    """Best-effort permissions; Windows has no group/other bits to set."""
    if os.name != "posix":
        return
    try:
        if path.stat().st_mode & 0o777 != mode:
            os.chmod(path, mode)
    except OSError:
        pass


def _harden_database_files(path: str) -> None:
    """The database holds emails and password hashes: keep it, and its WAL side-files, owner-only.

    SQLite creates new files with the process umask, which on many systems leaves the database
    world-readable. It also copies the main file's mode to new -wal/-shm files, so fixing the
    database once is enough for the side-files it creates later.
    """
    for suffix in ("", "-wal", "-shm"):
        _restrict(Path(path + suffix), 0o600)


@contextmanager
def db_session(path: str):
    parent = Path(path).parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
        _restrict(parent, 0o700)
    db = sqlite3.connect(path, timeout=15)
    _harden_database_files(path)
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


def _has_column(db: sqlite3.Connection, table: str, column: str) -> bool:
    return any(str(row["name"]) == column for row in db.execute(f"PRAGMA table_info({table})"))


def _schema_version(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    try:
        return int(row["value"]) if row else 1
    except (TypeError, ValueError):
        return 1


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
                password_scheme TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                session_id TEXT,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);
            CREATE UNIQUE INDEX IF NOT EXISTS sessions_session_id_idx ON sessions(session_id);
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
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        version = _schema_version(db)
        if version < 2:
            # Retry receipts arrived after the first release. Rebuild them once from the events
            # that are still stored: doing this on every start would re-read and re-hash the whole
            # event log (potentially hundreds of megabytes) before the API can accept a request.
            rows = db.execute(
                "SELECT account_id, event_id, iv, ciphertext, sequence FROM sync_events"
            ).fetchall()
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
        if version < 4:
            # Sessions gained a public, non-secret id so the app can list and revoke them without
            # ever handling the bearer token again.
            if not _has_column(db, "sessions", "session_id"):
                db.execute("ALTER TABLE sessions ADD COLUMN session_id TEXT")
            for row in db.execute("SELECT token_hash FROM sessions WHERE session_id IS NULL").fetchall():
                db.execute(
                    "UPDATE sessions SET session_id = ? WHERE token_hash = ?",
                    (str(uuid.uuid4()), row["token_hash"]),
                )
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS sessions_session_id_idx ON sessions(session_id)"
            )
        if version < 3:
            # Accounts written before password schemes were recorded are compared with the old
            # work factor and re-hashed with the current one after their next successful login.
            if not _has_column(db, "accounts", "password_scheme"):
                db.execute("ALTER TABLE accounts ADD COLUMN password_scheme TEXT")
        if version < SCHEMA_VERSION:
            db.execute(
                "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
    # WAL and its shared-memory file are created on first use; tighten them too.
    _harden_database_files(path)


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8")


# Hashing is deliberately memory-expensive, so only a few run at once: without this cap, parallel
# login attempts could allocate gigabytes and take the process down.
_kdf_slots = threading.BoundedSemaphore(PASSWORD_KDF_CONCURRENCY)


def configure_password_kdf(log2_n: int | None = None, concurrency: int | None = None) -> str:
    """Apply operator overrides, clamped to sane bounds, and return the resulting scheme."""
    global PASSWORD_KDF_LOG2, PASSWORD_KDF_CONCURRENCY, _kdf_slots
    # Upper bounds keep a misconfiguration from turning sign-in into a memory bomb: 2^17 is
    # 128 MiB per hash, and eight at once is still a whole gigabyte.
    if log2_n is not None:
        PASSWORD_KDF_LOG2 = min(max(int(log2_n), 12), 17)
    if concurrency is not None:
        PASSWORD_KDF_CONCURRENCY = min(max(int(concurrency), 1), 8)
    _kdf_slots = threading.BoundedSemaphore(PASSWORD_KDF_CONCURRENCY)
    return password_scheme()


def password_memory_mib() -> int:
    """Approximate peak memory for hashing, in MiB (per hash, and across the concurrency cap)."""
    per_hash = 128 * PASSWORD_KDF_R * (1 << PASSWORD_KDF_LOG2)
    return per_hash * PASSWORD_KDF_CONCURRENCY // (1024 * 1024)


def password_scheme(log2_n: int | None = None) -> str:
    """The stored description of how a password was hashed, e.g. `scrypt$32768$8$1$32`."""
    log2_n = PASSWORD_KDF_LOG2 if log2_n is None else log2_n
    return f"scrypt${1 << log2_n}${PASSWORD_KDF_R}${PASSWORD_KDF_P}${PASSWORD_KDF_DKLEN}"


LEGACY_PASSWORD_SCHEME = password_scheme(LEGACY_PASSWORD_KDF_LOG2)


def _parse_scheme(scheme: str | None) -> tuple[int, int, int, int]:
    """(log2_n, r, p, dklen) from a stored scheme; unknown values fall back to the legacy one."""
    if not scheme:
        return (LEGACY_PASSWORD_KDF_LOG2, PASSWORD_KDF_R, PASSWORD_KDF_P, PASSWORD_KDF_DKLEN)
    parts = scheme.split("$")
    try:
        algorithm, n, r, p, dklen = parts
        n, r, p, dklen = int(n), int(r), int(p), int(dklen)
    except (ValueError, TypeError):
        return (LEGACY_PASSWORD_KDF_LOG2, PASSWORD_KDF_R, PASSWORD_KDF_P, PASSWORD_KDF_DKLEN)
    # Clamp before hashing: a corrupted or edited row must not become a memory bomb.
    if algorithm != "scrypt" or not (1 << 12) <= n <= (1 << 20) or not 1 <= r <= 32 or not 1 <= p <= 16:
        return (LEGACY_PASSWORD_KDF_LOG2, PASSWORD_KDF_R, PASSWORD_KDF_P, PASSWORD_KDF_DKLEN)
    return (n.bit_length() - 1, r, p, min(max(dklen, 16), 64))


def password_digest(password: str, salt: bytes, scheme: str | None = None) -> bytes:
    log2_n, r, p, dklen = _parse_scheme(scheme if scheme else password_scheme())
    n = 1 << log2_n
    # OpenSSL's default cap (32 MiB) is below what these parameters need, so state it explicitly.
    maxmem = max(64 * 1024 * 1024, 2 * 128 * r * n)
    with _kdf_slots:
        return hashlib.scrypt(_password_bytes(password), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=maxmem)


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


def _issue_session(
    db: sqlite3.Connection, account_id: str, now: int | None = None
) -> tuple[str, int, str]:
    """Creates a session and returns (token, expires_at, session_id). The token is never stored."""
    issued_at = int(time.time()) if now is None else now
    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (issued_at,))
    token = secrets.token_urlsafe(32)
    session_id = str(uuid.uuid4())
    expires = issued_at + SESSION_SECONDS
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    db.execute(
        "INSERT INTO sessions(token_hash, session_id, account_id, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (token_hash, session_id, account_id, expires, issued_at),
    )
    # Keep the account's session list bounded: evict the oldest beyond the cap. A user who signs
    # in from many devices (or an attacker trying to bury a stolen session) cannot grow it without
    # limit; the newest sessions, including the one just issued, always survive.
    keep = db.execute(
        "SELECT token_hash FROM sessions WHERE account_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
        (account_id, MAX_SESSIONS_PER_ACCOUNT),
    ).fetchall()
    keep_hashes = {row["token_hash"] for row in keep}
    for row in db.execute("SELECT token_hash FROM sessions WHERE account_id = ?", (account_id,)).fetchall():
        if row["token_hash"] not in keep_hashes:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
    return token, expires, session_id


def create_account(db_path: str, raw_email: Any, raw_password: Any) -> dict[str, Any]:
    email = _validate_email(raw_email)
    password = _validate_password(raw_password)
    now = int(time.time())
    account_id = str(uuid.uuid4())
    salt = secrets.token_bytes(16)
    scheme = password_scheme()
    digest = password_digest(password, salt, scheme)
    try:
        with db_session(db_path) as db:
            db.execute(
                "INSERT INTO accounts(id, email, password_salt, password_hash, password_scheme, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (account_id, email, salt, digest, scheme, now),
            )
            token, expires, session_id = _issue_session(db, account_id, now)
    except sqlite3.IntegrityError as exc:
        raise ValueError("An account with that email already exists.") from exc
    return {
        "accountId": account_id, "email": email, "token": token,
        "expiresAt": expires, "sessionId": session_id,
    }


def login(db_path: str, raw_email: Any, raw_password: Any) -> dict[str, Any]:
    email = _validate_email(raw_email)
    if not isinstance(raw_password, str) or not 1 <= len(raw_password) <= PASSWORD_MAX_LENGTH:
        raise ValueError("Email or password is incorrect.")
    now = int(time.time())
    with db_session(db_path) as db:
        row = db.execute(
            "SELECT id, password_salt, password_hash, password_scheme FROM accounts WHERE email = ?",
            (email,),
        ).fetchone()
        # Perform a scrypt even for a missing account, to reduce email enumeration by timing.
        salt = bytes(row["password_salt"]) if row else bytes(16)
        stored_scheme = (row["password_scheme"] if row else None) or LEGACY_PASSWORD_SCHEME
        actual = password_digest(raw_password, salt, stored_scheme)
        if row is None or not hmac.compare_digest(actual, bytes(row["password_hash"])):
            raise ValueError("Email or password is incorrect.")
        if stored_scheme != password_scheme():
            # The account was created under a weaker work factor: upgrade it now that the correct
            # password is known. Costs one extra hash per account, once.
            upgraded_salt = secrets.token_bytes(16)
            upgraded_scheme = password_scheme()
            db.execute(
                "UPDATE accounts SET password_salt = ?, password_hash = ?, password_scheme = ? WHERE id = ?",
                (upgraded_salt, password_digest(raw_password, upgraded_salt, upgraded_scheme),
                 upgraded_scheme, row["id"]),
            )
        token, expires, session_id = _issue_session(db, row["id"], now)
    return {
        "accountId": row["id"], "email": email, "token": token,
        "expiresAt": expires, "sessionId": session_id,
    }


def session_record(db_path: str, token: str, now: int | None = None) -> dict[str, Any] | None:
    """The live session for a bearer token, or None when it is unknown, revoked, or expired."""
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).digest()
    current = int(time.time()) if now is None else now
    with db_session(db_path) as db:
        row = db.execute(
            "SELECT session_id, account_id, expires_at, created_at FROM sessions "
            "WHERE token_hash = ? AND expires_at > ?",
            (token_hash, current),
        ).fetchone()
    if row is None:
        return None
    return {
        "sessionId": row["session_id"] or "",
        "accountId": row["account_id"],
        "expiresAt": int(row["expires_at"]),
        "createdAt": int(row["created_at"]),
    }


def authenticate(db_path: str, token: str, now: int | None = None) -> str | None:
    record = session_record(db_path, token, now)
    return record["accountId"] if record else None


def account_email(db_path: str, account_id: str) -> str:
    with db_session(db_path) as db:
        row = db.execute("SELECT email FROM accounts WHERE id = ?", (account_id,)).fetchone()
    return row["email"] if row else ""


def list_sessions(db_path: str, account_id: str, current_session_id: str, now: int | None = None) -> list[dict[str, Any]]:
    """Live sessions for an account, newest first. Ids and timestamps only: never a token."""
    current = int(time.time()) if now is None else now
    with db_session(db_path) as db:
        rows = db.execute(
            "SELECT session_id, expires_at, created_at FROM sessions "
            "WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC, rowid DESC",
            (account_id, current),
        ).fetchall()
    return [
        {
            "id": row["session_id"] or "",
            "createdAt": int(row["created_at"]),
            "expiresAt": int(row["expires_at"]),
            "current": (row["session_id"] or "") == current_session_id,
        }
        for row in rows
    ]


def revoke_session_by_id(db_path: str, account_id: str, session_id: str) -> str:
    """Revokes one of this account's sessions. Returns 'revoked' or raises ValueError."""
    if not isinstance(session_id, str) or not UUID_RE.fullmatch(session_id):
        raise ValueError("That session id is not valid.")
    with db_session(db_path) as db:
        removed = db.execute(
            "DELETE FROM sessions WHERE account_id = ? AND session_id = ?", (account_id, session_id)
        ).rowcount
    if not removed:
        raise LookupError("That session is not signed in on this account.")
    return "revoked"


def renew_session(db_path: str, token: str) -> dict[str, Any]:
    """Rotates the caller's bearer token, so a copied token stops working.

    The 30-day lifetime restarts, the old token is deleted in the same transaction, and the
    response carries the only copy of the new one. The session id changes too: a renewed session
    is a new entry in the app's list, so a stale id cannot be used to revoke the live one.
    """
    record = session_record(db_path, token)
    if record is None:
        raise ValueError("Sign in again to renew this session.")
    now = int(time.time())
    with db_session(db_path) as db:
        db.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(token.encode("ascii", errors="ignore")).digest(),),
        )
        new_token, expires, session_id = _issue_session(db, record["accountId"], now)
    return {"token": new_token, "expiresAt": expires, "sessionId": session_id}


def change_password(
    db_path: str,
    account_id: str,
    current_password: Any,
    new_password: Any,
) -> dict[str, Any]:
    """Changes the password and signs every device out, returning a fresh session for this one.

    The current password is required, so a stolen bearer token alone cannot take the account
    over — it can only be ended by the change, never performed by it.
    """
    if not isinstance(current_password, str) or not 1 <= len(current_password) <= PASSWORD_MAX_LENGTH:
        raise PermissionError("The current password is incorrect.")
    password = _validate_password(new_password)
    now = int(time.time())
    with db_session(db_path) as db:
        row = db.execute(
            "SELECT password_salt, password_hash, password_scheme FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            raise ValueError("That account no longer exists.")
        stored_scheme = row["password_scheme"] or LEGACY_PASSWORD_SCHEME
        actual = password_digest(current_password, bytes(row["password_salt"]), stored_scheme)
        if not hmac.compare_digest(actual, bytes(row["password_hash"])):
            raise PermissionError("The current password is incorrect.")
        if hmac.compare_digest(password.encode("utf-8"), current_password.encode("utf-8")):
            raise ValueError("Choose a password different from the current one.")
        salt = secrets.token_bytes(16)
        scheme = password_scheme()
        db.execute(
            "UPDATE accounts SET password_salt = ?, password_hash = ?, password_scheme = ? WHERE id = ?",
            (salt, password_digest(password, salt, scheme), scheme, account_id),
        )
        revoked = db.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,)).rowcount
        token, expires, session_id = _issue_session(db, account_id, now)
    return {
        "changed": True,
        "revokedSessions": int(revoked),
        "token": token,
        "expiresAt": expires,
        "sessionId": session_id,
    }


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
    login_throttle = LoginThrottle()
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
            # These are JSON documents, never pages: forbid embedding, framing, or subresources.
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
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
            except RecursionError as exc:
                # Deeply nested arrays would otherwise unwind as a server error.
                raise ValueError("Request body is nested too deeply.") from exc
            if not isinstance(parsed, dict):
                raise ValueError("Request body must be a JSON object.")
            return parsed

        def _bearer(self) -> dict[str, Any] | None:
            """The authenticated session for this request, or None."""
            header = self.headers.get("Authorization", "")
            prefix, _, token = header.partition(" ")
            if prefix.lower() != "bearer" or not token:
                return None
            record = session_record(db_path, token)
            if record is None:
                return None
            record["token"] = token
            return record

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

        def _get_sessions(self, path: str) -> None:
            """`GET /v1/session/current` describes this session; `GET /v1/sessions` lists them all."""
            if not limiter.allow("session-read", self._rate_limit_ip(), limit=120, window_seconds=60):
                self._send(429, {"error": "Too many requests. Try again shortly."}, {"Retry-After": "60"})
                return
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to sync."})
                return
            if path == "/v1/session/current":
                self._send(200, {
                    "accountId": auth["accountId"],
                    "email": account_email(db_path, auth["accountId"]),
                    "sessionId": auth["sessionId"],
                    "createdAt": auth["createdAt"],
                    "expiresAt": auth["expiresAt"],
                })
                return
            self._send(200, {
                "sessions": list_sessions(db_path, auth["accountId"], auth["sessionId"]),
                "maxSessions": MAX_SESSIONS_PER_ACCOUNT,
            })

        def _post_session_current(self, path: str) -> None:
            """Renew this session's token, or change the account password."""
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to sync."})
                return
            if path == "/v1/sessions/current/renew":
                if not limiter.allow("session-renew", auth["accountId"], limit=30, window_seconds=60):
                    self._send(429, {"error": "Too many session renewals. Try again shortly."}, {"Retry-After": "60"})
                    return
                try:
                    self._send(200, renew_session(db_path, auth["token"]))
                except ValueError as exc:
                    self._send(401, {"error": str(exc)})
                return

            # Changing the password requires the current one: a stolen token must not be able to
            # lock the owner out, so failures are also throttled like sign-in failures.
            if not limiter.allow("password-change", self._rate_limit_ip(), limit=10, window_seconds=3600):
                self._send(429, {"error": "Too many password changes. Try again later."}, {"Retry-After": "3600"})
                return
            throttle_key = f"password:{auth['accountId']}"
            locked = login_throttle.locked_for(throttle_key)
            if locked:
                self._send(429, {"error": "Too many failed attempts. Try again shortly."}, {"Retry-After": str(locked)})
                return
            try:
                body = self._body()
            except OverflowError as exc:
                self._send(413, {"error": str(exc)})
                return
            except RequestTimeoutError as exc:
                self.close_connection = True
                try:
                    self._send(408, {"error": str(exc)})
                except OSError:
                    pass
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            try:
                result = change_password(
                    db_path, auth["accountId"], body.get("currentPassword"), body.get("newPassword")
                )
            except PermissionError as exc:
                login_throttle.record_failure(throttle_key)
                self._send(403, {"error": str(exc)})
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            login_throttle.record_success(throttle_key)
            self._send(200, result)

        def _post_youtube_audio(self) -> None:
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to the self-hosted server first."})
                return
            client_ip = self._rate_limit_ip()
            if (
                not limiter.allow("youtube-ip", client_ip, limit=30, window_seconds=60)
                or not limiter.allow("youtube-account", auth["accountId"], limit=20, window_seconds=60)
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
            if parsed.path in ("/v1/session/current", "/v1/sessions"):
                self._get_sessions(parsed.path)
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
                result = read_events(db_path, auth["accountId"], after, limit)
                self._send(200, result)
            except (ValueError, TypeError) as exc:
                self._send(400, {"error": str(exc)})

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/v1/youtube/audio":
                self._post_youtube_audio()
                return
            if parsed.path in ("/v1/sessions/current/renew", "/v1/account/current/password"):
                self._post_session_current(parsed.path)
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
                    # Normalise the key like login() does, so case and spacing cannot dodge the lock.
                    raw_email = body.get("email")
                    throttle_key = raw_email.strip().lower() if isinstance(raw_email, str) else ""
                    locked = login_throttle.locked_for(throttle_key)
                    if locked:
                        self._send(
                            429,
                            {"error": "Too many failed sign-in attempts. Try again shortly."},
                            {"Retry-After": str(locked)},
                        )
                        return
                    try:
                        result = login(db_path, raw_email, body.get("password"))
                    except ValueError as exc:
                        if str(exc) == "Email or password is incorrect.":
                            login_throttle.record_failure(throttle_key)
                        raise
                    login_throttle.record_success(throttle_key)
                    self._send(200, result)
                elif parsed.path == "/v1/events":
                    assert auth is not None
                    result = append_events(db_path, auth["accountId"], body.get("events"))
                    self._send(200, result)
                else:
                    assert auth is not None
                    result = compact_history(db_path, auth["accountId"], body.get("snapshot"))
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
            session_prefix = "/v1/sessions/"
            if path not in ("/v1/sessions/current", "/v1/account/current") and not (
                path.startswith(session_prefix) and len(path) > len(session_prefix)
            ):
                self._send(404, {"error": "Not found."})
                return
            auth = self._bearer()
            if not auth:
                self._send(401, {"error": "Sign in to sync."})
                return
            if path.startswith(session_prefix) and path != "/v1/sessions/current":
                # Sign another device out by its public session id; the token is never handled.
                if not limiter.allow("session-revoke", self._rate_limit_ip(), limit=60, window_seconds=60):
                    self._send(429, {"error": "Too many requests. Try again shortly."}, {"Retry-After": "60"})
                    return
                target = path[len(session_prefix):]
                try:
                    revoke_session_by_id(db_path, auth["accountId"], target)
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
                except LookupError as exc:
                    self._send(404, {"error": str(exc)})
                    return
                self._send(200, {"revoked": True, "signedOut": target == auth["sessionId"]})
                return
            if path == "/v1/account/current" and not limiter.allow(
                "account-delete", self._rate_limit_ip(), limit=5, window_seconds=3600
            ):
                self._send(429, {"error": "Too many account deletion requests."}, {"Retry-After": "3600"})
                return
            if path == "/v1/sessions/current":
                revoke_session(db_path, auth["token"])
                self._send(200, {"signedOut": True})
                return
            delete_account(db_path, auth["accountId"])
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
    scheme = configure_password_kdf(
        _env_int("SOUNDTRAIL_PASSWORD_KDF_LOG2", PASSWORD_KDF_LOG2),
        _env_int("SOUNDTRAIL_PASSWORD_KDF_CONCURRENCY", PASSWORD_KDF_CONCURRENCY),
    )
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

    print(
        f"Password hashing: {scheme} "
        f"({128 * PASSWORD_KDF_R * (1 << PASSWORD_KDF_LOG2) // (1024 * 1024)} MiB per hash, "
        f"at most {password_memory_mib()} MiB in parallel).",
        flush=True,
    )
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
