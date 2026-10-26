#!/usr/bin/env python3
"""Managed, verified backups for the Soundtrail sync server's SQLite database.

The sync API needs no downtime to make a consistent copy: SQLite's online backup API reads the
live database (including committed WAL content) while the server keeps serving. Every snapshot is
written next to the database, integrity-checked, given a SHA-256 sidecar, and pruned to a fixed
number of versions. The server starts a backup thread automatically (reusing an existing snapshot that
is newer than both the interval and the database files, so restart loops do not churn the retention
window); the same code is available from the command line for an immediate copy, a listing, a
verification, or a restore.

    python3 backup.py backup [--keep 7]
    python3 backup.py list
    python3 backup.py verify [NAME]
    python3 backup.py restore NAME --yes

Environment:
    SOUNDTRAIL_DB          database file (default: data/soundtrail.sqlite3)
    SOUNDTRAIL_BACKUP_DIR  where snapshots go (default: <database folder>/backups)
    SOUNDTRAIL_BACKUP_KEEP how many to keep (default: 7)

A snapshot is a copy of the whole database, not of the decrypted library: sync payloads remain
AES-256-GCM ciphertext. It does contain account email addresses, password hashes, session hashes,
event metadata, and ciphertext sizes, exactly as the live database does. Treat the backup folder
as sensitive, keep it on a volume only the service user can read, and copy it off-host.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sqlite3
import sys
import threading
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.request import pathname2url

PREFIX = "soundtrail-"
SUFFIX = ".sqlite3"
SIDECAR = ".sha256"
DEFAULT_KEEP = 7
DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60


def default_db_path() -> Path:
    """The same default the API uses, without importing it (keep this module standalone)."""
    configured = os.environ.get("SOUNDTRAIL_DB")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent / "data" / "soundtrail.sqlite3"


def default_backup_dir(db_path: Path) -> Path:
    configured = os.environ.get("SOUNDTRAIL_BACKUP_DIR")
    if configured:
        return Path(configured).expanduser()
    return db_path.parent / "backups"


def _protect(path: Path, mode: int) -> None:
    """Best-effort permissions; Windows has no group/other bits to set."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _sync_directory(path: Path) -> None:
    """Best-effort fsync of a folder, so a rename is durable (POSIX only)."""
    if os.name != "posix":
        return
    try:
        handle = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_backup_name(name: str) -> bool:
    return (
        name.startswith(PREFIX)
        and name.endswith(SUFFIX)
        and len(name) <= 80
        and all(character.isalnum() or character in "-_." for character in name)
    )


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + SIDECAR)


def _snapshot_name(now: float) -> str:
    # Microsecond precision keeps names unique and lexicographically chronological.
    stamp = datetime.fromtimestamp(now).strftime("%Y%m%d-%H%M%S-%f")
    return f"{PREFIX}{stamp}{SUFFIX}"


def create_backup(
    db_path: Path | str | None = None,
    backup_dir: Path | str | None = None,
    keep: int = DEFAULT_KEEP,
    now: float | None = None,
) -> Path:
    """Writes one consistent, integrity-checked snapshot and prunes old ones.

    Raises FileNotFoundError when the database does not exist, sqlite3.DatabaseError when it is
    unreadable, and OSError when the backup folder cannot be written. A failed attempt leaves no
    partial file behind.
    """
    database = Path(db_path) if db_path else default_db_path()
    destination_dir = Path(backup_dir) if backup_dir else default_backup_dir(database)
    if not database.is_file():
        raise FileNotFoundError(f"No database at {database}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    _protect(destination_dir, 0o700)

    stamp = now if now is not None else time.time()
    target = destination_dir / _snapshot_name(stamp)
    counter = 0
    while target.exists():
        counter += 1
        target = destination_dir / f"{PREFIX}{datetime.fromtimestamp(stamp).strftime('%Y%m%d-%H%M%S-%f')}-{counter}{SUFFIX}"
    temp = destination_dir / f".{target.name}.{os.getpid()}.tmp"
    temp.unlink(missing_ok=True)

    try:
        # A normal read-write connection opens an existing WAL database reliably (a read-only
        # connection can fail when SQLite needs the -shm file). No writes are made through it;
        # the online backup API takes a consistent snapshot.
        with closing(sqlite3.connect(str(database), timeout=15)) as source:
            source.execute("PRAGMA busy_timeout = 15000")
            with closing(sqlite3.connect(str(temp))) as copy:
                source.backup(copy)
                result = copy.execute("PRAGMA integrity_check").fetchone()
                if not result or result[0] != "ok":
                    raise sqlite3.DatabaseError("The database copy failed its integrity check.")
                copy.commit()
        # Make the rename durable before advertising the file.
        with temp.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temp, target)
        _sync_directory(destination_dir)
        _protect(target, 0o600)
        _sidecar(target).write_text(_sha256(target) + "\n", encoding="ascii")
        _protect(_sidecar(target), 0o600)
        prune_backups(destination_dir, keep)
        return target
    finally:
        if temp.exists():
            temp.unlink(missing_ok=True)


def list_backups(backup_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Every managed snapshot, newest first, with its size and sidecar state."""
    folder = Path(backup_dir) if backup_dir else default_backup_dir(default_db_path())
    if not folder.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in folder.iterdir():
        if not path.is_file() or not _is_backup_name(path.name):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        sidecar = _sidecar(path)
        try:
            checksum = sidecar.read_text(encoding="ascii").strip() if sidecar.is_file() else None
        except (OSError, UnicodeDecodeError):
            checksum = None
        rows.append(
            {
                "name": path.name,
                "path": path,
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "checksum": checksum,
            }
        )
    rows.sort(key=lambda row: row["name"], reverse=True)
    return rows


def prune_backups(backup_dir: Path | str, keep: int = DEFAULT_KEEP) -> int:
    """Deletes all but the newest [keep] snapshots (and their sidecars). Returns how many went."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    removed = 0
    for row in list_backups(backup_dir)[keep:]:
        try:
            Path(row["path"]).unlink()
            _sidecar(Path(row["path"])).unlink(missing_ok=True)
            removed += 1
        except OSError:
            # A file that cannot be deleted must not stop the backup that just succeeded.
            pass
    return removed


def verify_backup(backup: Path | str) -> str:
    """Checks integrity and, when present, the SHA-256 sidecar. Returns a human sentence."""
    path = Path(backup)
    if not path.is_file():
        raise FileNotFoundError(f"No backup at {path}")
    expected = None
    sidecar = _sidecar(path)
    if sidecar.is_file():
        expected = sidecar.read_text(encoding="ascii").strip().lower()
    actual = _sha256(path)
    if expected and expected != actual:
        raise ValueError(
            "The backup's SHA-256 does not match its sidecar — the file may have been changed "
            "or truncated."
        )
    uri = "file:" + pathname2url(str(path.resolve())) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=15)) as database:
        result = database.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise ValueError("The backup failed SQLite's integrity check.")
    size = path.stat().st_size
    return f"{path.name}: integrity ok, {size} bytes, SHA-256 {actual[:16]}…"


def latest_backup(backup_dir: Path | str | None = None) -> Path | None:
    rows = list_backups(backup_dir)
    return Path(rows[0]["path"]) if rows else None


def restore_backup(
    backup: Path | str,
    db_path: Path | str | None = None,
    backup_dir: Path | str | None = None,
    keep: int = DEFAULT_KEEP,
    confirmed: bool = False,
) -> Path:
    """Replaces the database with a verified snapshot.

    The server must be stopped first. A safety snapshot of the current database is taken before
    anything is replaced, so a restore can itself be undone. Requires `confirmed=True` (the CLI
    turns this into `--yes`) because this overwrites the live account database.
    """
    if not confirmed:
        raise ValueError("Restoring replaces the live database; pass --yes to confirm.")
    source = Path(backup)
    verify_backup(source)
    database = Path(db_path) if db_path else default_db_path()
    destination_dir = Path(backup_dir) if backup_dir else default_backup_dir(database)

    database.parent.mkdir(parents=True, exist_ok=True)
    temp = database.with_name(f".{database.name}.restore.tmp")
    try:
        # Copy the verified source before the safety snapshot prunes the folder: restoring the
        # oldest snapshot when retention is already full must not delete the file being restored.
        shutil.copy2(source, temp)
        with temp.open("rb") as handle:
            os.fsync(handle.fileno())
        if database.is_file():
            safety = create_backup(database, destination_dir, keep=keep)
            print(f"Safety snapshot: {safety}")
        # A restored database must not inherit a stale WAL from the database it replaces.
        for side_file in (database.with_name(database.name + "-wal"), database.with_name(database.name + "-shm")):
            side_file.unlink(missing_ok=True)
        os.replace(temp, database)
        _sync_directory(database.parent)
        _protect(database, 0o600)
    finally:
        temp.unlink(missing_ok=True)
    return database


def backup_folder(db_path: Path | str | None, backup_dir: Path | str | None) -> Path:
    """Where snapshots for this database live, without opening the database."""
    if backup_dir:
        return Path(backup_dir)
    return default_backup_dir(Path(db_path) if db_path else default_db_path())


def database_mtime(db_path: Path | str | None) -> float:
    """Newest modification time of the database main file and its WAL side-files."""
    database = Path(db_path) if db_path else default_db_path()
    newest = 0.0
    for path in (database, database.with_name(database.name + "-wal"), database.with_name(database.name + "-shm")):
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    return newest


def backup_loop(
    db_path: Path | str | None,
    backup_dir: Path | str | None,
    keep: int,
    interval_seconds: int,
    stop: threading.Event,
) -> None:
    """Runs in a daemon thread beside the API: one snapshot at startup, then on the interval.

    A snapshot that is both newer than the interval and newer than every database file is reused
    instead of being copied again: otherwise a restart loop, a redeploy, or a crash restart would
    write another full copy each time and prune the retention window down to "the last few
    restarts". A database that was recreated or written since the snapshot still gets a fresh one.
    """
    if interval_seconds <= 0:
        return
    first = True
    while not stop.is_set():
        try:
            existing = list_backups(backup_folder(db_path, backup_dir))
            recent = False
            if existing:
                snapshot_time = float(existing[0]["modified"])
                recent = (
                    time.time() - snapshot_time < interval_seconds
                    and snapshot_time >= database_mtime(db_path)
                )
            if first and recent:
                print(
                    f"Managed backup reused: {existing[0]['name']} is newer than the "
                    f"{interval_seconds:g}s interval.",
                    flush=True,
                )
            else:
                created = create_backup(db_path, backup_dir, keep=keep)
                print(f"Managed backup written: {created}", flush=True)
        except Exception as exc:  # noqa: BLE001 - a bad backup must not stop the API
            print(f"Managed backup failed: {type(exc).__name__}: {exc}", flush=True)
        first = False
        if stop.wait(interval_seconds):
            return


def _resolve_named(backup_dir: Path | str | None, name: str | None) -> Path:
    if name:
        folder = Path(backup_dir) if backup_dir else default_backup_dir(default_db_path())
        # Only a bare file name this module wrote: never a path that can walk out of the folder.
        if Path(name).name != name or "/" in name or "\\" in name or not _is_backup_name(name):
            raise FileNotFoundError(f"No managed backup named {name}")
        candidate = folder / name
        if not candidate.is_file():
            raise FileNotFoundError(f"No managed backup named {name}")
        return candidate
    latest = latest_backup(backup_dir)
    if latest is None:
        raise FileNotFoundError("No managed backups yet; run `python3 backup.py backup` first.")
    return latest


def _env_keep() -> int:
    """SOUNDTRAIL_BACKUP_KEEP as a positive whole number, or the default when unusable."""
    raw = os.environ.get("SOUNDTRAIL_BACKUP_KEEP")
    if not raw:
        return DEFAULT_KEEP
    try:
        return max(1, int(raw))
    except ValueError:
        print(f"Ignoring SOUNDTRAIL_BACKUP_KEEP: expected a whole number, got {raw!r}.")
        return DEFAULT_KEEP


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Managed, verified backups for the Soundtrail sync server."
    )
    parser.add_argument("--db", help="database file (default: SOUNDTRAIL_DB or data/soundtrail.sqlite3)")
    parser.add_argument("--backup-dir", help="snapshot folder (default: SOUNDTRAIL_BACKUP_DIR or <db folder>/backups)")
    parser.add_argument("--keep", type=int, default=_env_keep())
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("backup", help="write a snapshot now")
    subparsers.add_parser("list", help="list snapshots, newest first")

    verify_parser = subparsers.add_parser("verify", help="verify the newest snapshot, or one by name")
    verify_parser.add_argument("name", nargs="?")

    restore_parser = subparsers.add_parser("restore", help="replace the database with a snapshot")
    restore_parser.add_argument("name", nargs="?")
    restore_parser.add_argument("--yes", action="store_true", help="confirm the overwrite")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    database = Path(args.db) if args.db else default_db_path()
    folder = Path(args.backup_dir) if args.backup_dir else default_backup_dir(database)
    try:
        if args.command == "backup":
            created = create_backup(database, folder, keep=args.keep)
            print(f"Backup written: {created}")
            print(verify_backup(created))
            return 0
        if args.command == "list":
            rows = list_backups(folder)
            if not rows:
                print("No managed backups yet.")
                return 0
            for row in rows:
                checksum = "sidecar present" if row["checksum"] else "no sidecar"
                print(
                    f"{row['name']}  {row['size']:>10} bytes  "
                    f"{datetime.fromtimestamp(row['modified']).strftime('%Y-%m-%d %H:%M')}  "
                    f"{checksum}"
                )
            return 0
        if args.command == "verify":
            print(verify_backup(_resolve_named(folder, args.name)))
            return 0
        if args.command == "restore":
            source = _resolve_named(folder, args.name)
            restored = restore_backup(
                source, database, folder, keep=args.keep, confirmed=args.yes
            )
            print(f"Restored {database} from {source.name}.")
            print(f"Verified database at {restored}. Start the server again when ready.")
            return 0
    except (FileNotFoundError, ValueError, OSError, sqlite3.DatabaseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
