"""Tests for the managed, verified server backups (stdlib only, no network)."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

import app
import backup


class ManagedBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.db = root / "soundtrail.sqlite3"
        self.backups = root / "backups"
        app.initialize_db(str(self.db))

    def _markers(self, path: Path | None = None) -> list[str]:
        with sqlite3.connect(str(path or self.db)) as database:
            try:
                rows = database.execute("SELECT value FROM markers ORDER BY value").fetchall()
            except sqlite3.OperationalError:
                return []
        return [row[0] for row in rows]

    def _add_marker(self, value: str) -> None:
        with sqlite3.connect(str(self.db)) as database:
            database.execute("CREATE TABLE IF NOT EXISTS markers (value TEXT NOT NULL)")
            database.execute("INSERT INTO markers(value) VALUES (?)", (value,))
            database.commit()

    def test_backup_copies_every_row_and_writes_a_verified_sidecar(self) -> None:
        self._add_marker("alpha")
        self._add_marker("beta")

        created = backup.create_backup(self.db, self.backups, now=1_700_000_000.0)

        self.assertTrue(created.is_file())
        self.assertTrue(created.name.startswith(backup.PREFIX))
        self.assertTrue(created.name.endswith(backup.SUFFIX))
        self.assertTrue(created.with_name(created.name + backup.SIDECAR).is_file())
        self.assertEqual(self._markers(created), ["alpha", "beta"])
        self.assertIn("integrity ok", backup.verify_backup(created))

    def test_retention_keeps_only_the_newest_snapshots(self) -> None:
        created = [
            backup.create_backup(self.db, self.backups, keep=3, now=1_700_000_000.0 + index)
            for index in range(6)
        ]

        listed = backup.list_backups(self.backups)
        self.assertEqual(
            [row["name"] for row in listed],
            [created[5].name, created[4].name, created[3].name],
        )

    def test_restore_brings_back_a_deleted_row_and_keeps_a_safety_snapshot(self) -> None:
        self._add_marker("keep me")
        created = backup.create_backup(self.db, self.backups, now=1_700_000_000.0)
        with sqlite3.connect(str(self.db)) as database:
            database.execute("DELETE FROM markers")
            database.commit()
        self.assertEqual(self._markers(), [])

        restored = backup.restore_backup(
            created, self.db, self.backups, keep=5, confirmed=True
        )

        self.assertEqual(restored, self.db)
        self.assertEqual(self._markers(), ["keep me"])
        # The source snapshot plus the safety copy taken before the restore.
        self.assertGreaterEqual(len(backup.list_backups(self.backups)), 2)
        with sqlite3.connect(str(self.db)) as database:
            self.assertEqual(database.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_restoring_the_oldest_kept_snapshot_survives_its_own_retention(self) -> None:
        self._add_marker("from the oldest")
        created = [
            backup.create_backup(self.db, self.backups, keep=3, now=1_700_000_000.0 + index)
            for index in range(3)
        ]
        self.assertEqual(len(backup.list_backups(self.backups)), 3)

        # The safety snapshot taken during the restore must not prune the source before it is
        # copied — this is the case where the source is exactly at the retention boundary.
        backup.restore_backup(created[0], self.db, self.backups, keep=3, confirmed=True)

        self.assertEqual(self._markers(), ["from the oldest"])

    def test_restore_refuses_without_confirmation_and_leaves_the_database_alone(self) -> None:
        self._add_marker("still here")
        created = backup.create_backup(self.db, self.backups, now=1_700_000_000.0)

        with self.assertRaises(ValueError):
            backup.restore_backup(created, self.db, self.backups)

        self.assertEqual(self._markers(), ["still here"])

    def test_tampering_is_detected_by_the_checksum(self) -> None:
        created = backup.create_backup(self.db, self.backups, now=1_700_000_000.0)
        payload = bytearray(created.read_bytes())
        payload[len(payload) // 2] ^= 0xFF
        created.write_bytes(bytes(payload))

        with self.assertRaises(ValueError) as caught:
            backup.verify_backup(created)
        self.assertIn("SHA-256", str(caught.exception))

    def test_list_is_newest_first_and_ignores_foreign_files(self) -> None:
        (self.backups / "notes.txt").parent.mkdir(parents=True, exist_ok=True)
        (self.backups / "notes.txt").write_text("not a backup")
        first = backup.create_backup(self.db, self.backups, now=1_700_000_000.0)
        second = backup.create_backup(self.db, self.backups, now=1_700_000_100.0)

        listed = backup.list_backups(self.backups)

        self.assertEqual([row["name"] for row in listed], [second.name, first.name])
        self.assertEqual(backup.latest_backup(self.backups), second)

    def test_backup_thread_reuses_a_snapshot_that_is_newer_than_the_interval(self) -> None:
        existing = backup.create_backup(self.db, self.backups, keep=5)

        stop = threading.Event()
        thread = threading.Thread(
            target=backup.backup_loop, args=(self.db, self.backups, 5, 3600, stop), daemon=True
        )
        thread.start()
        time.sleep(0.4)
        stop.set()
        thread.join(timeout=5)

        # One snapshot already exists and is younger than the interval, so a restart must not
        # write (and prune) a second copy.
        self.assertEqual([row["name"] for row in backup.list_backups(self.backups)], [existing.name])

    def test_backup_thread_snapshots_again_when_the_database_changed_since_the_last_copy(self) -> None:
        existing = backup.create_backup(self.db, self.backups, keep=5)
        # A write after the snapshot (or a recreated database) means the copy is stale even
        # though it is younger than the interval.
        self._add_marker("written after the snapshot")
        # Make "later than the snapshot" unambiguous rather than relying on timestamp granularity.
        later = existing.stat().st_mtime + 60
        os.utime(self.db, (later, later))

        stop = threading.Event()
        thread = threading.Thread(
            target=backup.backup_loop, args=(self.db, self.backups, 5, 3600, stop), daemon=True
        )
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and len(backup.list_backups(self.backups)) < 2:
                time.sleep(0.05)
            names = [row["name"] for row in backup.list_backups(self.backups)]
            self.assertEqual(2, len(names), names)
            self.assertEqual(existing.name, names[1])
        finally:
            stop.set()
            thread.join(timeout=5)

    def test_backup_thread_writes_the_first_snapshot_when_none_exists(self) -> None:
        stop = threading.Event()
        thread = threading.Thread(
            target=backup.backup_loop, args=(self.db, self.backups, 5, 3600, stop), daemon=True
        )
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not backup.list_backups(self.backups):
                time.sleep(0.05)
            self.assertEqual(1, len(backup.list_backups(self.backups)), "the startup snapshot was not written")
        finally:
            stop.set()
            thread.join(timeout=5)

    def test_a_missing_database_is_an_error_not_an_empty_backup(self) -> None:
        with self.assertRaises(FileNotFoundError):
            backup.create_backup(self.db.with_name("missing.sqlite3"), self.backups)

    def test_verify_can_name_the_latest_without_a_second_argument(self) -> None:
        backup.create_backup(self.db, self.backups, now=1_700_000_000.0)
        self.assertEqual(backup.main(["--backup-dir", str(self.backups), "--db", str(self.db), "verify"]), 0)

    def test_restore_names_cannot_walk_out_of_the_backup_folder(self) -> None:
        self.assertEqual(
            backup.main(
                [
                    "--backup-dir", str(self.backups),
                    "--db", str(self.db),
                    "restore", "../../etc/passwd", "--yes",
                ]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
