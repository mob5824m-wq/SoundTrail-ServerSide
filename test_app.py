import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import app


class SyncApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp.name) / "sync.sqlite3")
        app.initialize_db(self.db_path)
        self.httpd = app.ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(self.db_path))
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.account = self.request("POST", "/v1/accounts", {"email": "MUSIC@example.net", "password": "correct horse battery"})[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, payload=None, token=None, extra_headers=None):
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        headers.update(extra_headers or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    @staticmethod
    def encrypted_event(event_id=None, marker="opaque-ciphertext"):
        import base64
        return {
            "id": event_id or str(uuid.uuid4()),
            "iv": base64.urlsafe_b64encode(b"0123456789ab").decode().rstrip("="),
            # Minimum AES-GCM ciphertext plus 16-byte auth tag; this is test data, not plaintext.
            "ciphertext": base64.urlsafe_b64encode((marker.encode() + b"0123456789abcdef")).decode().rstrip("="),
        }

    def test_account_creation_duplicate_and_password_login(self):
        self.assertEqual("music@example.net", self.account["email"])
        self.assertEqual(36, len(self.account["accountId"]))
        status, duplicate = self.request(
            "POST", "/v1/accounts", {"email": "music@example.net", "password": "correct horse battery"}
        )
        self.assertEqual(409, status)
        self.assertIn("already exists", duplicate["error"])

        status, session = self.request(
            "POST", "/v1/sessions", {"email": "MUSIC@example.net", "password": "correct horse battery"}
        )
        self.assertEqual(200, status)
        self.assertEqual(self.account["accountId"], session["accountId"])
        self.assertNotEqual(self.account["token"], session["token"])

    def test_invalid_password_and_unauthenticated_access_are_rejected(self):
        status, _ = self.request("POST", "/v1/accounts", {"email": "bad", "password": "short"})
        self.assertEqual(400, status)
        status, _ = self.request("POST", "/v1/sessions", {"email": "music@example.net", "password": "wrong password"})
        self.assertEqual(401, status)
        status, _ = self.request("GET", "/v1/events")
        self.assertEqual(401, status)

    def test_ciphertext_is_scoped_to_account_and_pagination_is_ordered(self):
        token = self.account["token"]
        first = self.encrypted_event(marker="first")
        second = self.encrypted_event(marker="second")
        status, pushed = self.request("POST", "/v1/events", {"events": [first, second]}, token)
        self.assertEqual(200, status)
        self.assertEqual([1, 2], [item["sequence"] for item in pushed["accepted"]])

        status, page = self.request("GET", "/v1/events?after=0&limit=1", token=token)
        self.assertEqual(200, status)
        self.assertEqual(1, len(page["events"]))
        self.assertTrue(page["hasMore"])
        self.assertEqual(1, page["nextCursor"])
        self.assertEqual(first["ciphertext"], page["events"][0]["ciphertext"])

        _, other = self.request(
            "POST", "/v1/accounts", {"email": "other@example.net", "password": "another strong pass"}
        )
        _, empty = self.request("GET", "/v1/events", token=other["token"])
        self.assertEqual([], empty["events"])

    def test_retries_are_idempotent_and_sessions_can_be_revoked(self):
        token = self.account["token"]
        event = self.encrypted_event()
        _, first = self.request("POST", "/v1/events", {"events": [event]}, token)
        _, retry = self.request("POST", "/v1/events", {"events": [event]}, token)
        self.assertEqual(first["accepted"], retry["accepted"])
        self.assertEqual(1, retry["latestSequence"])
        changed_retry = self.encrypted_event(event_id=event["id"], marker="changed-payload")
        self.assertEqual(400, self.request("POST", "/v1/events", {"events": [changed_retry]}, token)[0])
        self.assertEqual(200, self.request("DELETE", "/v1/sessions/current", token=token)[0])
        self.assertEqual(401, self.request("GET", "/v1/events", token=token)[0])

    def test_invalid_event_envelopes_are_rejected(self):
        status, _ = self.request("POST", "/v1/events", {"events": [{"id": "not-a-uuid", "iv": "x", "ciphertext": "x"}]}, self.account["token"])
        self.assertEqual(400, status)
        status, _ = self.request("POST", "/v1/events", {"events": []}, self.account["token"])
        self.assertEqual(400, status)

    def test_compaction_serves_checkpoint_and_prunes_covered_retry_receipts(self):
        token = self.account["token"]
        events = [self.encrypted_event(marker=f"event-{n}") for n in range(3)]
        self.request("POST", "/v1/events", {"events": events}, token)
        import base64
        snapshot = {
            "id": str(uuid.uuid4()),
            "throughCursor": 2,
            "iv": base64.urlsafe_b64encode(b"0123456789ab").decode().rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(b"encrypted-snapshot-payload").decode().rstrip("="),
        }
        status, result = self.request("POST", "/v1/snapshots", {"snapshot": snapshot}, token)
        self.assertEqual(200, status)
        self.assertEqual(2, result["snapshotThrough"])
        self.assertTrue(result["compacted"])

        _, page = self.request("GET", "/v1/events?after=0&limit=10", token=token)
        self.assertEqual(snapshot["id"], page["snapshot"]["id"])
        self.assertEqual(2, page["snapshotThrough"])
        self.assertEqual([3], [event["sequence"] for event in page["events"]])
        self.assertEqual(1, page["eventCount"])

        with app.db_session(self.db_path) as db:
            self.assertEqual(1, db.execute("SELECT COUNT(*) FROM sync_events").fetchone()[0])
            self.assertEqual(0, db.execute(
                "SELECT COUNT(*) FROM sync_event_receipts WHERE account_id = ? AND sequence <= 2",
                (self.account["accountId"],),
            ).fetchone()[0])

        next_event = self.encrypted_event(marker="after-compaction")
        _, appended = self.request("POST", "/v1/events", {"events": [next_event]}, token)
        self.assertEqual(4, appended["accepted"][0]["sequence"])

    def test_youtube_audio_requires_auth_permission_and_a_single_video_id(self):
        token = self.account["token"]
        status, _ = self.request(
            "POST", "/v1/youtube/audio", {"videoId": "bad-id", "authorized": True}, token
        )
        self.assertEqual(400, status)
        status, _ = self.request(
            "POST", "/v1/youtube/audio", {"videoId": "abcdefghijk", "authorized": False}, token
        )
        self.assertEqual(403, status)
        status, _ = self.request(
            "POST", "/v1/youtube/audio", {"videoId": "abcdefghijk", "authorized": True}
        )
        self.assertEqual(401, status)

    def test_youtube_extractor_requests_public_audio_only_without_credentials(self):
        captured = {}

        class FakeDownloader:
            def __init__(self, options):
                captured["options"] = options

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def extract_info(self, url, download):
                captured["url"] = url
                captured["download"] = download
                (output_dir / "youtube-audio.m4a").write_bytes(b"audio-only")

        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            fake_yt_dlp = type("FakeYtDlp", (), {"YoutubeDL": FakeDownloader})
            with patch.dict(sys.modules, {"yt_dlp": fake_yt_dlp}):
                path, content_type = app.extract_youtube_audio("abcdefghijk", output_dir)
                self.assertEqual("audio/mp4", content_type)
                self.assertEqual(b"audio-only", path.read_bytes())
        self.assertEqual("https://www.youtube.com/watch?v=abcdefghijk", captured["url"])
        self.assertTrue(captured["download"])
        self.assertIn("bestaudio", captured["options"]["format"])
        self.assertTrue(captured["options"]["noplaylist"])
        self.assertFalse({"cookiefile", "cookiesfrombrowser", "username", "password"} & set(captured["options"]))

    def test_youtube_audio_streams_only_audio_and_cleans_temporary_file(self):
        generated_paths = []
        original_extractor = app.extract_youtube_audio

        def fake_extractor(video_id, output_dir):
            self.assertEqual("abcdefghijk", video_id)
            path = output_dir / "youtube-audio.m4a"
            path.write_bytes(b"test-audio-bytes")
            generated_paths.append(path)
            return path, "audio/mp4"

        app.extract_youtube_audio = fake_extractor
        try:
            body = json.dumps({"videoId": "abcdefghijk", "authorized": True}).encode()
            request = urllib.request.Request(
                self.base + "/v1/youtube/audio", data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.account['token']}"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(200, response.status)
                self.assertEqual("audio/mp4", response.headers.get_content_type())
                self.assertIn("youtube-audio.m4a", response.headers.get("Content-Disposition", ""))
                self.assertEqual(b"test-audio-bytes", response.read())
            self.assertEqual(1, len(generated_paths))
            deadline = time.monotonic() + 1
            while generated_paths[0].exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(generated_paths[0].exists())
        finally:
            app.extract_youtube_audio = original_extractor

    def test_registration_rate_limit_applies_per_client_address(self):
        for index in range(4):
            status, _ = self.request(
                "POST", "/v1/accounts",
                {"email": f"extra-{index}@example.net", "password": "another strong pass"},
            )
            self.assertEqual(201, status)
        status, result = self.request(
            "POST", "/v1/accounts",
            {"email": "rate-limited@example.net", "password": "another strong pass"},
        )
        self.assertEqual(429, status)
        self.assertIn("Too many requests", result["error"])

    def test_rate_limiter_uses_forwarded_address_from_local_proxy(self):
        forwarded = {"X-Forwarded-For": "192.0.2.10"}
        for index in range(5):
            status, _ = self.request(
                "POST", "/v1/accounts",
                {"email": f"proxy-{index}@example.net", "password": "another strong pass"},
                extra_headers=forwarded,
            )
            self.assertEqual(201, status)
        self.assertEqual(
            429,
            self.request(
                "POST", "/v1/accounts",
                {"email": "proxy-limited@example.net", "password": "another strong pass"},
                extra_headers=forwarded,
            )[0],
        )
        self.assertEqual(
            201,
            self.request(
                "POST", "/v1/accounts",
                {"email": "other-forwarded-ip@example.net", "password": "another strong pass"},
                extra_headers={"X-Forwarded-For": "192.0.2.11"},
            )[0],
        )

    def test_account_event_quota_is_enforced(self):
        previous_limit = app.MAX_ACCOUNT_SYNC_BYTES
        try:
            app.MAX_ACCOUNT_SYNC_BYTES = 1
            with self.assertRaises(app.QuotaExceededError):
                app.append_events(self.db_path, self.account["accountId"], [self.encrypted_event()])
        finally:
            app.MAX_ACCOUNT_SYNC_BYTES = previous_limit

    def test_account_deletion_removes_sessions_and_encrypted_data(self):
        token = self.account["token"]
        self.request("POST", "/v1/events", {"events": [self.encrypted_event()]}, token)
        status, result = self.request("DELETE", "/v1/account/current", token=token)
        self.assertEqual(200, status)
        self.assertTrue(result["deleted"])
        self.assertEqual(401, self.request("GET", "/v1/events", token=token)[0])
        self.assertEqual(
            401,
            self.request("POST", "/v1/sessions", {
                "email": "music@example.net", "password": "correct horse battery"
            })[0],
        )
        with app.db_session(self.db_path) as db:
            for table in ("accounts", "sessions", "sync_events", "sync_event_receipts", "sync_snapshots"):
                self.assertEqual(0, db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def test_stale_extraction_folders_are_swept_but_recent_ones_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stale = root / f"{app.EXTRACTION_TMP_PREFIX}stale"
            fresh = root / f"{app.EXTRACTION_TMP_PREFIX}fresh"
            unrelated = root / "other-tool-data"
            for folder in (stale, fresh, unrelated):
                folder.mkdir()
                (folder / "youtube-audio.m4a").write_bytes(b"audio")
            old = time.time() - 7200
            for folder in (stale, unrelated):
                os.utime(folder, (old, old))

            removed = app.clean_stale_extraction_dirs(max_age_seconds=3600, root=root)

            self.assertEqual(1, removed)
            self.assertFalse(stale.exists())
            # A folder that is still in use, or belongs to something else, is left alone.
            self.assertTrue(fresh.exists())
            self.assertTrue(unrelated.exists())

    def test_slow_request_bodies_time_out(self):
        original = app.REQUEST_TIMEOUT_SECONDS
        app.REQUEST_TIMEOUT_SECONDS = 0.3
        httpd = None
        try:
            httpd = app.ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(self.db_path))
            httpd.daemon_threads = True
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5) as client:
                # Promise a body, then never send it: the server must not wait forever.
                client.sendall(
                    b"POST /v1/accounts HTTP/1.1\r\nHost: test\r\n"
                    b"Content-Type: application/json\r\nContent-Length: 40\r\n"
                    b"Connection: close\r\n\r\n"
                )
                client.settimeout(5)
                response = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            status_line = response.split(b"\r\n", 1)[0]
            self.assertIn(b" 408 ", status_line, status_line)
            self.assertIn(b"did not arrive", response)
        finally:
            app.REQUEST_TIMEOUT_SECONDS = original
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()

    @unittest.skipUnless(os.name == "posix" and hasattr(signal, "SIGTERM"), "POSIX signals only")
    def test_sigterm_drains_requests_in_progress_and_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            log_path = Path(directory) / "server.log"
            environment = dict(
                os.environ,
                SOUNDTRAIL_DB=str(Path(directory) / "server.sqlite3"),
                SOUNDTRAIL_BACKUP_INTERVAL_SECONDS="0",
                SOUNDTRAIL_HOST="127.0.0.1",
                PORT=str(port),
                PYTHONUNBUFFERED="1",
            )
            with log_path.open("w") as log:
                process = subprocess.Popen(
                    [sys.executable, str(Path(app.__file__).resolve())],
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            try:
                self._wait_for_health(port, process)
                body = json.dumps(
                    {"email": "drain@example.net", "password": "correct horse battery"}
                ).encode()
                client = socket.create_connection(("127.0.0.1", port), timeout=10)
                try:
                    # Start a request, ask the server to stop, then finish the upload: the
                    # response must still arrive and the process must exit with status 0.
                    client.sendall(
                        b"POST /v1/accounts HTTP/1.1\r\nHost: test\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        + body[:5]
                    )
                    time.sleep(0.3)
                    process.send_signal(signal.SIGTERM)
                    time.sleep(0.7)
                    client.sendall(body[5:])
                    response = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                finally:
                    client.close()
                self.assertIn(b" 201 ", response.split(b"\r\n", 1)[0])
                self.assertEqual(0, process.wait(timeout=15))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            log_text = log_path.read_text()
            self.assertIn("Received SIGTERM", log_text)
            self.assertIn("Soundtrail sync API stopped.", log_text)

    @staticmethod
    def _wait_for_health(port, process):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("the server exited before answering /health")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.1)
        raise AssertionError("the server did not become healthy in time")

    def test_retry_receipt_backfill_runs_once_per_database(self):
        self.request("POST", "/v1/events", {"events": [self.encrypted_event(marker="kept")]}, self.account["token"])
        # Rewind to a database written before receipts and the schema marker existed.
        with app.db_session(self.db_path) as db:
            db.execute("DELETE FROM sync_event_receipts")
            db.execute("DELETE FROM schema_meta")

        app.initialize_db(self.db_path)

        with app.db_session(self.db_path) as db:
            rebuilt = db.execute("SELECT COUNT(*) FROM sync_event_receipts").fetchone()[0]
            version = db.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()[0]
            self.assertEqual(1, rebuilt)
            self.assertEqual(str(app.SCHEMA_VERSION), version)
            # Starting again must not rescan and rewrite the receipt table; prove it by removing a
            # receipt and checking that the next start leaves it removed.
            db.execute("DELETE FROM sync_event_receipts")

        app.initialize_db(self.db_path)

        with app.db_session(self.db_path) as db:
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM sync_event_receipts").fetchone()[0])

    def test_health_is_public(self):
        status, data = self.request("GET", "/health")
        self.assertEqual(200, status)
        self.assertEqual("ok", data["status"])


if __name__ == "__main__":
    unittest.main()
