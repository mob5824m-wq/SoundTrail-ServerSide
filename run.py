#!/usr/bin/env python3
"""Cross-platform launcher for the Soundtrail sync server (no Docker, any OS/CPU).

    python3 run.py              # create .venv if needed, install dependencies, start
    python3 run.py --setup      # only prepare the environment, do not start
    python3 run.py --test       # run the API test suite inside the environment

Managed backups use the standard library only, so they work even before (or without) a venv:

    python3 run.py backup       # write a verified snapshot now
    python3 run.py list         # snapshots, newest first
    python3 run.py verify       # check the newest snapshot
    python3 run.py restore NAME --yes   # replace the database (stop the server first)

Requires Python 3.10+ on the PATH (`py -3` on Windows). The sync API needs only the
standard library; yt-dlp is needed only for the optional YouTube audio endpoint, and
FFmpeg is needed by yt-dlp to assemble some audio streams.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
VENV_DIR = SERVER_DIR / ".venv"
REQUIREMENTS = SERVER_DIR / "requirements.txt"
REQUIREMENTS_JS = SERVER_DIR / "requirements-js.txt"
STAMP = VENV_DIR / ".soundtrail-requirements.sha256"
MIN_PYTHON = (3, 10)


def venv_python() -> Path:
    # Windows puts the interpreter in Scripts\ and adds .exe; POSIX uses bin/.
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def run(command: list[str]) -> int:
    print("+ " + " ".join(command), flush=True)
    return subprocess.call(command, cwd=SERVER_DIR)


def requirements_digest() -> str:
    digest = hashlib.sha256()
    for path in (REQUIREMENTS, REQUIREMENTS_JS):
        if path.exists():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def ensure_environment() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.exit(f"Soundtrail needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+; found {sys.version.split()[0]}.")

    if not venv_python().exists():
        print(f"Creating virtual environment in {VENV_DIR} ...", flush=True)
        venv.EnvBuilder(with_pip=True, clear=True).create(VENV_DIR)

    python = str(venv_python())
    digest = requirements_digest()
    if STAMP.exists() and STAMP.read_text().strip() == digest:
        return

    # Core dependencies must install; failure here is fatal.
    if run([python, "-m", "pip", "install", "--upgrade", "pip"]) != 0:
        print("Warning: could not upgrade pip; continuing with the bundled version.", flush=True)
    if run([python, "-m", "pip", "install", "-r", str(REQUIREMENTS)]) != 0:
        sys.exit("Installing the core requirements failed (see the pip output above).")

    # The JavaScript runtime is optional: some platforms have no prebuilt wheel for it.
    if run([python, "-m", "pip", "install", "-r", str(REQUIREMENTS_JS)]) != 0:
        print(
            "Warning: the optional Deno runtime is unavailable for this platform. "
            "YouTube audio extraction will use a Deno or Node.js runtime from PATH if present.",
            flush=True,
        )

    STAMP.write_text(digest + "\n")


def check_ffmpeg() -> None:
    if shutil.which("ffmpeg") is None:
        print(
            "Note: FFmpeg was not found on PATH. The sync API works without it; install FFmpeg "
            "to enable YouTube audio extraction for streams that need assembling.",
            flush=True,
        )


def main(argv: list[str]) -> int:
    # The backup tool is stdlib-only and deliberately usable before dependencies are installed.
    if argv and argv[0] in {"backup", "list", "verify", "restore"}:
        command = [sys.executable, str(SERVER_DIR / "backup.py"), *argv]
        try:
            return subprocess.call(command, cwd=SERVER_DIR)
        except KeyboardInterrupt:
            return 0
    ensure_environment()
    if "--setup" in argv:
        check_ffmpeg()
        print("Environment ready.", flush=True)
        return 0
    if "--test" in argv:
        return run([str(venv_python()), "-m", "unittest", "discover", "-s", str(SERVER_DIR), "-v"])

    check_ffmpeg()
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        return subprocess.call([str(venv_python()), str(SERVER_DIR / "app.py")], cwd=SERVER_DIR, env=env)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
