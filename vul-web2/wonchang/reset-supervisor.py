#!/usr/bin/env python3
"""Own the Docker Wonchang process and its authenticated experiment reset.

The normal image entrypoint remains the Java application. The Docker reset
overlay opts into this supervisor and gives it a private backup volume.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


FIXTURE_ID = "vul-web2-wonchang"
RESET_PATH = "/_ca3p/experiment-reset"
SCOPES = ("database", "sessions", "process", "files")
RUNTIME_NAMES = frozenset(
    ("wonchang.sqlite", "wonchang.sqlite-wal", "wonchang.sqlite-shm", "wonchang.sqlite-journal")
)
BASELINE_COUNTS = {
    "users": 5,
    "posts": 18,
    "events": 5,
    "requests": 2,
    "staff_cases": 4,
    "settings": 2,
}
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~+/-]{32,512}\Z")


@dataclass(frozen=True)
class Config:
    token: str
    management_bind: str
    management_port: int
    target_origin: str
    target_port: int
    database_path: Path
    backup_root: Path
    child_command: tuple[str, ...]
    child_workdir: Path
    child_env: dict[str, str]
    startup_timeout: float = 12.0

    @classmethod
    def from_environment(cls, env: dict[str, str]) -> "Config":
        token = env.get("CA3P_WONCHANG_RESET_TOKEN", "")
        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("CA3P_WONCHANG_RESET_TOKEN must contain 32–512 safe characters")
        management_bind = env.get("CA3P_WONCHANG_RESET_BIND", "127.0.0.1")
        if management_bind not in ("127.0.0.1", "0.0.0.0"):
            raise ValueError("Invalid Wonchang management bind address")
        port_text = env.get("CA3P_WONCHANG_RESET_PORT", "54102")
        if not port_text.isdecimal() or not 1 <= int(port_text) <= 65535 or int(port_text) == 4102:
            raise ValueError("Invalid Wonchang management port")
        target_origin = env.get("CA3P_WONCHANG_TARGET_ORIGIN", "")
        if target_origin != "http://wonchang:4102":
            raise ValueError("Docker Wonchang reset must target http://wonchang:4102")
        if env.get("SERVER_PORT", "4102") != "4102" or env.get("SERVER_ADDRESS") != "0.0.0.0":
            raise ValueError("Docker Wonchang must listen on 0.0.0.0:4102")
        database_path = Path(env.get("WONCHANG_DB_PATH", "/app/data/wonchang.sqlite"))
        backup_root = Path(env.get("CA3P_WONCHANG_RESET_BACKUP_ROOT", "/app/.reset-backups"))
        if database_path != Path("/app/data/wonchang.sqlite") or backup_root != Path("/app/.reset-backups"):
            raise ValueError("Unexpected Docker Wonchang data or backup path")
        child_env = dict(env)
        for key in tuple(child_env):
            if key.startswith("CA3P_WONCHANG_RESET_") or key == "CA3P_EXPERIMENT_RESET_TARGETS":
                child_env.pop(key)
        return cls(token, management_bind, int(port_text), target_origin, 4102,
                   database_path, backup_root, ("java", "-jar", "/app/wonchang.jar"),
                   Path("/app"), child_env)


@dataclass(frozen=True)
class Backup:
    directory: Path
    digests: dict[str, str]


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise ValueError("Unsafe Wonchang runtime file")


def runtime_files(database_path: Path, *, require_database: bool = True) -> list[Path]:
    directory = database_path.parent
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise ValueError("Unsafe Wonchang data directory")
    files = []
    for path in sorted(directory.iterdir()):
        if path.name not in RUNTIME_NAMES:
            raise ValueError("Unexpected Wonchang runtime file")
        regular_file(path)
        files.append(path)
    if require_database and database_path not in files:
        raise ValueError("Wonchang database is missing")
    return files


def copy_private(source: Path, destination: Path) -> None:
    regular_file(source)
    descriptor = None
    created = False
    try:
        with source.open("rb") as input_file:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            output_file = os.fdopen(descriptor, "wb")
            descriptor = None
            with output_file:
                shutil.copyfileobj(input_file, output_file, 65536)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            destination.unlink(missing_ok=True)
        raise


def create_backup(database_path: Path, backup_root: Path) -> Backup:
    files = runtime_files(database_path)
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = backup_root.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise ValueError("Unsafe Wonchang backup directory")
    directory = backup_root / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4()}"
    directory.mkdir(mode=0o700)
    digests = {}
    for path in files:
        destination = directory / path.name
        copy_private(path, destination)
        source_digest = file_digest(path)
        if file_digest(destination) != source_digest:
            raise ValueError("Wonchang backup verification failed")
        digests[path.name] = source_digest
    return Backup(directory, digests)


def remove_runtime_files(database_path: Path) -> None:
    for path in runtime_files(database_path):
        path.unlink()


def restore_backup(database_path: Path, backup: Backup) -> None:
    for name, digest in backup.digests.items():
        source = backup.directory / name
        regular_file(source)
        if file_digest(source) != digest:
            raise ValueError("Wonchang backup changed before recovery")
    for path in runtime_files(database_path, require_database=False):
        path.unlink()
    for name in backup.digests:
        copy_private(backup.directory / name, database_path.parent / name)


def verify_baseline(database_path: Path) -> None:
    regular_file(database_path)
    connection = sqlite3.connect(database_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Wonchang SQLite integrity check failed")
        for table, expected in BASELINE_COUNTS.items():
            actual = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            if actual != expected:
                raise ValueError(f"Wonchang baseline {table} count differs")
    finally:
        connection.close()


class Supervisor:
    def __init__(self, config: Config):
        self.config = config
        self.child: subprocess.Popen | None = None
        self.generation = 0
        self.reset_lock = threading.Lock()
        self.closing = False

    @property
    def local_origin(self) -> str:
        return f"http://127.0.0.1:{self.config.target_port}"

    def target_health(self) -> dict:
        if self.child is None or self.child.poll() is not None:
            raise RuntimeError("Wonchang child is not running")
        url = self.local_origin + "/_diag/config"
        with urllib.request.urlopen(url, timeout=2) as response:
            if response.status != 200 or response.url != url:
                raise ValueError("Unexpected Wonchang target response")
            if not response.headers.get("Content-Type", "").lower().startswith("application/json"):
                raise ValueError("Wonchang target did not return JSON")
            body = response.read(8193)
            if len(body) > 8192:
                raise ValueError("Wonchang target response is too large")
        result = json.loads(body)
        sessions = result.get("activeSessions")
        if result.get("site") != "wonchang" or result.get("database") != str(self.config.database_path) \
                or type(sessions) is not int or sessions < 0:
            raise ValueError("Unexpected Wonchang target identity")
        return result

    def start_child(self) -> None:
        if self.child is not None:
            raise RuntimeError("Wonchang child is already owned")
        with socket.socket() as probe:
            # Tomcat's recently closed connections can leave TIME_WAIT sockets.
            # Allow the same immediate rebind that the restarted server uses.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", self.config.target_port))
        self.child = subprocess.Popen(self.config.child_command, cwd=self.config.child_workdir,
                                      env=self.config.child_env, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + self.config.startup_timeout
        try:
            while time.monotonic() < deadline:
                if self.child.poll() is not None:
                    raise RuntimeError("Wonchang child exited during startup")
                try:
                    self.target_health()
                    self.generation += 1
                    return
                except (OSError, ValueError, json.JSONDecodeError):
                    time.sleep(0.15)
            raise RuntimeError("Wonchang child did not become healthy")
        except BaseException:
            self.stop_child()
            raise

    def stop_child(self) -> None:
        child = self.child
        self.child = None
        if child is None or child.poll() is not None:
            return
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)

    def reset_target(self) -> dict:
        old_pid = self.child.pid if self.child is not None else None
        self.stop_child()
        try:
            backup = create_backup(self.config.database_path, self.config.backup_root)
        except BaseException:
            self.start_child()
            raise
        try:
            remove_runtime_files(self.config.database_path)
            self.start_child()
            health = self.target_health()
            if health["activeSessions"] != 0 or self.child is None or self.child.pid == old_pid:
                raise ValueError("Wonchang process or sessions were not reset")
            runtime_files(self.config.database_path)
            verify_baseline(self.config.database_path)
            return {"status": "clean", "fixtureId": FIXTURE_ID,
                    "targetOrigin": self.config.target_origin, "scopes": list(SCOPES)}
        except BaseException:
            self.stop_child()
            try:
                restore_backup(self.config.database_path, backup)
                self.start_child()
            except BaseException:
                # The untouched backup remains available for operator recovery.
                pass
            raise


def authorized(header: str | None, token: str) -> bool:
    candidate = header[7:] if isinstance(header, str) and header.startswith("Bearer ") else ""
    return bool(TOKEN_PATTERN.fullmatch(candidate)) and hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(), hashlib.sha256(token.encode()).digest())


def management_server(supervisor: Supervisor) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format_string: str, *args) -> None:
            # Never log Authorization headers or request bodies.
            print(f"Wonchang reset manager: {format_string % args}", file=sys.stderr)

        def respond(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path != "/health":
                self.respond(404, {"error": "not found"})
                return
            if supervisor.closing or supervisor.reset_lock.locked():
                self.respond(503, {"status": "unavailable"})
                return
            try:
                supervisor.target_health()
                self.respond(200, {"status": "ready", "fixtureId": FIXTURE_ID,
                                   "targetOrigin": supervisor.config.target_origin,
                                   "generation": supervisor.generation})
            except (OSError, RuntimeError, ValueError):
                self.respond(503, {"status": "unavailable"})

        def do_POST(self) -> None:
            if self.path != RESET_PATH:
                self.respond(404, {"error": "not found"})
                return
            if not authorized(self.headers.get("Authorization"), supervisor.config.token):
                self.respond(401, {"error": "unauthorized"})
                return
            content_type = self.headers.get("Content-Type", "")
            length = self.headers.get("Content-Length", "")
            if not re.match(r"\Aapplication/json(?:\s*;|\s*\Z)", content_type, re.I) \
                    or not length.isdecimal() or not 1 <= int(length) <= 1024:
                self.respond(400, {"error": "invalid request"})
                return
            try:
                self.connection.settimeout(3)
                received = self.rfile.read(int(length))
                if len(received) != int(length):
                    raise ValueError("incomplete request")
                body = json.loads(received)
            except (OSError, ValueError, UnicodeDecodeError):
                self.respond(400, {"error": "invalid request"})
                return
            if not isinstance(body, dict) or set(body) != {"confirmation", "fixtureId", "targetOrigin"} \
                    or body.get("confirmation") != "reset-experiment-target" \
                    or body.get("fixtureId") != FIXTURE_ID \
                    or body.get("targetOrigin") != supervisor.config.target_origin:
                self.respond(400, {"error": "invalid target confirmation"})
                return
            if supervisor.closing or not supervisor.reset_lock.acquire(blocking=False):
                self.respond(409, {"error": "reset already in progress"})
                return
            try:
                self.respond(200, supervisor.reset_target())
            except BaseException as error:
                print(f"Wonchang reset failed: {error}", file=sys.stderr)
                self.respond(503, {"error": "Wonchang reset could not be verified"})
            finally:
                supervisor.reset_lock.release()

    server = http.server.ThreadingHTTPServer(
        (supervisor.config.management_bind, supervisor.config.management_port), Handler)
    server.daemon_threads = False
    return server


def main() -> int:
    os.umask(0o077)
    supervisor = None
    try:
        config = Config.from_environment(dict(os.environ))
        supervisor = Supervisor(config)
        supervisor.start_child()
        server = management_server(supervisor)
    except BaseException as error:
        if supervisor is not None:
            supervisor.stop_child()
        print(f"Wonchang reset supervisor failed: {error}", file=sys.stderr)
        return 1

    def shutdown(_number, _frame) -> None:
        supervisor.closing = True
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print(f"Wonchang reset supervisor ready on {config.management_bind}:{config.management_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        supervisor.closing = True
        server.server_close()
        supervisor.stop_child()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
