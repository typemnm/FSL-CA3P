"""A process-level reset contract test with a disposable HTTP/SQLite child."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "reset-supervisor.py"
SPEC = importlib.util.spec_from_file_location("wonchang_reset_supervisor", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reset = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reset
SPEC.loader.exec_module(reset)

CHILD = r'''
import http.server, json, os, sqlite3
from pathlib import Path
db_path = Path(os.environ['TEST_DB'])
db_path.parent.mkdir(parents=True, exist_ok=True)
db = sqlite3.connect(db_path)
counts = {'users': 5, 'posts': 18, 'events': 5, 'requests': 2, 'staff_cases': 4, 'settings': 2}
for table, count in counts.items():
    db.execute(f'CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY)')
    if db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0:
        db.executemany(f'INSERT INTO {table} DEFAULT VALUES', [()] * count)
db.commit()
sessions = 0
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        global sessions
        if self.path == '/_diag/config':
            body = json.dumps({'site': 'wonchang', 'database': str(db_path), 'activeSessions': sessions}).encode()
        elif self.path == '/login':
            sessions += 1
            body = b'logged in'
        elif self.path == '/mutate':
            db.execute('INSERT INTO posts DEFAULT VALUES')
            db.commit()
            body = b'mutated'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json' if self.path == '/_diag/config' else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(('127.0.0.1', int(os.environ['TEST_PORT'])), Handler).serve_forever()
'''


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def fetch(url: str, *, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    headers = {}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=payload, headers=headers,
                                     method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


class WonchangResetSupervisorTest(unittest.TestCase):
    def test_docker_configuration_rejects_other_targets_and_hides_token_from_child(self) -> None:
        token = "a" * 64
        env = {
            "CA3P_WONCHANG_RESET_TOKEN": token,
            "CA3P_WONCHANG_RESET_BIND": "0.0.0.0",
            "CA3P_WONCHANG_RESET_PORT": "54102",
            "CA3P_WONCHANG_TARGET_ORIGIN": "http://wonchang:4102",
            "CA3P_WONCHANG_RESET_BACKUP_ROOT": "/app/.reset-backups",
            "SERVER_ADDRESS": "0.0.0.0",
            "SERVER_PORT": "4102",
            "WONCHANG_DB_PATH": "/app/data/wonchang.sqlite",
        }
        config = reset.Config.from_environment(env)
        self.assertEqual(config.target_origin, "http://wonchang:4102")
        self.assertNotIn("CA3P_WONCHANG_RESET_TOKEN", config.child_env)
        loopback = reset.Config.from_environment({**env, "CA3P_WONCHANG_TARGET_ORIGIN": "http://127.0.0.1:4102"})
        self.assertEqual(loopback.target_origin, "http://127.0.0.1:4102")
        for key, value in (("CA3P_WONCHANG_TARGET_ORIGIN", "http://other:4102"),
                           ("CA3P_WONCHANG_RESET_BACKUP_ROOT", "/app/data"),
                           ("CA3P_WONCHANG_RESET_TOKEN", "short")):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    reset.Config.from_environment({**env, key: value})

    def test_authenticated_reset_restarts_process_and_restores_baseline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ca3p-wonchang-reset-") as temporary:
            root = Path(temporary)
            child_file = root / "child.py"
            child_file.write_text(CHILD, encoding="utf-8")
            database = root / "data" / "wonchang.sqlite"
            target_port, management_port = free_port(), free_port()
            token = "local-reset-token-0123456789abcdef"
            config = reset.Config(
                token=token, management_bind="127.0.0.1", management_port=management_port,
                target_origin=f"http://127.0.0.1:{target_port}", target_port=target_port,
                database_path=database, backup_root=root / "backups",
                child_command=(sys.executable, str(child_file)), child_workdir=root,
                child_env={**os.environ, "TEST_DB": str(database), "TEST_PORT": str(target_port)},
                startup_timeout=5,
            )
            supervisor = reset.Supervisor(config)
            supervisor.start_child()
            server = reset.management_server(supervisor)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                manager = f"http://127.0.0.1:{management_port}"
                body = {"confirmation": "reset-experiment-target", "fixtureId": reset.FIXTURE_ID,
                        "targetOrigin": config.target_origin}
                self.assertEqual(fetch(manager + "/health")[0], 200)
                self.assertEqual(fetch(manager + reset.RESET_PATH, body=body)[0], 401)
                self.assertEqual(fetch(manager + reset.RESET_PATH,
                                       body={**body, "targetOrigin": "http://wrong:4102"}, token=token)[0], 400)
                with urllib.request.urlopen(supervisor.local_origin + "/login", timeout=3):
                    pass
                with urllib.request.urlopen(supervisor.local_origin + "/mutate", timeout=3):
                    pass
                old_pid = supervisor.child.pid
                unknown = database.parent / "unrelated.txt"
                unknown.write_text("keep", encoding="utf-8")
                self.assertEqual(fetch(manager + reset.RESET_PATH, body=body, token=token)[0], 503)
                self.assertEqual(unknown.read_text(encoding="utf-8"), "keep")
                self.assertIsNotNone(supervisor.child)
                self.assertIsNone(supervisor.child.poll())
                unknown.unlink()
                status, result = fetch(manager + reset.RESET_PATH, body=body, token=token)
                self.assertEqual(status, 200)
                self.assertEqual(result, {"status": "clean", "fixtureId": reset.FIXTURE_ID,
                                          "targetOrigin": config.target_origin, "scopes": list(reset.SCOPES)})
                self.assertNotEqual(supervisor.child.pid, old_pid)
                self.assertEqual(supervisor.target_health()["activeSessions"], 0)
                reset.verify_baseline(database)
                self.assertEqual(len(list(config.backup_root.iterdir())), 1)
            finally:
                supervisor.closing = True
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                supervisor.stop_child()


if __name__ == "__main__":
    unittest.main()
