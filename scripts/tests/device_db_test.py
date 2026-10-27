"""Exercise deployment DB operations exclusively with disposable SQLite files."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/device-db.py"


class DeviceDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ca3p-device-db-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_db = self.root / "runtime/runs.sqlite"
        self.case_db = self.root / "data/cases.sqlite3"
        self.backup = self.root / "backup"

    def cli(self, command, *arguments, success=True):
        environment = {**os.environ, "PYTHONPATH": str(ROOT / "casper-db/src")}
        result = subprocess.run([sys.executable, str(SCRIPT), command, *map(str, arguments)],
                                capture_output=True, text=True, env=environment)
        output = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0 if success else 1, result.stdout + result.stderr)
        self.assertEqual(output["ok"], success)
        return output

    def both(self):
        return ["--run-db", self.run_db, "--case-db", self.case_db]

    def create_run(self, wal=False):
        self.run_db.parent.mkdir(parents=True)
        connection = sqlite3.connect(self.run_db)
        self.addCleanup(connection.close)
        if wal:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.executescript("""
            CREATE TABLE runs(id TEXT PRIMARY KEY, status TEXT, manifest_json TEXT, state_json TEXT);
            CREATE TABLE jobs(id TEXT);
            CREATE TABLE run_events(run_id TEXT);
            CREATE TABLE action_intents(run_id TEXT);
            CREATE TABLE model_calls(run_id TEXT);
            CREATE TABLE artifacts(run_id TEXT);
            CREATE TABLE review_audit(run_id TEXT);
            PRAGMA user_version=1;
        """)
        connection.execute("INSERT INTO runs VALUES ('run-1','completed','{}','{}')")
        connection.commit()
        return connection

    def create_v5_case(self):
        from casper_db import CaseStore, initialize_database

        initialize_database(self.case_db)
        store = CaseStore(self.case_db)
        case = json.loads((ROOT / "casper-db/examples/case.example.json").read_text())
        store.add(case)
        store.update({**case, "title": "Preserve a second revision"}, expected_revision=1)
        check = json.loads((ROOT / "casper-db/examples/check.example.json").read_text())
        store.add_check(check)
        with sqlite3.connect(self.case_db) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            cases_sql = (ROOT / "casper-db/tests/fixtures/v4-cases.sql").read_text().split(";", 1)[0]
            connection.execute(cases_sql.replace("cases (", "cases_v5 (", 1))
            connection.execute("ALTER TABLE cases_v5 ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
            connection.execute("ALTER TABLE cases_v5 ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")
            old_columns = [row[1] for row in connection.execute("PRAGMA table_info(cases_v5)")]
            names = ",".join(old_columns)
            connection.execute(f"INSERT INTO cases_v5 ({names}) SELECT {names} FROM cases")
            checks_sql = (ROOT / "casper-db/src/casper_db/checks.sql").read_text().split(";", 1)[0]
            checks_sql = "\n".join(line for line in checks_sql.splitlines()
                                    if not any(token in line for token in (
                                        "parameter_not_applicable", "observed_evidence",
                                        "OR (parameter_not_applicable")))
            connection.execute(checks_sql.replace("checks (", "checks_v5 (", 1))
            names = ",".join(row[1] for row in connection.execute("PRAGMA table_info(checks_v5)"))
            connection.execute(f"INSERT INTO checks_v5 ({names}) SELECT {names} FROM checks")
            connection.execute("DROP TABLE checks")
            connection.execute("DROP TABLE cases")
            connection.execute("ALTER TABLE cases_v5 RENAME TO cases")
            connection.execute("ALTER TABLE checks_v5 RENAME TO checks")
            connection.execute("PRAGMA user_version=5")

    def test_inspect_absent_does_not_create_database_or_parent(self):
        output = self.cli("inspect", *self.both())
        self.assertFalse(output["databases"]["run"]["exists"])
        self.assertFalse(output["databases"]["case"]["exists"])
        self.assertFalse(self.run_db.parent.exists())
        self.assertFalse(self.case_db.parent.exists())

    def test_online_backup_includes_committed_wal_and_keeps_sources_unchanged(self):
        connection = self.create_run(wal=True)
        main_bytes = self.run_db.read_bytes()
        wal_bytes = Path(str(self.run_db) + "-wal").read_bytes()
        output = self.cli("backup", *self.both(), "--output", self.backup)
        self.assertEqual(output["databases"]["run"]["info"]["counts"]["runs"], 1)
        self.assertEqual(self.run_db.read_bytes(), main_bytes)
        self.assertEqual(Path(str(self.run_db) + "-wal").read_bytes(), wal_bytes)
        self.assertEqual(connection.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
        with sqlite3.connect(self.backup / "run.sqlite3") as copied:
            self.assertEqual(copied.execute("SELECT id FROM runs").fetchone()[0], "run-1")
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)
        for name in ("manifest.json", "run.sqlite3"):
            self.assertEqual((self.backup / name).stat().st_mode & 0o777, 0o600)

    def test_v5_to_v7_preserves_cases_checks_and_revision_snapshots(self):
        self.create_v5_case()
        with sqlite3.connect(self.case_db) as connection:
            snapshots = connection.execute("SELECT * FROM case_versions ORDER BY revision").fetchall()
        output = self.cli("migrate", "--case-db", self.case_db)
        self.assertEqual(output["before"]["userVersion"], 5)
        self.assertEqual(output["after"]["userVersion"], 7)
        self.assertEqual(output["after"]["counts"], {"cases": 1, "checks": 1, "case_versions": 2})
        self.assertEqual(output["after"]["foreignKeyCheck"], "ok")
        self.assertTrue(output["changed"])
        with sqlite3.connect(self.case_db) as connection:
            self.assertEqual(connection.execute("SELECT * FROM case_versions ORDER BY revision").fetchall(), snapshots)
            self.assertEqual(connection.execute("SELECT title,revision FROM cases").fetchone(),
                             ("Preserve a second revision", 2))
        second = self.cli("migrate", "--case-db", self.case_db)
        self.assertFalse(second["changed"])
        self.assertEqual(self.case_db.stat().st_mode & 0o777, 0o600)

    def test_unrelated_case_database_is_not_migrated(self):
        self.case_db.parent.mkdir(parents=True)
        with sqlite3.connect(self.case_db) as connection:
            connection.execute("CREATE TABLE unrelated(secret TEXT)")
            connection.execute("INSERT INTO unrelated VALUES ('keep')")
            connection.execute("PRAGMA user_version=5")
        original = self.case_db.read_bytes()
        output = self.cli("migrate", "--case-db", self.case_db, success=False)
        self.assertIn("unrelated", output["error"])
        self.assertEqual(self.case_db.read_bytes(), original)

    def test_missing_databases_restore_to_absence_after_failed_first_install(self):
        self.cli("backup", *self.both(), "--output", self.backup)
        self.cli("migrate", "--case-db", self.case_db)
        self.create_run().close()
        output = self.cli("restore", *self.both(), "--backup", self.backup)
        self.assertFalse(output["databases"]["run"]["exists"])
        self.assertFalse(output["databases"]["case"]["exists"])

    def test_restore_returns_v5_and_existing_run_rows_and_removes_sidecars(self):
        self.create_v5_case()
        self.create_run().close()
        self.cli("backup", *self.both(), "--output", self.backup)
        self.cli("migrate", "--case-db", self.case_db)
        self.run_db.write_bytes(b"broken by a failed release")
        for suffix in ("-wal", "-shm"):
            Path(str(self.run_db) + suffix).write_bytes(b"stopped-writer-sidecar")
        output = self.cli("restore", *self.both(), "--backup", self.backup)
        self.assertEqual(output["databases"]["case"]["userVersion"], 5)
        self.assertEqual(output["databases"]["run"]["counts"]["runs"], 1)
        self.assertFalse(Path(str(self.run_db) + "-wal").exists())
        self.assertFalse(Path(str(self.run_db) + "-shm").exists())

    def test_tampered_second_backup_is_rejected_before_either_target_is_modified(self):
        self.create_v5_case()
        self.create_run().close()
        self.cli("backup", *self.both(), "--output", self.backup)
        original_run = self.run_db.read_bytes()
        original_case = self.case_db.read_bytes()
        with (self.backup / "case.sqlite3").open("ab") as file:
            file.write(b"tampering")
        output = self.cli("restore", *self.both(), "--backup", self.backup, success=False)
        self.assertIn("hash or size", output["error"])
        self.assertEqual(self.run_db.read_bytes(), original_run)
        self.assertEqual(self.case_db.read_bytes(), original_case)

    def test_manifest_cannot_restore_to_another_path(self):
        self.cli("backup", *self.both(), "--output", self.backup)
        other = self.root / "other.sqlite3"
        self.cli("restore", "--run-db", other, "--case-db", self.case_db,
                 "--backup", self.backup, success=False)
        self.assertFalse(other.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
