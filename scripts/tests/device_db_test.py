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
        self.chat_db = self.root / "runtime/chat.sqlite"
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
        self.run_db.parent.mkdir(parents=True, exist_ok=True)
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

    def assert_run_tables_restored(self, expected):
        output = self.cli("backup", *self.both(), "--output", self.backup)
        for table, rows in expected.items():
            self.assertEqual(output["databases"]["run"]["info"]["counts"][table], len(rows))
        self.run_db.write_bytes(b"failed deployment")
        self.cli("restore", *self.both(), "--backup", self.backup)
        with sqlite3.connect(self.run_db) as restored:
            for table, rows in expected.items():
                self.assertEqual(restored.execute(f'SELECT * FROM "{table}"').fetchall(), rows)

    def test_experiment_control_extension_is_backed_up_and_restored(self):
        connection = self.create_run()
        connection.executescript("""
            CREATE TABLE experiment_control (
                id INTEGER PRIMARY KEY, status TEXT, owner TEXT, epoch INTEGER,
                last_reset_at TEXT, summary_json TEXT, error TEXT);
            INSERT INTO experiment_control VALUES (1,'failed',NULL,3,NULL,'{}','preserve');
        """)
        rows = connection.execute("SELECT * FROM experiment_control").fetchall()
        connection.close()
        self.assert_run_tables_restored({"experiment_control": rows})

    def test_current_run_repository_schema_and_pending_reset_state_survive_rollback(self):
        # Use the actual application's schema so future extensions cannot silently
        # pass tests against only a historical hand-written fixture.
        module_url = (ROOT / "packages/run-store/index.mjs").as_uri()
        script = (f"import {{createRunRepository}} from {json.dumps(module_url)};"
                  f"const r=createRunRepository({{path:{json.dumps(str(self.run_db))}}});r.close();")
        result = subprocess.run([os.environ.get("CA3P_NODE", "node"), "--input-type=module", "-e", script],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with sqlite3.connect(self.run_db) as connection:
            connection.execute("UPDATE experiment_control SET epoch=4,summary_json='{}' WHERE id=1")
            connection.execute("INSERT OR REPLACE INTO pending_target_resets VALUES (1,?)",
                               ('[{"targetId":"isolated-lab","reason":"preserve"}]',))
            expected = {table: connection.execute(f'SELECT * FROM "{table}"').fetchall()
                        for table in ("experiment_control", "pending_target_resets")}
        self.assert_run_tables_restored(expected)

    def test_unknown_run_tables_are_rejected_without_altering_the_source(self):
        connection = self.create_run()
        connection.execute("CREATE TABLE unrelated(secret TEXT)")
        connection.commit()
        connection.close()
        original = self.run_db.read_bytes()
        output = self.cli("backup", *self.both(), "--output", self.backup, success=False)
        self.assertIn("unknown tables", output["error"])
        self.assertEqual(self.run_db.read_bytes(), original)

    def test_malformed_optional_run_tables_are_rejected(self):
        for table in ("experiment_control", "pending_target_resets"):
            with self.subTest(table=table):
                connection = self.create_run()
                connection.execute(f'CREATE TABLE "{table}"(unrelated TEXT)')
                connection.commit()
                connection.close()
                original = self.run_db.read_bytes()
                output = self.cli("backup", *self.both(), "--output", self.backup / table, success=False)
                self.assertIn(table, output["error"])
                self.assertEqual(self.run_db.read_bytes(), original)
                self.run_db.unlink()

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

    def test_current_case_extensions_survive_backup_migration_and_rollback(self):
        # Exercise the actual feature owners rather than duplicating their DDL.
        from casper_db import CaseStore
        from casper_db.attack_catalog import prepare_catalog_database
        from casper_db.external_vulnerabilities import normalize_external, store_external
        from casper_db.applicability import assess_database
        from casper_db.sync_journal import begin_sync
        from casper_db.dashboard_api import _setup_case_metadata

        prepare_catalog_database(self.case_db)
        case = json.loads((ROOT / "casper-db/examples/case.example.json").read_text())
        CaseStore(self.case_db).add(case)
        bundle = normalize_external("nvd", {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-10000", "descriptions": [{"lang": "en", "value": "Disposable advisory"}],
        }}]})
        self.assertFalse(bundle.rejected_items)
        store_external(self.case_db, [bundle])
        assess_database(self.case_db, {
            "schema_version": "casper-software-inventory-1", "target_id": "LAB-DEMO",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "components": [{"ecosystem": "npm", "package": "disposable", "version": "1.0.0",
                            "source_refs": ["fixture:device-backup"]}],
        }, ["CVE-2026-10000"], apply=True)
        begin_sync(self.case_db, {"target_id": "LAB-DEMO", "started_at": "2026-01-01T00:00:00+00:00",
                                  "inventory_sha256": "a" * 64})
        _setup_case_metadata(self.case_db)
        with sqlite3.connect(self.case_db) as connection:
            connection.execute("INSERT INTO dashboard_case_state VALUES (?,?,?,?)",
                               (case["case_id"], "2026-01-01T00:00:00+00:00", "fixture", "preserve"))
            connection.execute("INSERT INTO dashboard_case_audit VALUES (1,?,?,?,?,?)",
                               (case["case_id"], "archive", "fixture", "2026-01-01T00:00:00+00:00", "{}"))
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            expected = {table: connection.execute(f'SELECT * FROM "{table}"').fetchall() for table in tables}
        self.assertEqual(len(expected), 20)
        backup = self.cli("backup", *self.both(), "--output", self.backup)
        self.assertEqual(backup["databases"]["case"]["info"]["counts"],
                         {table: len(rows) for table, rows in expected.items()})
        migrated = self.cli("migrate", "--case-db", self.case_db)
        self.assertFalse(migrated["changed"])
        self.assertEqual(migrated["preservedCounts"], backup["databases"]["case"]["info"]["counts"])
        self.case_db.write_bytes(b"failed deployment")
        self.cli("restore", *self.both(), "--backup", self.backup)
        with sqlite3.connect(self.case_db) as restored:
            for table, rows in expected.items():
                self.assertEqual(restored.execute(f'SELECT * FROM "{table}"').fetchall(), rows, table)

    def test_malformed_optional_case_namespaces_are_rejected_without_source_changes(self):
        from casper_db import initialize_database

        for table in ("attack_payloads", "external_records", "external_sync_runs", "dashboard_case_state"):
            with self.subTest(table=table):
                initialize_database(self.case_db)
                with sqlite3.connect(self.case_db) as connection:
                    connection.execute(f'CREATE TABLE "{table}"(unrelated TEXT)')
                original = self.case_db.read_bytes()
                output = self.cli("backup", *self.both(), "--output", self.backup / table, success=False)
                self.assertIn(table, output["error"])
                self.assertEqual(self.case_db.read_bytes(), original)
                self.case_db.unlink()

    def test_case_namespace_markers_must_match_their_owners(self):
        from casper_db import initialize_database

        for table in ("attack_catalog_metadata", "external_metadata"):
            for marker in (None, "unrelated-application"):
                with self.subTest(table=table, marker=marker):
                    initialize_database(self.case_db)
                    with sqlite3.connect(self.case_db) as connection:
                        connection.execute(f'CREATE TABLE "{table}"(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                        if marker is not None:
                            connection.execute(f'INSERT INTO "{table}" VALUES (?,?)', ("schema", marker))
                    original = self.case_db.read_bytes()
                    output = self.cli("migrate", "--case-db", self.case_db, success=False)
                    self.assertIn("namespace marker", output["error"])
                    self.assertEqual(self.case_db.read_bytes(), original)
                    self.case_db.unlink()

    def test_separate_intake_namespace_is_not_accepted_as_case_metadata(self):
        from casper_db import initialize_database

        initialize_database(self.case_db)
        with sqlite3.connect(self.case_db) as connection:
            connection.execute("CREATE TABLE dashboard_intake_audit(id INTEGER PRIMARY KEY)")
        original = self.case_db.read_bytes()
        output = self.cli("backup", *self.both(), "--output", self.backup, success=False)
        self.assertIn("unknown tables", output["error"])
        self.assertEqual(self.case_db.read_bytes(), original)

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

    def create_chat(self):
        module_url = (ROOT / "packages/chat-store/index.mjs").as_uri()
        script = (f"import {{createChatRepository}} from {json.dumps(module_url)};"
                  f"const r=createChatRepository({{path:{json.dumps(str(self.chat_db))}}});"
                  "const s=r.createSession({owner:'fixture',modelId:'deepseek-flash',title:'보존할 대화'});"
                  "r.appendMessage('fixture',s.id,{role:'user',content:'보존할 질문'});"
                  "r.appendMessage('fixture',s.id,{role:'assistant',content:'보존할 답변'});"
                  "r.compactSession('fixture',s.id,{summary:'보존할 요약',throughSequence:1});r.close();")
        result = subprocess.run([os.environ.get("CA3P_NODE", "node"), "--input-type=module", "-e", script],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_chat_sessions_messages_and_summary_survive_three_store_rollback(self):
        self.create_chat()
        with sqlite3.connect(self.chat_db) as connection:
            expected = {table: connection.execute(f'SELECT * FROM "{table}"').fetchall()
                        for table in ("chat_sessions", "chat_messages")}
        args = [*self.both(), "--chat-db", self.chat_db]
        backed_up = self.cli("backup", *args, "--output", self.backup)
        self.assertEqual(backed_up["databases"]["chat"]["info"]["counts"],
                         {table: len(rows) for table, rows in expected.items()})
        self.chat_db.write_bytes(b"failed candidate")
        restored = self.cli("restore", *args, "--backup", self.backup)
        self.assertEqual(restored["databases"]["chat"]["quickCheck"], "ok")
        with sqlite3.connect(self.chat_db) as connection:
            for table, rows in expected.items():
                self.assertEqual(connection.execute(f'SELECT * FROM "{table}"').fetchall(), rows)

    def test_chat_first_install_rollback_restores_absence(self):
        args = [*self.both(), "--chat-db", self.chat_db]
        self.cli("backup", *args, "--output", self.backup)
        self.create_chat()
        self.cli("restore", *args, "--backup", self.backup)
        self.assertFalse(self.chat_db.exists())

    def test_chat_backup_rejects_unrelated_database_without_modifying_it(self):
        self.chat_db.parent.mkdir(parents=True)
        with sqlite3.connect(self.chat_db) as connection:
            connection.execute("CREATE TABLE unrelated(secret TEXT)")
        original = self.chat_db.read_bytes()
        failed = self.cli("backup", *self.both(), "--chat-db", self.chat_db,
                          "--output", self.backup, success=False)
        self.assertIn("unknown tables", failed["error"])
        self.assertEqual(self.chat_db.read_bytes(), original)

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
