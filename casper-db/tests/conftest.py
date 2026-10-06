import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from casper_db import CaseStore, initialize_database


@pytest.fixture
def legacy_database(tmp_path):
    """Construct genuine v2/v3/v4 layouts from the frozen, previous SQL contract."""
    def create(version, case, check=None):
        path = tmp_path / f"legacy-v{version}.sqlite3"
        fixture_dir = Path(__file__).parent / "fixtures"
        with closing(sqlite3.connect(path)) as connection, connection:
            for name in ("v4-cases.sql", "v4-checks.sql"):
                connection.executescript((fixture_dir / name).read_text(encoding="utf-8"))
            data = {key: value for key, value in case.items() if key != "source"}
            data.update(created_at="2026-08-20T00:00:00+00:00",
                        updated_at="2026-08-20T00:00:00+00:00")
            for key in ("preconditions", "procedure", "remediation"):
                data[key] = json.dumps(data[key], ensure_ascii=False)
            connection.execute(
                f"INSERT INTO cases ({', '.join(data)}) "
                f"VALUES ({', '.join('?' for _ in data)})", list(data.values())
            )
            if check is not None:
                data = {
                    **check, "created_at": "2026-09-30T00:00:00+00:00",
                    "review_status": check.get("review_status", "draft"),
                    "reviewer": check.get("reviewer"),
                    "evidence_refs": json.dumps(check.get("evidence_refs", [])),
                }
                connection.execute(
                    f"INSERT INTO checks ({', '.join(data)}) "
                    f"VALUES ({', '.join('?' for _ in data)})", list(data.values())
                )
            if version < 4:
                connection.execute("ALTER TABLE cases DROP COLUMN parameter_location")
                connection.execute("ALTER TABLE checks DROP COLUMN parameter_location")
            if version == 2:
                connection.execute("DROP TABLE checks")
            connection.execute(f"PRAGMA user_version = {version}")
        return path

    return create


@pytest.fixture
def case_data():
    path = Path(__file__).resolve().parents[1] / "examples" / "case.example.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def store(tmp_path):
    path = initialize_database(tmp_path / "cases.sqlite3")
    return CaseStore(path)
