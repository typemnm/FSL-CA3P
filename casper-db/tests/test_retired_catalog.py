"""Retired lab guidance stays out of active catalog lookups."""

import json
import sqlite3
from pathlib import Path

from casper_db.attack_catalog import (
    import_attack_catalog,
    list_attack_patterns,
    lookup_attack_info,
    prepare_catalog_database,
)


def test_retired_board_guidance_is_hidden_even_in_existing_databases(tmp_path: Path):
    database = tmp_path / "catalog.sqlite3"
    prepared = prepare_catalog_database(database)
    assert len(prepared) == 1
    assert prepared[0]["created"] == 3

    legacy_path = Path(__file__).resolve().parents[1] / "src/casper_db/catalog_seed/develop-v2.json"
    import_attack_catalog(database, json.loads(legacy_path.read_text("utf-8")),
                          source_ref="test:historical-board-catalog")
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM attack_patterns WHERE application='vul-web-1'"
        ).fetchone()[0] == 2

    patterns = list_attack_patterns(database)["patterns"]
    assert len(patterns) == 3
    assert {item["definition"]["target"]["application"] for item in patterns} == {"vul-web2"}
    assert lookup_attack_info(database, {
        "vulnType": "stored_xss",
        "target": {"application": "vul-web-1", "endpoint": "POST /api/posts", "parameter": "content"},
    }) is None
