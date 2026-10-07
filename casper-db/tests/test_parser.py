import json
import subprocess
import sys
from pathlib import Path

import pytest

from casper_db.matching import assess_observation
from casper_db.parser import parse_html_inputs

PROJECT = Path(__file__).resolve().parents[1]


def test_saved_mock_page_produces_distinct_input_points_and_match_results(store, case_data):
    html = (PROJECT / "examples/mock-site/search.html").read_text(encoding="utf-8")
    parsed = parse_html_inputs(
        html, page_url="https://lab.example.invalid/search", target_id="LAB-DEMO"
    )
    assert parsed.warnings == []
    assert [
        (item.endpoint, item.method, item.parameter, item.parameter_location)
        for item in parsed.observations
    ] == [
        ("/search", "GET", "q", "query"),
        ("/search", "GET", "page", "query"),
        ("/feedback", "POST", "message", "body"),
    ]
    store.add({**case_data, "status": "ready"})
    assert [assess_observation(store, item).decision for item in parsed.observations] == [
        "retest_candidate", "manual_review", "no_match"
    ]


def test_parser_ignores_external_forms_disabled_inputs_and_duplicates():
    html = """
    <form action="https://other.invalid/search" method="get"><input name="outside"></form>
    <form action="/search" method="get">
      <input name="q"><input name="q"><input name="disabled" disabled>
      <input type="submit" name="submit_button">
    </form>
    <a href="/search?q=again#fragment">same point</a>
    <a href="javascript:alert(1)">ignored</a>
    """
    parsed = parse_html_inputs(
        html, page_url="https://lab.example.invalid/", target_id="LAB-DEMO"
    )
    assert [(item.endpoint, item.parameter) for item in parsed.observations] == [
        ("/search", "q")
    ]
    assert any("cross-origin" in warning for warning in parsed.warnings)
    assert any("invalid link" in warning for warning in parsed.warnings)


@pytest.mark.parametrize("url", ["file:///search", "https://user:pass@lab.invalid/search"])
def test_parser_requires_http_page_url_without_credentials(url):
    with pytest.raises(ValueError):
        parse_html_inputs("<form><input name='q'></form>", page_url=url, target_id="LAB-DEMO")


def test_cli_parse_html_file_can_feed_existing_match_command(tmp_path, store, case_data):
    store.add({**case_data, "status": "ready"})
    output_file = tmp_path / "observations.json"
    parsed = subprocess.run(
        [
            sys.executable, "-m", "casper_db", "parse-html", "--target", "LAB-DEMO",
            "--page-url", "https://lab.example.invalid/search", "--html",
            str(PROJECT / "examples/mock-site/search.html"), "--output", str(output_file),
        ],
        cwd=PROJECT, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert parsed.returncode == 0, parsed.stderr
    assert len(json.loads(output_file.read_text(encoding="utf-8"))) == 3
    matched = subprocess.run(
        [sys.executable, "-m", "casper_db", "--db", str(store.path), "match", str(output_file)],
        cwd=PROJECT, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert matched.returncode == 0, matched.stderr
    assert [row["decision"] for row in json.loads(matched.stdout)] == [
        "retest_candidate", "manual_review", "no_match"
    ]
