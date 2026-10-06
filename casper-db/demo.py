"""Persistent, clearly fictional DB demonstration. No site, parser, or LLM runs."""

# ruff: noqa: E501 -- inline HTML template keeps the visible demo in one file.

from __future__ import annotations

import argparse
import html
import json
import sys
import webbrowser
from pathlib import Path

from casper_db import CaseStore, assess_observation, initialize_database
from casper_db.repository import NotFoundError


def escaped(value: object) -> str:
    return html.escape(str(value), quote=True)


def pretty(value: object) -> str:
    return escaped(json.dumps(value, ensure_ascii=False, indent=2))


def render(report: dict, parser_rows: list[dict], checks: list[dict], db_path: Path) -> str:
    match_rows = "".join(
        "<tr>"
        f"<td>{escaped(row['method'])} {escaped(row['endpoint'])}</td>"
        f"<td>{escaped(row['parameter'])}</td>"
        f"<td>{escaped(row['parameter_location'])}</td>"
        f"<td>{escaped(row['count'])}건</td>"
        f"<td>{escaped(row['meaning'])}</td>"
        f"<td>{escaped(row['reason'])}</td>"
        "</tr>"
        for row in parser_rows
    )
    check_rows = "".join(
        "<tr>"
        f"<td>{escaped(item['observed_at'])}</td>"
        f"<td>{escaped(item['result'])}</td>"
        f"<td>{escaped(item['source'])} / {escaped(item['review_status'])}</td>"
        f"<td>{escaped(item['observation'])}</td>"
        "</tr>"
        for item in checks
    )
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CASPER 취약점 DB 시연</title>
<style>
:root{{font-family:system-ui,'Malgun Gothic',sans-serif;color:#172337;background:#f4f7fb}}
body{{max-width:1120px;margin:0 auto;padding:32px 20px 70px;line-height:1.55}}
h1{{margin:0 0 8px;font-size:2rem}}h2{{margin-top:0;font-size:1.25rem}}
.lead{{color:#536176;margin:0 0 24px}}.notice{{background:#fff0d6;border-left:5px solid #c97800;padding:14px 18px;border-radius:8px;margin:20px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}}
.card,section{{background:white;border:1px solid #dce3ec;border-radius:12px;padding:18px;margin:18px 0;box-shadow:0 2px 10px #1231}}
.card{{margin:0}}.label{{font-size:.85rem;color:#66768c}}.value{{font-size:1.1rem;font-weight:700;overflow-wrap:anywhere}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #dce3ec;padding:10px}}th{{background:#f2f5f9}}.scroll{{overflow:auto}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101e30;color:#e8f0fc;padding:16px;border-radius:8px;font-size:.85rem}}
code{{background:#edf2f8;padding:2px 5px;border-radius:4px}}.flow{{font-weight:700;color:#184d87}}
</style></head><body>
<h1>CASPER 취약점 DB 시연</h1>
<p class="lead">지난달 보고서를 저장하고, 이번 달 파서 출력과 비교한 다음, 재점검 기록을 별도로 쌓는 흐름</p>
<div class="notice"><strong>모두 모의 자료입니다.</strong> 입력 지점은 JSON 파일에서 읽었습니다. 실제 사이트, XSS 재현 도구, LLM은 실행하지 않았습니다. 아래 화면은 SQLite에서 다시 읽은 값으로 만들었습니다.</div>
<p class="flow">지난달 보고서 → SQLite 사례 → 이번 달 경로·입력변수 비교 → 재점검 이력</p>
<div class="grid">
<div class="card"><div class="label">저장된 사례</div><div class="value">{escaped(report['case_id'])}</div></div>
<div class="card"><div class="label">지난달 보고일</div><div class="value">{escaped(report['reported_on'])}</div></div>
<div class="card"><div class="label">위치</div><div class="value">{escaped(report['method'])} {escaped(report['endpoint'])} · {escaped(report['parameter'])}</div></div>
<div class="card"><div class="label">재점검 기록</div><div class="value">{len(checks)}건 (가상)</div></div>
</div>
<section><h2>1. 실제 DB에 저장된 지난달 보고서</h2>
<p><strong>{escaped(report['title'])}</strong> · {escaped(report['vulnerability_type'])} · 심각도 {escaped(report['severity'])}</p>
<p>{escaped(report['description'])}</p><p>발생 URL: <code>{escaped(report['vulnerability_url'])}</code></p>
<p>조치 방안: {escaped(' / '.join(report['remediation']))}</p>
<details><summary>DB에서 읽은 보고서 JSON 전체 보기</summary><pre>{pretty(report)}</pre></details></section>
<section><h2>2. 모의 입력 지점과 후보 판정</h2>
<div class="scroll"><table><thead><tr><th>요청 위치</th><th>입력변수</th><th>입력 위치</th><th>관련 전월 사례</th><th>판정</th><th>이유</th></tr></thead><tbody>{match_rows}</tbody></table></div>
<p>정확히 일치하면 재점검 후보, 일부만 일치하면 수동 확인입니다. 어느 쪽도 이번 달 XSS 존재 여부를 판정하지 않습니다.</p></section>
<section><h2>3. 별도 테이블에 저장된 이번 달 재점검 기록</h2>
<div class="scroll"><table><thead><tr><th>관찰 시각</th><th>결과</th><th>출처 / 검토</th><th>기록</th></tr></thead><tbody>{check_rows}</tbody></table></div>
<p><code>inconclusive</code>는 판단 보류입니다. 실제 점검 결과를 주장하지 않습니다.</p>
<details><summary>DB에서 읽은 재점검 JSON 전체 보기</summary><pre>{pretty(checks)}</pre></details></section>
<section><h2>팀원에게 보여줄 핵심</h2><p>보고서와 재점검 기록은 <code>{escaped(db_path)}</code>의 서로 다른 테이블에 남습니다. 재실행해도 중복 저장하지 않습니다. 다른 팀원의 파서 결과를 받으면 이 예시 입력을 실제 출력으로 교체하고, 검증 결과를 새 이력으로 넣는 것이 다음 연결 작업입니다.</p></section>
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "data" / "demo")
    parser.add_argument("--parser-input", type=Path, help="Use an existing parser JSON array")
    parser.add_argument("--no-open", action="store_true", help="Do not open the generated HTML")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = initialize_database(output_dir / "cases.sqlite3")
    store = CaseStore(db_path)
    case = json.loads((Path(__file__).parent / "examples" / "case.example.json").read_text(encoding="utf-8"))
    try:
        store.get(case["case_id"])
    except NotFoundError:
        store.add({**case, "status": "ready"})
    report = store.get(case["case_id"]).model_dump()
    if report["status"] != "ready":
        raise ValueError("demo case exists but is not ready; inspect the demo database")

    parser_file = args.parser_input.resolve() if args.parser_input else output_dir / "parser-observations.json"
    if not args.parser_input and not parser_file.exists():
        source = Path(__file__).parent / "examples" / "parser-observations.json"
        parser_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    mock_parser = json.loads(parser_file.read_text(encoding="utf-8"))
    if not isinstance(mock_parser, list):
        raise ValueError("parser observations must be a JSON array")
    parser_rows = []
    for location in mock_parser:
        assessment = assess_observation(store, location)
        labels = {
            "retest_candidate": "재점검 후보",
            "manual_review": "수동 확인",
            "no_match": "일치 없음",
        }
        parser_rows.append({
            **assessment.observation.model_dump(),
            "count": len(assessment.matches),
            "meaning": labels[assessment.decision],
            "reason": assessment.explanation,
        })

    existing = store.list_checks(case["case_id"])
    if not any(item.check_id == "CHECK-DEMO-001" for item in existing):
        store.add_check({
            "check_id": "CHECK-DEMO-001",
            "case_id": case["case_id"],
            "run_id": "RUN-DEMO-001",
            "target_id": case["target_id"],
            "endpoint": case["endpoint"],
            "method": case["method"],
            "parameter": case["parameter"],
            "parameter_location": case["parameter_location"],
            "observed_at": "2026-09-30T10:00:00+09:00",
            "result": "inconclusive",
            "observation": "가상 시연 기록: 실제 모의 사이트를 점검하지 않아 XSS 존재 여부를 판단하지 않았다.",
            "evidence_refs": [],
            "source": "synthetic",
            "review_status": "draft",
        })
    checks = [item.model_dump() for item in store.list_checks(case["case_id"])]
    page = output_dir / "index.html"
    page.write_text(render(report, parser_rows, checks, db_path), encoding="utf-8")
    print(f"SQLite DB: {db_path}")
    print(f"파서 입력 JSON: {parser_file}")
    print(f"시연 화면: {page}")
    print("모의 자료만 사용했습니다. 실제 사이트 점검·LLM은 아직 연결되지 않았습니다.")
    if not args.no_open:
        webbrowser.open(page.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
