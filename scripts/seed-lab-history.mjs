import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const python = process.env.CASPER_DB_PYTHON ?? join(root, '.venv/bin/python');
const result = spawnSync(python, ['-c', String.raw`
import json,sys
from pathlib import Path
from casper_db.repository import CaseStore,initialize_database
r=json.load(sys.stdin)
path=Path(r['database']); initialize_database(path); store=CaseStore(path)
if not store.find(target_id='vul-web-1',endpoint='/api/posts',method='POST',parameter='content',parameter_location='body',include_drafts=True):
    row=json.loads(Path(r['example']).read_text())
    row.update(case_id='LAB-STORED-XSS',target_id='vul-web-1',title='격리 실습 게시판 회귀용 예시 과거 사례',
      endpoint='/api/posts',method='POST',parameter='content',parameter_location='body',status='ready',source='synthetic',
      vulnerability_url='http://127.0.0.1/api/posts',description='격리 실습용 합성 사례입니다. 실제 사이트의 CERT 결과가 아닙니다.',
      prior_evidence='합성 회귀 fixture의 기대 결과. 현재 실행 증거와 구분합니다.',
      preconditions=['서버가 생성한 격리 vul-web-1 게시판만 검사'],procedure=['무해한 고유 canary를 게시하고 독립 브라우저에서 확인'],
      success_condition='동일 게시글과 marker에 묶인 브라우저 콜백 실행 증거',payload='CA3P_SYNTHETIC_CANARY_MARKER')
    store.add(row)
print('Isolated lab history fixture ready (synthetic provenance).')
`], { cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONPATH: join(root, 'casper-db/src') },
  input: JSON.stringify({ database: process.env.CASPER_DB_PATH ?? join(root, 'casper-db/data/cases.sqlite3'), example: join(root, 'casper-db/examples/case.example.json') }) });
if (result.status !== 0) throw new Error('Lab history fixture initialization failed.');
console.log(result.stdout.trim());
