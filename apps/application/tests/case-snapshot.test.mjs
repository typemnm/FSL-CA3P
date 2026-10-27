import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROJECT_ROOT } from '../../../packages/contracts/manifest.mjs';
import { prepareCaseSnapshot } from '../case-snapshot.mjs';

test('snapshot comparison digest includes run-derived checks as well as the curated case rows', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-case-snapshot-digest-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'cases.sqlite');
  const python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
  const env = { ...process.env, CASPER_DB_PYTHON: python, CASPER_DB_PATH: database, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src') };
  function execute(code) {
    const result = spawnSync(python, ['-c', code, database, join(PROJECT_ROOT, 'casper-db/examples/case.example.json')], { env, encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, result.error?.message || result.stderr);
  }
  execute(String.raw`
import json,sys
from casper_db import CaseStore,initialize_database
store=CaseStore(initialize_database(sys.argv[1]))
case=json.load(open(sys.argv[2],encoding='utf-8'))
store.add({**case,'target_id':'vul-web-1','status':'ready'})
`);
  const before = prepareCaseSnapshot({ runId: 'snapshot-before', storePath: join(directory, 'runs.sqlite'), env });
  const sourceBefore = readFileSync(database);
  execute(String.raw`
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c:
    c.execute("INSERT INTO checks(check_id,case_id,case_revision,run_id,target_id,endpoint,method,parameter,parameter_location,observed_at,result,observation,source,review_status,created_at) VALUES ('CHECK-EXPERIMENT','CASE-001',1,'prior-run','vul-web-1','/search','GET','q','query','2026-10-26T09:00:00Z','confirmed','prior model result','tool','draft','2026-10-26T09:00:00Z')")
`);
  assert.notDeepEqual(readFileSync(database), sourceBefore);
  const after = prepareCaseSnapshot({ runId: 'snapshot-after', storePath: join(directory, 'runs.sqlite'), env });
  assert.deepEqual(after.caseRevisions, before.caseRevisions, 'curated cases did not change');
  assert.notEqual(after.contentDigest, before.contentDigest, 'check contamination must change the comparison input digest');
  assert.equal(prepareCaseSnapshot({ runId: 'snapshot-repeat', storePath: join(directory, 'runs.sqlite'), env }).contentDigest, after.contentDigest);
});
