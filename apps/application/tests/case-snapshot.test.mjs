import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
store.add({**case,'target_id':'vul-web2-daehan','status':'ready'})
`);
  const before = prepareCaseSnapshot({ runId: 'snapshot-before', storePath: join(directory, 'runs.sqlite'),
    fixtureId: 'vul-web2-daehan', env });
  assert.match(before.knowledgeDigest, /^[a-f0-9]{64}$/u);
  const sourceBefore = readFileSync(database);
  execute(String.raw`
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c:
    c.execute("INSERT INTO checks(check_id,case_id,case_revision,run_id,target_id,endpoint,method,parameter,parameter_location,observed_at,result,observation,source,review_status,created_at) VALUES ('CHECK-EXPERIMENT','CASE-001',1,'prior-run','vul-web2-daehan','/search','GET','q','query','2026-10-26T09:00:00Z','confirmed','prior model result','tool','draft','2026-10-26T09:00:00Z')")
`);
  assert.notDeepEqual(readFileSync(database), sourceBefore);
  const after = prepareCaseSnapshot({ runId: 'snapshot-after', storePath: join(directory, 'runs.sqlite'),
    fixtureId: 'vul-web2-daehan', env });
  assert.deepEqual(after.caseRevisions, before.caseRevisions, 'curated cases did not change');
  assert.notEqual(after.contentDigest, before.contentDigest, 'check contamination must change the comparison input digest');
  assert.equal(prepareCaseSnapshot({ runId: 'snapshot-repeat', storePath: join(directory, 'runs.sqlite'),
    fixtureId: 'vul-web2-daehan', env }).contentDigest, after.contentDigest);
});

test('historical snapshot filters cases by the registered general fixture', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-case-snapshot-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const storePath = join(directory, 'runs.sqlite');
  const sourcePath = join(directory, 'cases.sqlite3');
  for (const fixtureId of ['vul-web2-daehan', 'vul-web2-wonchang']) {
    let called = 0;
    const result = prepareCaseSnapshot({ runId: `run-${fixtureId}`, storePath, fixtureId,
      env: { CASPER_DB_PYTHON: 'configured-python', CASPER_DB_PATH: sourcePath },
      spawn(command, args, options) {
        called += 1;
        assert.equal(command, 'configured-python');
        assert.equal(args[0], '-c');
        assert.match(args[1], /list_for_target\(fixture_id\)/u);
        assert.equal(args[2], sourcePath);
        assert.equal(args[4], fixtureId);
        assert.ok(options.env.PYTHONPATH.endsWith(join('casper-db', 'src')));
        writeFileSync(args[3], `snapshot for ${fixtureId}`);
        return { status: 0, stdout: JSON.stringify({ schemaVersion: 7, knowledgeDigest: `knowledge-${fixtureId}`, cases: [{
          case_id: `case-${fixtureId}`, revision: 2, title: 'Past case',
          vulnerability_type: 'access_control', endpoint: '/api/posts', method: 'GET',
          description: 'Historical reference only', status: 'confirmed', patch_status: 'open',
        }], checks: [] }) };
      },
    });
    assert.equal(called, 1);
    assert.equal(result.caseSummaries[0].caseId, `case-${fixtureId}`);
    assert.equal(result.knowledgeDigest, `knowledge-${fixtureId}`);
    assert.equal(result.schemaVersion, 7);
    assert.deepEqual(result.caseRevisions, [{ caseId: `case-${fixtureId}`, revision: 2 }]);
  }
});

test('historical snapshot rejects unregistered fixture before calling Python', () => {
  let called = false;
  assert.throws(() => prepareCaseSnapshot({ runId: 'run-unsafe', storePath: 'unused', fixtureId: '../other',
    spawn() { called = true; },
  }), { status: 400 });
  assert.throws(() => prepareCaseSnapshot({ runId: 'run-retired', storePath: 'unused', fixtureId: 'vul-web-1',
    spawn() { called = true; },
  }), { status: 400 });
  assert.equal(called, false);
});
