import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { matchCasperHistory } from '../../adapters/integrations/casper-db.mjs';
import { syncRunChecks, reviewRunCheck } from '../check-sync.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const python = process.env.CASPER_DB_PYTHON ?? 'python3';
test('populated history matches a pinned revision, writes a draft idempotently, and verifies review evidence', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-history-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const databasePath = join(directory, 'cases.sqlite3');
  const example = JSON.parse(await readFile(join(root, 'casper-db/examples/case.example.json'), 'utf8'));
  Object.assign(example, { target_id: 'vul-web-1', endpoint: '/api/posts', method: 'POST', parameter: 'content', parameter_location: 'body', status: 'ready', vulnerability_url: 'http://127.0.0.1/api/posts' });
  const setup = spawnSync(python, ['-c', 'import json,sys; from casper_db.repository import CaseStore,initialize_database; r=json.load(sys.stdin); initialize_database(r["database"]); CaseStore(r["database"]).add(r["case"])'], {
    cwd: root, encoding: 'utf8', input: JSON.stringify({ database: databasePath, case: example }),
    env: { ...process.env, PYTHONPATH: join(root, 'casper-db/src'), PYTHONIOENCODING: 'utf-8' } });
  assert.equal(setup.status, 0, setup.stderr);
  const origin = 'http://127.0.0.1:32123';
  const result = await matchCasperHistory({ report: { schemaVersion: '3.4', pages: [{ behaviors: [{ api: [{ method: 'POST', url: `${origin}/api/posts`, bodyKeys: ['content'] }] }] }] }, origin, databasePath, python });
  assert.equal(result.readyCaseCount, 1); assert.equal(result.assessments[0].decision, 'retest_candidate');
  assert.equal(result.assessments[0].matches[0].case_revision, 1);
  const evidenceRoot = join(directory, 'artifacts'); await mkdir(evidenceRoot);
  const artifact = { path: join(evidenceRoot, 'proof.json') }; await writeFile(artifact.path, '{"bindingCalled":true}');
  const run = { id: 'run-history-test', simulated: false, report: { testProfile: 'stored_xss_canary', finding: { status: 'confirmed' }, completedAt: new Date().toISOString() },
    events: [{ module: 'casper', response: { payload: { assessments: result.assessments } } }] };
  const first = await syncRunChecks(run, { artifact, storePath: join(directory, 'runs.sqlite'), databasePath, python });
  const second = await syncRunChecks(run, { artifact, storePath: join(directory, 'runs.sqlite'), databasePath, python });
  assert.equal(first.checks.length, 1); assert.equal(first.checks[0].review_status, 'draft');
  assert.equal(second.checks[0].check_id, first.checks[0].check_id);
  const reviewed = await reviewRunCheck(first.checks[0].check_id, { reviewer: 'reviewer', note: 'Unit fixture evidence inspected.', databasePath, evidenceRoot, python });
  assert.equal(reviewed.review_status, 'reviewed'); assert.equal(reviewed.evidence_metadata[0].sha256.length, 64);
});
test('simulated runs and changed locations do not become real case checks', async () => {
  assert.equal((await syncRunChecks({ simulated: true }, {})).status, 'not-applicable');
  await assert.rejects(reviewRunCheck('../escape', { note: 'invalid' }), { status: 400 });
});
