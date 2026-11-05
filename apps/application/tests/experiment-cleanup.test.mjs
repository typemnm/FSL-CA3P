import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROJECT_ROOT } from '../../../packages/contracts/manifest.mjs';
import { prepareHistoryReset, prepareExperimentCleanup } from '../experiment-cleanup.mjs';

const python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
const pythonEnv = { ...process.env, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src') };
function sql(path, program) {
  const result = spawnSync(python, ['-c', program, path], { env: pythonEnv, encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  return result.stdout.trim();
}
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-reset-history-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'cases.sqlite');
  sql(path, String.raw`
import sqlite3, sys
from casper_db.repository import SCHEMA_VERSION
with sqlite3.connect(sys.argv[1]) as c:
    c.executescript('CREATE TABLE cases(id TEXT, body TEXT); CREATE TABLE case_versions(id TEXT, revision INTEGER); CREATE TABLE checks(check_id TEXT,run_id TEXT,source TEXT,review_status TEXT,body TEXT);')
    c.execute('INSERT INTO cases VALUES (?,?)', ('curated', 'preserve baseline'))
    c.execute('INSERT INTO case_versions VALUES (?,?)', ('curated', 3))
    c.executemany('INSERT INTO checks VALUES (?,?,?,?,?)', [
        ('check-a','run-a','tool','reviewed','experimental-secret'),
        ('check-b','run-a','tool','draft','experimental-secret'),
        ('check-c','reference','manual','reviewed','baseline'),
        ('check-d','other-run','tool','reviewed','other workspace'),
    ])
    c.execute('PRAGMA user_version=' + str(SCHEMA_VERSION))
`);
  return { dir, path, env: { ...process.env, CASPER_DB_PYTHON: python, CASPER_DB_PATH: path } };
}

test('reset removes run-linked draft/reviewed checks while preserving curated and unrelated knowledge', async t => {
  const { path, env } = await fixture(t);
  const before = await readFile(path);
  const cleanup = await prepareHistoryReset({ runs: [{ id: 'run-a', manifest: { data: { caseDatabaseSourcePath: path } } }], env });
  assert.deepEqual(await readFile(path), before, 'preflight must not modify the source database');
  assert.equal((await cleanup.execute()).checksRemoved, 2);
  assert.deepEqual(JSON.parse(sql(path, String.raw`
import sqlite3,sys,json
with sqlite3.connect(sys.argv[1]) as c:
    json.dump({'cases':c.execute('SELECT * FROM cases').fetchall(),'versions':c.execute('SELECT * FROM case_versions').fetchall(),'checks':c.execute('SELECT check_id FROM checks ORDER BY check_id').fetchall()},sys.stdout)
`)), { cases: [['curated', 'preserve baseline']], versions: [['curated', 3]], checks: [['check-c'], ['check-d']] });
  assert.equal((await prepareHistoryReset({ runs: [{ id: 'run-a' }], env })).execute instanceof Function, true);
  assert.equal((await cleanup.execute()).checksRemoved, 0, 'partial reset retries are idempotent');
});

test('different historical source or unsupported database blocks before deleting anything', async t => {
  const { path, env, dir } = await fixture(t);
  const before = await readFile(path);
  await assert.rejects(prepareHistoryReset({ runs: [{ id: 'run-a', manifest: { data: { caseDatabaseSourcePath: join(dir, 'other.sqlite') } } }], env }), /다른 과거 사례 DB/);
  assert.deepEqual(await readFile(path), before);
  sql(path, "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA user_version=999'); c.close()");
  const unsupported = await readFile(path);
  await assert.rejects(prepareHistoryReset({ runs: [{ id: 'run-a' }], env }), /초기화할 수 없습니다/);
  assert.deepEqual(await readFile(path), unsupported);
});

test('a linked database directory is refused and its external data stays unchanged', async t => {
  const { path, env, dir } = await fixture(t);
  const alias = join(dir, 'alias');
  await symlink(dir, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const before = await readFile(path);
  await assert.rejects(prepareHistoryReset({ runs: [{ id: 'run-a' }], env: { ...env, CASPER_DB_PATH: join(alias, 'cases.sqlite') } }), /연결 파일/);
  assert.deepEqual(await readFile(path), before);
});

test('an unmanaged contacted target blocks the complete plan before CASPER mutation', async t => {
  const { path, env, dir } = await fixture(t);
  const before = await readFile(path);
  await assert.rejects(prepareExperimentCleanup({ runs: [{ id: 'run-a', fixtureId: 'external', targetContacted: true }], storePath: join(dir, 'runs.sqlite'), env }), /외부 대상/);
  assert.deepEqual(await readFile(path), before);
});
