import { spawn } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { dirname, join, parse, resolve } from 'node:path';
import { PROJECT_ROOT } from '../../packages/contracts/manifest.mjs';
import { prepareTargetReset } from './experiment-targets.mjs';

const fault = message => Object.assign(new Error(message), { status: 409, code: 'EXPERIMENT_HISTORY_RESET_BLOCKED' });
const PROGRAM = String.raw`
import json, sqlite3, sys
from pathlib import Path
from casper_db.repository import SCHEMA_VERSION
r = json.load(sys.stdin)
p = Path(r['path'])
if not p.exists():
    json.dump({'checksRemoved': 0}, sys.stdout)
    sys.exit(0)
uri = p.resolve().as_uri() + ('?mode=rw' if r['apply'] else '?mode=ro')
with sqlite3.connect(uri, uri=True, timeout=5) as c:
    c.execute('PRAGMA busy_timeout=5000')
    c.execute('BEGIN IMMEDIATE' if r['apply'] else 'BEGIN')
    if c.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
        raise ValueError('unsupported history schema')
    tables = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'cases', 'case_versions', 'checks'}.issubset(tables):
        raise ValueError('unrecognized history database')
    columns = {row[1] for row in c.execute('PRAGMA table_info(checks)')}
    if not {'check_id', 'run_id', 'source', 'review_status'}.issubset(columns):
        raise ValueError('unrecognized check schema')
    c.execute('CREATE TEMP TABLE reset_run_ids(id TEXT PRIMARY KEY)')
    c.executemany('INSERT INTO reset_run_ids VALUES (?)', [(x,) for x in r['runIds']])
    count = c.execute('SELECT count(*) FROM checks WHERE run_id IN (SELECT id FROM reset_run_ids)').fetchone()[0]
    if r['apply']:
        c.execute('PRAGMA secure_delete=ON')
        c.execute('DELETE FROM checks WHERE run_id IN (SELECT id FROM reset_run_ids)')
    c.commit()
    if r['apply']:
        # Do not leave earlier check bodies in this database's WAL/free pages.
        result = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if result and result[0] != 0:
            raise ValueError('history WAL remains busy')
        c.execute('VACUUM')
        result = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if result and result[0] != 0:
            raise ValueError('history WAL remains busy')
    json.dump({'checksRemoved': count if r['apply'] else 0, 'checksFound': count}, sys.stdout)
`;

async function assertRegularDatabase(path) {
  // Refuse symlinks/junctions anywhere in an operator-configured database path.
  let part = parse(path).root;
  for (const name of path.slice(part.length).split(/[\\/]/).filter(Boolean)) {
    part = join(part, name);
    let info;
    try { info = await lstat(part); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (info.isSymbolicLink()) throw fault('과거 사례 DB 경로에 연결 파일이 있습니다. 운영자가 경로를 확인한 뒤 다시 시도하세요.');
    if (part === path && !info.isFile()) throw fault('과거 사례 DB가 일반 파일이 아닙니다.');
  }
}

function historyOperation(path, runIds, apply, env) {
  return new Promise((done, reject) => {
    const python = env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
    const child = spawn(python, ['-c', PROGRAM], { cwd: PROJECT_ROOT, windowsHide: true,
      env: { ...env, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src'), PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
      stdio: ['pipe', 'pipe', 'ignore'] });
    let output = ''; let failed = false;
    const fail = () => { if (!failed) { failed = true; reject(fault('과거 사례의 실험 체크를 초기화할 수 없습니다. DB와 Python 설정을 확인한 뒤 다시 시도하세요.')); } };
    const timer = setTimeout(() => { child.kill(); fail(); }, 20_000);
    child.on('error', fail);
    child.stdout.on('data', chunk => { output += chunk; if (output.length > 16_384) { child.kill(); fail(); } });
    child.stdin.on('error', () => {});
    child.once('close', code => {
      clearTimeout(timer);
      if (code !== 0) return fail();
      if (!failed) { try { done(JSON.parse(output)); } catch { fail(); } }
    });
    child.stdin.end(JSON.stringify({ path, runIds, apply }));
  });
}

/** Only run-linked experimental checks are removed; curated cases/revisions stay intact. */
export async function prepareHistoryReset({ runs, env = process.env } = {}) {
  const runIds = [...new Set(runs.flatMap(run => [run.id, run.coreRunId, run.report?.runId])
    .filter(value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)))];
  const path = resolve(env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3'));
  for (const run of runs) {
    const recorded = run.manifest?.data?.caseDatabaseSourcePath;
    if (recorded && resolve(recorded) !== path) throw fault('이전 실험이 다른 과거 사례 DB를 사용했습니다. 동일한 DB 설정으로 초기화하거나 운영자가 해당 기록을 정리해야 합니다.');
  }
  if (!runIds.length) return { execute: async () => ({ checksRemoved: 0 }) };
  await assertRegularDatabase(path);
  await assertRegularDatabase(`${path}-wal`);
  await assertRegularDatabase(`${path}-shm`);
  const exists = await lstat(path).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  if (!exists) return { execute: async () => ({ checksRemoved: 0 }) };
  await historyOperation(path, runIds, false, env);
  return { execute: async () => {
    await assertRegularDatabase(path);
    await assertRegularDatabase(`${path}-wal`);
    await assertRegularDatabase(`${path}-shm`);
    return historyOperation(path, runIds, true, env);
  } };
}

/** Prepare every participant before changing any data. The service owns the maintenance fence. */
export async function prepareExperimentCleanup({ runs, storePath, env = process.env } = {}) {
  const targets = await prepareTargetReset({ runs, env, cleanupRegistryPath: join(dirname(storePath), 'lab-sessions') });
  const history = await prepareHistoryReset({ runs, env });
  return { execute: async () => {
    const targetResult = await targets.execute();
    const historyResult = await history.execute();
    return { targets: targetResult, history: historyResult };
  } };
}
