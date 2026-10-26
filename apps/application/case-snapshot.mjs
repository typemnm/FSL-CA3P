import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { PROJECT_ROOT, treeDigest } from '../../packages/contracts/manifest.mjs';
import { digest } from '../../packages/contracts/index.mjs';

const SNAPSHOT_CODE = String.raw`
import json, sqlite3, sys
from pathlib import Path
from casper_db.repository import initialize_database, CaseStore, SCHEMA_VERSION
source, destination = map(Path, sys.argv[1:3])
source.parent.mkdir(parents=True, exist_ok=True)
if not source.exists():
    initialize_database(source)
with sqlite3.connect(source) as origin, sqlite3.connect(destination) as snapshot:
    origin.backup(snapshot)
store = CaseStore(destination)
cases = store.list_for_target('vul-web-1')
checks = [check.model_dump() for item in cases for check in store.list_checks(item.case_id)]
json.dump({'schemaVersion': SCHEMA_VERSION, 'cases': [item.model_dump() for item in cases], 'checks': checks}, sys.stdout)
`;

/** SQLite backup includes a consistent view of WAL data and freezes lookup input. */
export function prepareCaseSnapshot({ runId, storePath, env = process.env } = {}) {
  const sourcePath = resolve(env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3'));
  const directory = join(dirname(storePath), 'case-snapshots');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, `${digest(runId)}.sqlite`);
  const python = env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python.exe' : 'python');
  const result = spawnSync(python, ['-c', SNAPSHOT_CODE, sourcePath, path], { cwd: PROJECT_ROOT,
    env: { ...env, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src') }, encoding: 'utf8',
    timeout: 15_000, maxBuffer: 2_000_000, windowsHide: true });
  if (result.error || result.status !== 0) throw Object.assign(new Error('Cannot prepare the historical-case snapshot. Configure CASPER_DB_PYTHON and the case database.'),
    { status: 503, code: 'CASE_SNAPSHOT_UNAVAILABLE' });
  const snapshot = JSON.parse(result.stdout);
  return { path, sourcePath, contentDigest: digest(snapshot), fileDigest: treeDigest(path), schemaVersion: snapshot.schemaVersion,
    caseRevisions: snapshot.cases.map(item => ({ caseId: item.case_id, revision: item.revision })) };
}
