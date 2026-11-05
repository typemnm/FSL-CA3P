import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { PROJECT_ROOT, treeDigest } from '../../packages/contracts/manifest.mjs';
import { digest } from '../../packages/contracts/index.mjs';

const SNAPSHOT_CODE = String.raw`
import json, sqlite3, sys
from contextlib import closing
from pathlib import Path
from casper_db.repository import CaseStore, SCHEMA_VERSION
from casper_db.attack_catalog import prepare_catalog_database
from casper_db.snapshot_identity import knowledge_identity
source, destination = map(Path, sys.argv[1:3])
fixture_id = sys.argv[3]
source.parent.mkdir(parents=True, exist_ok=True)
prepare_catalog_database(source)
with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro',uri=True)) as origin, \
        closing(sqlite3.connect(destination)) as snapshot:
    origin.backup(snapshot)
store = CaseStore(destination)
cases = store.list_for_target(fixture_id)
checks = [check.model_dump() for item in cases for check in store.list_checks(item.case_id)]
case_rows = [item.model_dump() for item in cases]
with closing(sqlite3.connect(destination)) as connection:
    identity = knowledge_identity(connection, case_rows, checks)
json.dump({'schemaVersion': SCHEMA_VERSION, 'cases': case_rows, 'checks': checks, 'knowledgeDigest': identity}, sys.stdout)
`;

const CASE_FIXTURES = new Set(['vul-web-1', 'vul-web2-daehan', 'vul-web2-wonchang']);

/** SQLite backup includes a consistent view of WAL data and freezes lookup input. */
export function prepareCaseSnapshot({ runId, storePath, fixtureId = 'vul-web-1', env = process.env,
  spawn = spawnSync } = {}) {
  if (!CASE_FIXTURES.has(fixtureId)) throw Object.assign(new TypeError('Choose a registered local fixture.'), { status: 400 });
  const sourcePath = resolve(env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3'));
  const directory = join(dirname(storePath), 'case-snapshots');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, `${digest(runId)}.sqlite`);
  const python = env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python.exe' : 'python3');
  const result = spawn(python, ['-c', SNAPSHOT_CODE, sourcePath, path, fixtureId], { cwd: PROJECT_ROOT,
    env: { ...env, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src') }, encoding: 'utf8',
    timeout: 15_000, maxBuffer: 2_000_000, windowsHide: true });
  if (result.error || result.status !== 0) throw Object.assign(new Error('Cannot prepare the historical-case snapshot. Configure CASPER_DB_PYTHON and the case database.'),
    { status: 503, code: 'CASE_SNAPSHOT_UNAVAILABLE' });
  const snapshot = JSON.parse(result.stdout);
  return { path, sourcePath, contentDigest: digest({ schemaVersion: snapshot.schemaVersion, cases: snapshot.cases, checks: snapshot.checks }),
    knowledgeDigest: snapshot.knowledgeDigest, fileDigest: treeDigest(path), schemaVersion: snapshot.schemaVersion,
    caseRevisions: snapshot.cases.map(item => ({ caseId: item.case_id, revision: item.revision })),
    caseSummaries: snapshot.cases.slice(0, 30).map(item => ({
      caseId: item.case_id, revision: item.revision,
      title: String(item.title ?? '').slice(0, 160),
      vulnerabilityType: String(item.vulnerability_type ?? '').slice(0, 80),
      endpoint: String(item.endpoint ?? '').slice(0, 200),
      method: String(item.method ?? '').slice(0, 12),
      description: String(item.description ?? '').slice(0, 300),
      status: item.status, patchStatus: item.patch_status,
    })) };
}
