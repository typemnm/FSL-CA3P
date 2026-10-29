import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchCasperHistory, observationsFromParser } from '../integrations/casper-db.mjs';

const origin = 'http://127.0.0.1:32123';
const report = {
  schemaVersion: '3.4',
  pages: [{
    behaviors: [{
      api: [{ method: 'POST', url: `${origin}/api/posts`, bodyKeys: ['title', 'content'] }],
    }],
  }],
};

const python = process.env.CASPER_DB_PYTHON || 'python';
const casperSource = fileURLToPath(new URL('../../casper-db/src', import.meta.url));
const adapterSource = fileURLToPath(new URL('../../packages/adapters/integrations/casper-db.mjs', import.meta.url));
const pythonEnvironment = { ...process.env, PYTHONPATH: casperSource, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' };

// Run the actual embedded lookup body with a deterministic concurrent commit.
// WAL lets the writer finish while a fixed reader retains its earlier snapshot.
const CONCURRENT_COMMIT = String.raw`
import io, json, sqlite3, sys
from pathlib import Path
from casper_db.repository import initialize_database

source, database, omit_snapshot = sys.argv[1:]
original_connect = sqlite3.connect
with original_connect(database) as connection:
    assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
committed = False

class BarrierCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        self.reads_version = sql == 'PRAGMA user_version'
        return super().execute(sql, parameters)

    def fetchone(self):
        global committed
        row = super().fetchone()
        if self.reads_version and not committed:
            assert row[0] == 0
            self.close()
            initialize_database(database)
            committed = True
        return row

class BarrierConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        if omit_snapshot == 'yes' and sql == 'BEGIN':
            return None
        return self.cursor(BarrierCursor).execute(sql, parameters)

def connect(path, *args, **kwargs):
    if kwargs.get('uri') and str(path).endswith('?mode=ro'):
        kwargs['factory'] = BarrierConnection
    return original_connect(path, *args, **kwargs)

sqlite3.connect = connect
request = {'database':database, 'targetId':'vul-web2-daehan', 'observations':[]}
sys.stdin = io.StringIO(json.dumps(request))
code = Path(source).read_text(encoding='utf-8').split('const PYTHON_CODE = String.raw' + chr(96), 1)[1].split(chr(96) + ';', 1)[0]
exec(compile(code, source + ':PYTHON_CODE', 'exec'))
assert committed, 'the initializer did not commit between schema reads'
`;

test('parser API hints become location observations without asserting a vulnerability', () => {
  const rows = observationsFromParser(report, { targetId: 'vul-web2-daehan', origin });
  assert.deepEqual(rows, [
    { target_id: 'vul-web2-daehan', endpoint: '/api/posts', method: 'POST', parameter: 'title', parameter_location: 'body' },
    { target_id: 'vul-web2-daehan', endpoint: '/api/posts', method: 'POST', parameter: 'content', parameter_location: 'body' },
  ]);
  assert.deepEqual(observationsFromParser({ pages: [{ behaviors: [{ api: [
    { method: 'POST', url: 'https://other.invalid/api/posts', bodyKeys: ['content'] },
  ] }] }] }, { targetId: 'vul-web2-daehan', origin }), []);
});

test('real casper-db assesses parser locations against an isolated empty SQLite database', async t => {
  const databasePath = join(tmpdir(), `ca3p-casper-integration-${randomUUID()}.sqlite3`);
  t.after(async () => { await unlink(databasePath).catch(error => { if (error.code !== 'ENOENT') throw error; }); });
  const result = await matchCasperHistory({ report, targetId: 'vul-web2-daehan', origin, databasePath });
  assert.equal(result.source, 'casper-db');
  assert.equal(result.readyCaseCount, 0);
  assert.equal(result.assessments.length, 2);
  assert.ok(result.assessments.every(item => item.decision === 'no_match' && item.matches.length === 0));
});

test('concurrent first-use lookups wait for one complete database initialization', async t => {
  const databasePath = join(tmpdir(), `ca3p-casper-concurrent-${randomUUID()}.sqlite3`);
  t.after(async () => { await unlink(databasePath).catch(error => { if (error.code !== 'ENOENT') throw error; }); });
  const results = await Promise.all(Array.from({ length: 4 }, () =>
    matchCasperHistory({ report, targetId: 'vul-web2-daehan', origin, databasePath })));
  assert.equal(results.length, 4);
  assert.ok(results.every(result => result.readyCaseCount === 0 && result.assessments.length === 2));
});

test('schema inspection retains one snapshot when initialization commits between its reads', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-casper-snapshot-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const withoutSnapshot = spawnSync(python, ['-c', CONCURRENT_COMMIT, adapterSource,
    join(directory, 'without-snapshot.sqlite3'), 'yes'], { env: pythonEnvironment, encoding: 'utf8', timeout: 15_000 });
  assert.equal(withoutSnapshot.status, 1, withoutSnapshot.error?.message || withoutSnapshot.stderr);
  assert.match(withoutSnapshot.stderr, /explicit database migration is required/);

  const withSnapshot = spawnSync(python, ['-c', CONCURRENT_COMMIT, adapterSource,
    join(directory, 'with-snapshot.sqlite3'), 'no'], { env: pythonEnvironment, encoding: 'utf8', timeout: 15_000 });
  assert.equal(withSnapshot.status, 0, withSnapshot.error?.message || withSnapshot.stderr);
  assert.deepEqual(JSON.parse(withSnapshot.stdout).assessments, []);
  assert.equal(JSON.parse(withSnapshot.stdout).readyCaseCount, 0);
});

test('a read-only lookup still refuses an existing old schema without changing its bytes', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-casper-old-schema-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const databasePath = join(directory, 'cases.sqlite3');
  const created = spawnSync(python, ['-c', String.raw`
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute('CREATE TABLE existing_data (value TEXT NOT NULL)')
    connection.execute("INSERT INTO existing_data VALUES ('preserve this existing data')")
    connection.execute('PRAGMA user_version=5')
`, databasePath], { env: pythonEnvironment, encoding: 'utf8', timeout: 15_000 });
  assert.equal(created.status, 0, created.error?.message || created.stderr);
  const before = await readFile(databasePath);
  await assert.rejects(matchCasperHistory({ report, targetId: 'vul-web2-daehan', origin, databasePath }),
    /explicit database migration is required before read-only lookup/);
  assert.deepEqual(await readFile(databasePath), before);
});
