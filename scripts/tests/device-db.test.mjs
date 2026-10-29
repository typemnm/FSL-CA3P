import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('device database snapshots, schema migration and rollback preserve private state', { timeout: 60_000 }, () => {
  const suite = fileURLToPath(new URL('./device_db_test.py', import.meta.url));
  const source = fileURLToPath(new URL('../../casper-db/src', import.meta.url));
  const result = spawnSync(process.env.CASPER_DB_PYTHON || 'python3', [suite], {
    encoding: 'utf8', env: { ...process.env, PYTHONPATH: source, CA3P_NODE: process.execPath }, timeout: 55_000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
