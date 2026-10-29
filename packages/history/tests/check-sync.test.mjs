import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { syncRunChecks, reviewRunCheck } from '../check-sync.mjs';

test('simulated runs and invalid review IDs do not become real case checks', async () => {
  assert.equal((await syncRunChecks({ simulated: true }, {})).status, 'not-applicable');
  await assert.rejects(reviewRunCheck('../escape', { note: 'invalid' }), { status: 400 });
});

test('a run without explicit case results does not create a case check', async () => {
  const directory = join(tmpdir(), 'ca3p-history-no-results');
  const result = await syncRunChecks({ id: 'run-no-results', simulated: false,
    report: { schemaVersion: 'general-assessment/1' }, events: [] }, {
    artifact: { path: join(directory, 'artifacts', 'run.json') },
    storePath: join(directory, 'runs.sqlite'),
  });
  assert.deepEqual(result, { status: 'not-applicable', checks: [], reason: 'no-explicit-results' });
});
