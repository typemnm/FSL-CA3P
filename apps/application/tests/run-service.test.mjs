import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRunService } from '../run-service.mjs';

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-service-test-')); const storePath = join(directory, 'runs.sqlite');
  const service = createRunService({ storePath, envFile: null, env: { ...process.env, DEEPSEEK_API_KEY: '' }, ...options });
  t.after(async () => { await service.close(); rmSync(directory, { recursive: true, force: true }); });
  return { service, storePath };
}
async function waitFor(service, id, terminal = ['completed', 'failed', 'interrupted', 'cancelled']) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const state = service.getRun(id);
    if (terminal.includes(state.status)) return state;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Worker did not finish the run.');
}
test('a separate worker executes queued fixture runs and history survives API restart', async t => {
  const { service, storePath } = setup(t);
  const started = await service.start({ mode: 'core-fixture', target: 'https://display.invalid', delayMs: 0 });
  assert.equal(started.run.status, 'queued');
  const final = await waitFor(service, started.run.id);
  assert.equal(final.status, 'completed', final.error);
  assert.equal(final.id, final.coreRunId); assert.equal(final.id, final.report.runId);
  assert.equal(final.events.length, 25); assert.equal(final.events.at(-1).sequence, 25);
  assert.ok(final.manifest.modules.agent.contentDigest); assert.ok(final.artifacts.some(item => item.kind === 'run-report'));
  await service.close();
  const restarted = createRunService({ storePath, autoStartWorker: false, envFile: null }); t.after(() => restarted.close());
  assert.equal(restarted.getState().run.id, final.id); assert.equal(restarted.getRun(final.id).status, 'completed');
});
test('queued cancellation never reaches a worker; arbitrary lab targets are rejected', async t => {
  const { service } = setup(t, { autoStartWorker: false });
  await assert.rejects(service.start({ mode: 'local-lab-rule', target: 'https://remote.invalid' }), { status: 400 });
  const state = await service.start({ mode: 'core-fixture' });
  assert.equal(service.stop(state.run.id).run.status, 'cancelled');
  assert.equal(service.store.claimNext('test-worker'), null); assert.equal(service.reset().run.status, 'idle');
});
