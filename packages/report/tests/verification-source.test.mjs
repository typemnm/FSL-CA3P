import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateReportDocument } from '../index.mjs';

const env = { DEEPSEEK_API_KEY: 'report-test-fake-key' };
const run = { id: 'report-run-verification', mode: 'local-lab-rule', simulated: false,
  report: { runId: 'report-run-verification', status: 'completed' } };

test('verificationDir adds a handoff-dir source to the trigger only when given', async t => {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  await mkdir(temporaryRoot, { recursive: true });
  const directory = await mkdtemp(join(temporaryRoot, 'rv-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const triggers = [];
  const execute = async ({ input }) => {
    triggers.push(JSON.parse(input));
    return { code: 1, stdout: '{"ok":false}' };
  };
  const options = { run, storePath: join(directory, 'runs.sqlite'), envFile: null, env, execute };
  const verificationDir = join(directory, 'verifications', 'p-a');

  await generateReportDocument({ ...options, verificationDir });
  await generateReportDocument(options);

  assert.deepEqual(triggers[0].sources.verification,
    { kind: 'handoff-dir', location: resolve(verificationDir) });
  assert.equal('verification' in triggers[1].sources, false);
});
