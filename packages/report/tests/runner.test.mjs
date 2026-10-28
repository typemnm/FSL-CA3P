import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeReportProcess, generateReportDocument } from '../index.mjs';

const sha = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const env = { DEEPSEEK_API_KEY: 'report-test-fake-key' };
const run = { id: 'report-run-test', mode: 'local-lab-rule', simulated: false,
  report: { runId: 'report-run-test', status: 'completed' } };
const hwpx = Buffer.from('PK\x03\x04synthetic document');
async function setup(t) {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  await mkdir(temporaryRoot, { recursive: true });
  const directory = await mkdtemp(join(temporaryRoot, 'rt-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, storePath: join(directory, 'runs.sqlite') };
}
function successfulExecution(change = value => value, modelRunId) {
  return async ({ input, args, env: childEnv }) => {
    assert.deepEqual(args, ['-m', 'ca3p_report', 'run', '--trigger', '-']);
    assert.equal(childEnv.DEEPSEEK_API_KEY, env.DEEPSEEK_API_KEY);
    assert.equal(childEnv.DEEPSEEK_MODEL, 'deepseek-flash');
    const trigger = JSON.parse(input);
    assert.equal(trigger.sources.run.kind, 'run-store');
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify({ run: { runId: modelRunId ?? trigger.runId } }));
    await writeFile(join(directory, '검사결과.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    return { code: 0, stdout: JSON.stringify(change({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: trigger.runId, reportFilename: '검사결과.hwpx', files: [
        { name: '검사결과.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
      ] })) };
  };
}

test('fixture and missing API configuration never start a report process', async t => {
  const options = await setup(t);
  const execute = () => assert.fail('must not dispatch');
  assert.equal((await generateReportDocument({ ...options, run: { ...run, mode: 'core-fixture' }, envFile: null, env, execute })).status, 'skipped');
  const missing = await generateReportDocument({ ...options, run, envFile: null, env: {}, execute });
  assert.equal(missing.status, 'unavailable');
  assert.equal(missing.errorCode, 'REPORT_NOT_CONFIGURED');
});

test('checks CLI run identity, filename, model identity and hashes before returning HWPX bytes', async t => {
  const options = await setup(t);
  const result = await generateReportDocument({ ...options, run, env, envFile: null, execute: successfulExecution() });
  assert.equal(result.status, 'ready');
  assert.equal(result.filename, '검사결과.hwpx');
  assert.deepEqual(result.bytes, hwpx);
  for (const change of [
    value => ({ ...value, runId: 'another-run' }),
    value => ({ ...value, reportFilename: '../escape.hwpx' }),
    value => ({ ...value, files: value.files.map(item => ({ ...item, sha256: `sha256:${'0'.repeat(64)}` })) }),
  ]) {
    const rejected = await generateReportDocument({ ...options, run, env, envFile: null, execute: successfulExecution(change) });
    assert.equal(rejected.status, 'failed');
    assert.equal(rejected.errorCode, 'REPORT_INVALID_OUTPUT');
    assert.equal('bytes' in rejected, false);
  }
  const wrongModel = await generateReportDocument({ ...options, run, env, envFile: null,
    execute: successfulExecution(undefined, 'another-model-run') });
  assert.equal(wrongModel.errorCode, 'REPORT_INVALID_OUTPUT');
});

test('provider errors and raw output never enter public failure messages', async t => {
  const options = await setup(t);
  const result = await generateReportDocument({ ...options, run, env, envFile: null,
    execute: async () => ({ code: 8, stdout: JSON.stringify({ ok: false, error: { message: '/private/path SECRET' } }) }) });
  assert.equal(result.status, 'failed');
  assert.equal(result.errorCode, 'REPORT_LLM_FAILED');
  assert.doesNotMatch(JSON.stringify(result), /SECRET|private|report-test-fake-key/);
});

test('general report selects one confirmed finding without a model key and rejects mismatched output', async t => {
  const options = await setup(t);
  const generalRun = { id: 'general-report-run', mode: 'local-lab-general', simulated: false,
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general', status: 'completed',
      findings: [{ id: 'finding:h-a', status: 'confirmed', evidenceIds: ['ev-a'] },
        { id: 'finding:h-b', status: 'not_reproduced', evidenceIds: ['ev-b'] }] } };
  const runGeneral = (modelChange = value => value, responseChange = value => value) => async ({ input, env: childEnv }) => {
    const trigger = JSON.parse(input);
    assert.deepEqual(trigger.options, { findingId: 'finding:h-a' });
    assert.equal(childEnv.DEEPSEEK_API_KEY, undefined);
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify(modelChange({ run: { runId: trigger.runId, status: 'completed' },
      generator: { method: 'deterministic' },
      sourceFindingId: 'finding:h-a', sourceEvidenceIds: ['ev-a'],
      findings: [{ common: { findingId: 'finding:h-a', status: 'confirmed' } }] })));
    await writeFile(join(directory, 'selected.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    return { code: 0, stdout: JSON.stringify(responseChange({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: trigger.runId, findingId: 'finding:h-a', reportFilename: 'selected.hwpx', files: [
        { name: 'selected.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
      ] })) };
  };
  const result = await generateReportDocument({ ...options, run: generalRun, findingId: 'finding:h-a',
    env: {}, envFile: null, execute: runGeneral() });
  assert.equal(result.status, 'ready');
  assert.equal(result.findingId, 'finding:h-a');
  for (const execute of [
    runGeneral(value => ({ ...value, sourceFindingId: 'finding:h-b' })),
    runGeneral(value => ({ ...value, findings: [{ common: { findingId: 'finding:h-a', status: 'not_reproduced' } }] })),
    runGeneral(undefined, value => ({ ...value, findingId: 'finding:h-b' })),
  ]) {
    const rejected = await generateReportDocument({ ...options, run: generalRun, findingId: 'finding:h-a',
      env: {}, envFile: null, execute });
    assert.equal(rejected.errorCode, 'REPORT_INVALID_OUTPUT');
  }
  const never = () => assert.fail('nonconfirmed finding must not start Python');
  const unconfirmed = await generateReportDocument({ ...options, run: generalRun,
    findingId: 'finding:h-b', env: {}, envFile: null, execute: never });
  assert.equal(unconfirmed.errorCode, 'REPORT_INVALID_SELECTION');
});

test('process timeout, cancellation and output cap terminate the child', async () => {
  const invoke = options => executeReportProcess({ command: process.execPath,
    args: ['-e', 'setInterval(() => {}, 1000)'], input: '', ...options });
  await assert.rejects(invoke({ timeoutMs: 50 }), { code: 'REPORT_TIMEOUT' });
  const controller = new AbortController();
  const pending = invoke({ signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { code: 'REPORT_CANCELLED' });
  await assert.rejects(invoke({ args: ['-e', 'process.stdout.write("x".repeat(1000)); setInterval(() => {}, 1000)'],
    maxOutputBytes: 100 }), { code: 'REPORT_OUTPUT_LIMIT' });
});
