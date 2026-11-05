import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeReportProcess, generateReportDocument } from '../index.mjs';

const sha = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const env = { DEEPSEEK_API_KEY: 'report-test-fake-key' };
const run = { id: 'report-run-test', mode: 'local-lab-rule', modelId: 'rule-baseline', simulated: false,
  report: { runId: 'report-run-test', status: 'completed', finding: { category: 'CWE-639', status: 'confirmed' } } };
const legacyModel = (runId, verdict = 'confirmed') => ({ run: { run_id: runId, status: 'completed' },
  sourceFindingId: 'finding', sourceEvidenceIds: [], findings: [{ id: 'V-01', finding_id: 'finding', verdict }] });
const hwpx = Buffer.from('PK\x03\x04synthetic document');
const preview = Buffer.from('# 검사 결과\n\n| 항목 | 값 |\n| --- | --- |\n| 상태 | 완료 |\n');
const htmlPreview = Buffer.from('<!doctype html><html><body><table><tr><td>완료</td></tr></table></body></html>');
async function setup(t) {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  await mkdir(temporaryRoot, { recursive: true });
  const directory = await mkdtemp(join(temporaryRoot, 'rt-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, storePath: join(directory, 'runs.sqlite') };
}
function successfulExecution(change = value => value, modelRunId, modelName = 'deepseek-flash') {
  return async ({ input, args, env: childEnv }) => {
    assert.deepEqual(args, ['-m', 'ca3p_report', 'run', '--trigger', '-']);
    assert.equal(childEnv.DEEPSEEK_API_KEY, env.DEEPSEEK_API_KEY);
    assert.equal(childEnv.DEEPSEEK_MODEL, modelName);
    const trigger = JSON.parse(input);
    assert.equal(trigger.sources.run.kind, 'run-store');
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify(legacyModel(modelRunId ?? trigger.runId)));
    await writeFile(join(directory, '검사결과.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    await writeFile(join(directory, 'report.md'), preview);
    await writeFile(join(directory, 'report.html'), htmlPreview);
    return { code: 0, stdout: JSON.stringify(change({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: trigger.runId, findingId: 'finding', reportFilename: '검사결과.hwpx', files: [
        { name: '검사결과.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
        { name: 'report.md', sha256: sha(preview), size: preview.length },
        { name: 'report.html', sha256: sha(htmlPreview), size: htmlPreview.length },
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
  assert.equal(result.previewMarkdown, preview.toString('utf8'));
  assert.equal(result.previewHtml, htmlPreview.toString('utf8'));
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

test('the report uses the run model, falls back for rule-only runs and refuses other models', async t => {
  const options = await setup(t);
  for (const [modelId, used] of [['deepseek-v4-pro', 'deepseek-v4-pro'], ['deepseek-flash', 'deepseek-flash'],
    ['rule-baseline', 'deepseek-flash'], [undefined, 'deepseek-flash']]) {
    const result = await generateReportDocument({ ...options, run: { ...run, modelId }, env, envFile: null,
      execute: successfulExecution(undefined, undefined, used) });
    assert.equal(result.status, 'ready', String(modelId));
  }
  const local = await generateReportDocument({ ...options, run: { ...run, modelId: 'local-llm' }, env, envFile: null,
    execute: () => assert.fail('a local-model run must not be sent to DeepSeek') });
  assert.equal(local.errorCode, 'REPORT_NOT_CONFIGURED');
});

test('legacy output must keep the source finding identity and verdict', async t => {
  const options = await setup(t);
  const unconfirmed = { ...run, report: { ...run.report, finding: { status: 'not_confirmed' } } };
  for (const [change, source = run, accepted = false] of [
    [value => ({ ...value, sourceFindingId: 'another' })],
    [value => ({ ...value, findings: [{ ...value.findings[0], verdict: 'unverified' }] })],
    [value => ({ ...value, findings: [{ ...value.findings[0], finding_id: 'another' }] })],
    [value => ({ ...value, findings: [...value.findings, ...value.findings] })],
    [value => ({ ...value, sourceEvidenceIds: ['invented'] })],
    [value => value, unconfirmed],
    [value => ({ ...value, findings: [{ ...value.findings[0], verdict: 'unverified' }] }), unconfirmed, true],
  ]) {
    const execute = async args => {
      const trigger = JSON.parse(args.input);
      const directory = join(trigger.output.dir, 'report');
      await mkdir(directory);
      const model = Buffer.from(JSON.stringify(change(legacyModel(trigger.runId))));
      await writeFile(join(directory, 'r.hwpx'), hwpx);
      await writeFile(join(directory, 'report-model.json'), model);
      return { code: 0, stdout: JSON.stringify({ schemaVersion: 'report-result-1.0', ok: true, stage: 'reported',
        runId: trigger.runId, findingId: 'finding', reportFilename: 'r.hwpx', files: [
          { name: 'r.hwpx', sha256: sha(hwpx), size: hwpx.length },
          { name: 'report-model.json', sha256: sha(model), size: model.length }] }) };
    };
    const result = await generateReportDocument({ ...options, run: source, env, envFile: null, execute });
    assert.equal(result.status, accepted ? 'ready' : 'failed');
    if (!accepted) assert.equal(result.errorCode, 'REPORT_INVALID_OUTPUT');
  }
});

test('general report selects one confirmed finding and rejects mismatched output', async t => {
  const options = await setup(t);
  const generalRun = { id: 'general-report-run', mode: 'local-lab-general', modelId: 'deepseek-flash', simulated: false,
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general', status: 'completed',
      findings: [{ id: 'finding:h-a', status: 'confirmed', evidenceIds: ['ev-a'] },
        { id: 'finding:h-b', status: 'not_reproduced', evidenceIds: ['ev-b'] }] } };
  const runGeneral = (modelChange = value => value, responseChange = value => value) => async ({ input, env: childEnv }) => {
    const trigger = JSON.parse(input);
    assert.deepEqual(trigger.options, { findingId: 'finding:h-a' });
    assert.equal(childEnv.DEEPSEEK_API_KEY, env.DEEPSEEK_API_KEY);
    assert.equal(childEnv.DEEPSEEK_MODEL, 'deepseek-flash');
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify(modelChange({ run: { run_id: trigger.runId, status: 'completed' },
      generator: { method: 'llm' },
      sourceFindingId: 'finding:h-a', sourceEvidenceIds: ['ev-a'],
      findings: [{ id: 'V-01', finding_id: 'finding:h-a', verdict: 'confirmed' }] })));
    await writeFile(join(directory, 'selected.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    return { code: 0, stdout: JSON.stringify(responseChange({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: trigger.runId, findingId: 'finding:h-a', reportFilename: 'selected.hwpx', files: [
        { name: 'selected.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
      ] })) };
  };
  const result = await generateReportDocument({ ...options, run: generalRun, findingId: 'finding:h-a',
    env, envFile: null, execute: runGeneral() });
  assert.equal(result.status, 'ready');
  assert.equal(result.findingId, 'finding:h-a');
  for (const execute of [
    runGeneral(value => ({ ...value, sourceFindingId: 'finding:h-b' })),
    runGeneral(value => ({ ...value, findings: [{ id: 'V-01', finding_id: 'finding:h-a', verdict: 'unverified' }] })),
    runGeneral(value => ({ ...value, run: { ...value.run, run_id: 'another-run' } })),
    runGeneral(undefined, value => ({ ...value, findingId: 'finding:h-b' })),
    runGeneral(value => ({ ...value, sourceEvidenceIds: ['ev-b'] })),
  ]) {
    const rejected = await generateReportDocument({ ...options, run: generalRun, findingId: 'finding:h-a',
      env, envFile: null, execute });
    assert.equal(rejected.errorCode, 'REPORT_INVALID_OUTPUT');
  }
  const never = () => assert.fail('nonconfirmed finding must not start Python');
  const unconfirmed = await generateReportDocument({ ...options, run: generalRun,
    findingId: 'finding:h-b', env, envFile: null, execute: never });
  assert.equal(unconfirmed.errorCode, 'REPORT_INVALID_SELECTION');
});

test('a custom AI API provider run writes its report through the provider settings', async t => {
  const options = await setup(t);
  const customRun = { id: 'custom-report-run', mode: 'local-lab-general', modelId: 'custom-ab0537de1cad',
    simulated: false,
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general', status: 'completed',
      findings: [{ id: 'finding:h-a', status: 'confirmed', evidenceIds: ['ev-a'] }] } };
  const providerSettings = { baseUrl: 'https://api-sf1-cdn.deploy.com/api/v1',
    apiKey: 'provider-test-fake-key', model: 'deepseek-ai/deepseek-v4.1-flash-1017', maxTokens: 32768 };
  const execute = async ({ env: childEnv, input }) => {
    assert.equal(childEnv.DEEPSEEK_BASE_URL, providerSettings.baseUrl);
    assert.equal(childEnv.DEEPSEEK_API_KEY, providerSettings.apiKey);
    assert.equal(childEnv.DEEPSEEK_MODEL, providerSettings.model);
    assert.equal(childEnv.DEEPSEEK_MAX_TOKENS, '32768');
    const trigger = JSON.parse(input);
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify({ run: { run_id: trigger.runId, status: 'completed' },
      generator: { method: 'llm' }, sourceFindingId: 'finding:h-a', sourceEvidenceIds: ['ev-a'],
      findings: [{ id: 'V-01', finding_id: 'finding:h-a', verdict: 'confirmed' }] }));
    await writeFile(join(directory, 'selected.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    return { code: 0, stdout: JSON.stringify({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: trigger.runId, findingId: 'finding:h-a', reportFilename: 'selected.hwpx', files: [
        { name: 'selected.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
      ] }) };
  };
  const result = await generateReportDocument({ ...options, run: customRun, findingId: 'finding:h-a',
    env, envFile: null, providerSettings, execute });
  assert.equal(result.status, 'ready');
  assert.equal(result.findingId, 'finding:h-a');
  // Without the provider settings the same custom run cannot be configured.
  const missing = await generateReportDocument({ ...options, run: customRun, findingId: 'finding:h-a',
    env, envFile: null, execute: () => assert.fail('a custom run without provider settings must not dispatch') });
  assert.equal(missing.errorCode, 'REPORT_NOT_CONFIGURED');
});

test('child report requires completed task provenance and a matching CLI result', async t => {
  const options = await setup(t);
  const parent = { ...run, id: 'parent-run', mode: 'local-lab-general', modelId: 'deepseek-flash',
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
      runId: 'parent-run', status: 'completed',
      findings: [{ id: 'finding:h-a', hypothesisId: 'h-a', status: 'not_tested', evidenceIds: ['seed'] }] } };
  const subtask = { id: 'sub-one', kind: 'finding-followup', status: 'completed',
    sourceFindingId: 'finding:h-a', input: { hypothesisId: 'h-a' },
    result: { report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
      runId: 'sub-one', status: 'completed',
      findings: [{ id: 'finding:h-a', hypothesisId: 'h-a', status: 'confirmed',
        evidenceIds: ['child-evidence'] }] } } };
  const execute = (reportedSubtaskId = 'sub-one') => async ({ input }) => {
    const trigger = JSON.parse(input);
    assert.deepEqual(trigger.options, { findingId: 'finding:h-a', subtaskId: 'sub-one' });
    const directory = join(trigger.output.dir, 'report');
    await mkdir(directory);
    const model = Buffer.from(JSON.stringify({ run: { run_id: 'parent-run', status: 'completed' },
      sourceFindingId: 'finding:h-a', sourceEvidenceIds: ['child-evidence'],
      findings: [{ id: 'V-01', finding_id: 'finding:h-a', verdict: 'confirmed' }] }));
    await writeFile(join(directory, 'child.hwpx'), hwpx);
    await writeFile(join(directory, 'report-model.json'), model);
    return { code: 0, stdout: JSON.stringify({ schemaVersion: 'report-result-1.0', ok: true,
      stage: 'reported', runId: 'parent-run', findingId: 'finding:h-a',
      subtaskId: reportedSubtaskId, reportFilename: 'child.hwpx', files: [
        { name: 'child.hwpx', sha256: sha(hwpx), size: hwpx.length },
        { name: 'report-model.json', sha256: sha(model), size: model.length },
      ] }) };
  };
  const selected = { ...options, run: parent, findingId: 'finding:h-a', subtaskId: 'sub-one',
    subtask, env, envFile: null };
  const result = await generateReportDocument({ ...selected, execute: execute() });
  assert.equal(result.status, 'ready');
  assert.equal(result.subtaskId, 'sub-one');
  assert.equal(result.sourceFindingId, 'finding:h-a');
  const foreign = await generateReportDocument({ ...selected, execute: execute('other-task') });
  assert.equal(foreign.errorCode, 'REPORT_INVALID_OUTPUT');
  for (const task of [{ ...subtask, status: 'failed' },
    { ...subtask, sourceFindingId: 'another-finding' },
    { ...subtask, result: { report: { ...subtask.result.report, runId: 'other-task' } } }]) {
    const rejected = await generateReportDocument({ ...selected, subtask: task,
      execute: () => assert.fail('invalid task must not start Python') });
    assert.equal(rejected.errorCode, 'REPORT_INVALID_SELECTION');
  }
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
