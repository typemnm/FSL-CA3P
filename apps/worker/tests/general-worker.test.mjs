import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../../packages/run-store/index.mjs';
import { runWorker } from '../worker.mjs';

async function waitFor(check, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('general worker state did not settle');
}

async function setup(modelId = 'deepseek-flash', loopBudget) {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'general-worker-'));
  const storePath = join(directory, 'runs.sqlite');
  const id = 'general-worker-run';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'local-lab-general', modelId,
    manifest: { runId: id, modules: {}, shared: {} },
    state: { id, mode: 'local-lab-general', assessmentMode: 'general', modelId,
      status: 'queued', events: [] },
    options: { mode: 'local-lab-general', testProfile: 'general', fixtureId: 'vul-web2-daehan',
      target: 'http://127.0.0.1:4101', delayMs: 0, ...(loopBudget ? { loopBudget } : {}) } });
  store.close();
  return { id, storePath, directory };
}

async function runWithFindings(t, { findings, status = 'completed', reportGenerator, beforeWait }) {
  const { id, storePath, directory } = await setup();
  const report = { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
    status, findings, evidence: [], coverage: { totalHypotheses: findings.length } };
  const generalRuntimeFactory = () => {
    let state; const listeners = new Set();
    return {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() {
        state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
          status, events: [], report, reviewItems: [] } };
        for (const listener of listeners) listener(structuredClone(state));
      },
      getState() { return structuredClone(state); }, stop() {}, async close() {},
    };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    env: {}, generalRuntimeFactory, reportGenerator });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  if (beforeWait) await beforeWait(worker, id);
  const run = await waitFor(() => { const value = worker.store.getRun(id);
    return value.status === status && value.reportDocuments?.completedAt && value; });
  return { worker, run };
}

test('general worker uses its own runtime and model, persists the report, and writes one confirmed HWPX', async t => {
  const loopBudget = { maxIterations: 10, maxProbes: 40, maxEvidenceItems: 180 };
  const { id, storePath, directory } = await setup('deepseek-flash', loopBudget);
  let legacyInvoked = false; let closed = false; let factoryOptions;
  const report = { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
    status: 'completed', findings: [{ id: 'f1', category: 'access_control', status: 'confirmed', evidenceIds: ['e1'] }],
    evidence: [{ id: 'e1', source: 'http-response', summary: 'role mismatch' }],
    coverage: { totalHypotheses: 2, confirmed: 1, notTested: 1 } };
  const generalRuntimeFactory = options => {
    factoryOptions = options;
    const listeners = new Set(); let state;
    return {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() {
        options.onModelCall({ provider: 'deepseek', requestedModel: options.modelId,
          usage: { prompt_tokens: 8, completion_tokens: 5 } });
        const probe = { iteration: 1, tool: 'http', session: 'test', method: 'POST',
          url: 'http://127.0.0.1:4101/api/probe' };
        const reservation = await options.beforeProbe(probe);
        await options.afterProbe(probe, { status: 'completed', evidenceId: 'e1', body: 'PRIVATE_RESPONSE' }, reservation);
        state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
          status: 'completed', events: [{ id: 'event-1', module: 'agent', stage: 'probe.verify', title: 'Verified' }],
          report, reviewItems: [] } };
        for (const listener of listeners) listener(structuredClone(state));
        return state;
      },
      getState() { return structuredClone(state); },
      stop() {},
      async close() { closed = true; },
    };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    env: { DEEPSEEK_API_KEY: 'test-only' },
    idorRuntimeFactory: () => { legacyInvoked = true; throw new Error('IDOR runtime called'); },
    generalRuntimeFactory,
    reportGenerator: ({ findingId }) => {
      assert.equal(findingId, 'f1');
      return { status: 'ready', filename: 'f1.hwpx', bytes: Buffer.from('PK\x03\x04f1') };
    } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'completed' && closed && state; });
  assert.equal(legacyInvoked, false);
  assert.equal(factoryOptions.modelId, 'deepseek-flash');
  assert.equal(factoryOptions.fixtureId, 'vul-web2-daehan');
  assert.equal(factoryOptions.targetOrigin, 'http://127.0.0.1:4101');
  assert.deepEqual(factoryOptions.limits, loopBudget);
  assert.equal(final.report.schemaVersion, 'general-assessment/1');
  assert.equal(final.report.findings.length, 1);
  assert.equal(final.historyWrite.status, 'skipped');
  assert.equal(final.reportDocuments.status, 'ready');
  assert.deepEqual(final.reportDocuments.items.map(item => [item.findingId, item.status]), [['f1', 'ready']]);
  assert.equal(worker.store.getArtifact(final.reportDocuments.items[0].artifactId).findingId, 'f1');
  assert.equal(final.modelCalls.length, 1);
  assert.ok(final.artifacts.some(artifact => artifact.kind === 'run-report'));
  const actions = worker.store.listActions(id);
  assert.equal(actions.length, 1);
  assert.equal(actions[0].status, 'completed');
  assert.doesNotMatch(actions[0].result_json, /PRIVATE_RESPONSE/);
});

test('general worker creates one document per confirmed finding and keeps other results in JSON', async t => {
  const calls = [];
  const { worker, run } = await runWithFindings(t, { findings: [
    { id: 'finding:h1', status: 'confirmed', evidenceIds: ['e1'] },
    { id: 'finding:h2', status: 'not_reproduced', evidenceIds: ['e2'] },
    { id: 'finding:h3', status: 'confirmed', evidenceIds: ['e3'] },
    { id: 'finding:h4', status: 'not_tested', evidenceIds: [] },
  ], reportGenerator: ({ findingId }) => {
    calls.push(findingId);
    return { status: 'ready', filename: `${findingId.slice(-2)}.hwpx`,
      bytes: Buffer.from(`PK\x03\x04${findingId}`) };
  } });
  assert.deepEqual(calls, ['finding:h1', 'finding:h3']);
  assert.equal(run.report.findings.length, 4);
  assert.equal(run.reportDocuments.status, 'ready');
  assert.deepEqual(run.reportDocuments.items.map(item => item.findingId), calls);
  assert.equal(new Set(run.reportDocuments.items.map(item => item.artifactId)).size, 2);
  for (const item of run.reportDocuments.items) {
    const artifact = worker.store.getArtifact(item.artifactId);
    assert.equal(artifact.findingId, item.findingId);
    assert.equal(artifact.kind, 'hwpx-report');
  }
});

test('general worker generates two distinct real Python HWPX files for two confirmed findings',
  { timeout: 60_000 }, async t => {
    const { id, storePath, directory } = await setup();
    const report = { schemaVersion: 'general-assessment/1', assessmentMode: 'general', runId: id,
      status: 'completed', target: { origin: 'http://127.0.0.1:4101' },
      hypotheses: [
        { id: 'h1', category: 'access_control', asset: '/api/records/:id', status: 'confirmed' },
        { id: 'h2', category: 'access_control', asset: '/api/posts/:id', status: 'confirmed' },
      ],
      findings: [
        { id: 'finding:h1', hypothesisId: 'h1', category: 'access_control',
          asset: '/api/records/:id', status: 'confirmed', evidenceIds: ['ev1'] },
        { id: 'finding:h2', hypothesisId: 'h2', category: 'access_control',
          asset: '/api/posts/:id', status: 'confirmed', evidenceIds: ['ev2'] },
      ],
      probes: [
        { id: 'p1', hypothesisId: 'h1', tool: 'known_record_idor_read', status: 'confirmed', evidenceIds: ['ev1'] },
        { id: 'p2', hypothesisId: 'h2', tool: 'known_cross_user_delete_canary', status: 'confirmed', evidenceIds: ['ev2'] },
      ],
      evidence: [
        { id: 'ev1', source: 'control', kind: 'role-comparison', summary: 'Cross-role record read was confirmed.' },
        { id: 'ev2', source: 'control', kind: 'owner-comparison', summary: 'Cross-owner delete was confirmed.' },
      ], coverage: { totalHypotheses: 2, confirmed: 2, notReproduced: 0, inconclusive: 0, notTested: 0 } };
    const events = [
      { id: 'verify-h1', source: 'agent/general-assessment', module: 'agent', stage: 'verify',
        request: { hypothesisId: 'h1', probeId: 'p1' }, response: { status: 'confirmed', evidenceIds: ['ev1'] } },
      { id: 'verify-h2', source: 'agent/general-assessment', module: 'agent', stage: 'verify',
        request: { hypothesisId: 'h2', probeId: 'p2' }, response: { status: 'confirmed', evidenceIds: ['ev2'] } },
    ];
    const generalRuntimeFactory = () => {
      let state; const listeners = new Set();
      return { subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
        async startLab() {
          state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
            status: 'completed', events, report, reviewItems: [] } };
          for (const listener of listeners) listener(structuredClone(state));
        },
        getState() { return structuredClone(state); }, stop() {}, async close() {} };
    };
    const localPython = fileURLToPath(new URL(`../../../.venv/${process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'}`, import.meta.url));
    const env = { ...process.env, DEEPSEEK_API_KEY: '', CA3P_REPORT_PYTHON: process.env.CA3P_REPORT_PYTHON
      || process.env.CASPER_DB_PYTHON || (existsSync(localPython) ? localPython : process.platform === 'win32' ? 'py' : 'python3') };
    const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, env, generalRuntimeFactory });
    t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
    const run = await waitFor(() => { const value = worker.store.getRun(id);
      return value.status === 'completed' && value.reportDocuments?.completedAt && value; }, 30_000);
    assert.equal(run.reportDocuments.status, 'ready', JSON.stringify(run.reportDocuments));
    const documents = run.reportDocuments.items;
    assert.deepEqual(documents.map(item => item.findingId), ['finding:h1', 'finding:h2']);
    assert.ok(documents.every(item => item.status === 'ready'));
    assert.equal(new Set(documents.map(item => item.artifactId)).size, 2);
    assert.equal(new Set(documents.map(item => item.filename)).size, 2);
    const binaries = documents.map(item => {
      const artifact = worker.store.getArtifact(item.artifactId);
      assert.equal(artifact.findingId, item.findingId);
      assert.equal(artifact.kind, 'hwpx-report');
      const bytes = readFileSync(artifact.path);
      assert.deepEqual(bytes.subarray(0, 4), Buffer.from([0x50, 0x4b, 0x03, 0x04]));
      const inspect = spawnSync(env.CA3P_REPORT_PYTHON, ['-c', `import io,json,sys,zipfile
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as archive:
    xml=''.join(archive.read(name).decode('utf-8') for name in archive.namelist() if name.startswith('Contents/section') and name.endswith('.xml'))
    print(json.dumps({'h1':'finding:h1' in xml,'h2':'finding:h2' in xml}))`],
      { input: bytes, encoding: 'utf8', env, windowsHide: true, timeout: 10_000 });
      assert.equal(inspect.status, 0, inspect.stderr);
      const ids = JSON.parse(inspect.stdout);
      assert.equal(ids[item.findingId.slice(-2)], true);
      assert.equal(ids[item.findingId === 'finding:h1' ? 'h2' : 'h1'], false);
      return bytes;
    });
    assert.notDeepEqual(binaries[0], binaries[1]);
  });

test('general worker skips HWPX generation when no finding is confirmed', async t => {
  const { run } = await runWithFindings(t, { findings: [
    { id: 'finding:h1', status: 'not_reproduced' },
    { id: 'finding:h2', status: 'inconclusive' },
  ], reportGenerator: () => assert.fail('No HWPX should be generated') });
  assert.equal(run.reportDocuments.status, 'skipped');
  assert.equal(run.reportDocuments.errorCode, 'NO_CONFIRMED_FINDINGS');
  assert.deepEqual(run.reportDocuments.items, []);
});

test('general worker preserves ready documents and the inspection when another document fails', async t => {
  const { worker, run } = await runWithFindings(t, { findings: [
    { id: 'finding:h1', status: 'confirmed' }, { id: 'finding:h2', status: 'confirmed' },
  ], reportGenerator: ({ findingId }) => {
    if (findingId === 'finding:h2') throw new Error('PRIVATE_REPORT_DETAIL');
    return { status: 'ready', filename: 'first.hwpx', bytes: Buffer.from('PK\x03\x04first') };
  } });
  assert.equal(run.status, 'completed');
  assert.equal(run.reportDocuments.status, 'partial');
  assert.deepEqual(run.reportDocuments.items.map(item => item.status), ['ready', 'failed']);
  assert.ok(worker.store.getArtifact(run.reportDocuments.items[0].artifactId));
  assert.doesNotMatch(JSON.stringify(run.reportDocuments), /PRIVATE_REPORT_DETAIL/);
});

test('general worker refuses to attach identical HWPX bytes to two different findings', async t => {
  const { run } = await runWithFindings(t, { findings: [
    { id: 'finding:h1', status: 'confirmed' }, { id: 'finding:h2', status: 'confirmed' },
  ], reportGenerator: () => ({ status: 'ready', filename: 'same.hwpx',
    bytes: Buffer.from('PK\x03\x04same-content') }) });
  assert.equal(run.reportDocuments.status, 'partial');
  assert.deepEqual(run.reportDocuments.items.map(item => item.status), ['ready', 'failed']);
  assert.equal(run.reportDocuments.items[1].artifactId, undefined);
});

test('general worker documents a confirmed finding retained in a failed inspection', async t => {
  const { run } = await runWithFindings(t, { status: 'failed', findings: [
    { id: 'finding:h1', status: 'confirmed' },
  ], reportGenerator: ({ findingId }) => ({ status: 'ready', filename: 'partial.hwpx',
    bytes: Buffer.from(`PK\x03\x04${findingId}`) }) });
  assert.equal(run.status, 'failed');
  assert.equal(run.reportDocuments.status, 'ready');
  assert.equal(run.reportDocuments.items[0].status, 'ready');
});

test('cancelling general document generation leaves the inspection and skips remaining documents', async t => {
  const calls = [];
  const { run } = await runWithFindings(t, { findings: [
    { id: 'finding:h1', status: 'confirmed' }, { id: 'finding:h2', status: 'confirmed' },
  ], reportGenerator: ({ findingId, signal }) => {
    calls.push(findingId);
    return new Promise(resolve => signal.addEventListener('abort', () => resolve({
      status: 'failed', errorCode: 'REPORT_CANCELLED', message: '보고서 생성을 취소했습니다.',
    }), { once: true }));
  }, beforeWait: async (worker, id) => {
    await waitFor(() => worker.store.getRun(id).reportDocuments?.items[0]?.status === 'generating');
    worker.store.requestCancel(id);
  } });
  assert.deepEqual(calls, ['finding:h1']);
  assert.equal(run.status, 'completed');
  assert.deepEqual(run.reportDocuments.items.map(item => item.status), ['failed', 'skipped']);
  assert.equal(run.reportDocuments.items[1].errorCode, 'REPORT_CANCELLED');
  assert.equal(run.report.findings.length, 2);
});

test('general worker rejects rule-baseline leases before creating a runtime', async t => {
  const { id, storePath, directory } = await setup('rule-baseline');
  let runtimeCreated = false;
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, env: {},
    generalRuntimeFactory: () => { runtimeCreated = true; throw new Error('should not start'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'failed' && state; });
  assert.equal(runtimeCreated, false);
  assert.match(final.error, /INVALID_GENERAL_RUN/);
});

test('cancelling a general run aborts its model and closes the runtime', async t => {
  const { id, storePath, directory } = await setup();
  let stopCalls = 0; let closed = false; let signal;
  const generalRuntimeFactory = options => {
    signal = options.signal;
    const listeners = new Set();
    let state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
      status: 'running', events: [] } };
    const publish = () => { for (const listener of listeners) listener(structuredClone(state)); };
    return {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() { publish(); return state; },
      stop() { stopCalls += 1; state = { run: { ...state.run, status: 'stopped' } }; publish(); },
      getState() { return structuredClone(state); },
      async close() { closed = true; },
    };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, env: {}, generalRuntimeFactory });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  await waitFor(() => worker.store.getRun(id).status === 'running');
  worker.store.requestCancel(id);
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'cancelled' && closed && state; });
  assert.ok(stopCalls >= 1);
  assert.equal(signal.aborted, true);
  assert.equal(final.reportDocuments.status, 'skipped');
});
