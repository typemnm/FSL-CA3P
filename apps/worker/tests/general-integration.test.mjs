import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunService } from '../../application/run-service.mjs';
import { runWorker } from '../worker.mjs';

async function waitFor(check) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('general integration run did not finish');
}

test('service, worker, and general runtime create a real HWPX for a confirmed finding without a report model API',
  { timeout: 60_000 }, async () => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'general-integration-'));
  const storePath = join(directory, 'runs.sqlite');
  const localPython = fileURLToPath(new URL(`../../../.venv/${process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'}`, import.meta.url));
  const env = { ...process.env, DEEPSEEK_API_KEY: 'synthetic-test-only',
    CA3P_REPORT_PYTHON: process.env.CA3P_REPORT_PYTHON || process.env.CASPER_DB_PYTHON
      || (existsSync(localPython) ? localPython : process.platform === 'win32' ? 'py' : 'python3') };
  let service; let worker; let reopened;
  try {
    service = createRunService({ storePath, autoStartWorker: false, importLegacy: false,
      envFile: null, env });
    const queued = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-flash',
      fixtureId: 'vul-web2-daehan', target: 'http://127.0.0.1:4101' });
    const id = queued.run.id;
    const fetchCalls = [];
    const generalFetchImpl = async (url, init) => {
      const parsed = new URL(url);
      fetchCalls.push({ origin: parsed.origin, path: parsed.pathname, method: init.method,
        authenticated: Boolean(init.headers?.cookie) });
      if (parsed.pathname === '/login' && init.method === 'POST') {
        const account = new URLSearchParams(init.body).get('username');
        return new Response('', { status: 302,
          headers: { location: '/mypage', 'set-cookie': `sid=${account}private; HttpOnly; Path=/` } });
      }
      if (parsed.pathname === '/api/search') {
        return new Response(JSON.stringify({ site: '대한대학교', results: [] }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('<html><title>대한대학교</title><a href="/about">About</a>'
        + '<form action="/api/search" method="get"></form></html>', {
        status: 200, headers: { 'content-type': 'text/html' },
      });
    };
    const generalPlannerFactory = () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: { provider: 'deepseek', requestedModel: 'deepseek-flash',
          status: 'completed', usage: { prompt_tokens: 6, completion_tokens: 2 } } };
      const observedEvidenceId = context.evidence[0].id;
      return { done: false, hypotheses: [
        { id: 'h-access', category: 'access_control',
          asset: '/api/admissions/partner/applications/:id',
          rationale: 'Compare owner and non-owner records.', evidenceIds: [observedEvidenceId] },
        { id: 'h-xss', category: 'xss', asset: '/api/search',
          rationale: 'Search input exists, but browser verification is unavailable.',
          evidenceIds: [observedEvidenceId] },
      ], probes: [{ id: 'p-access', hypothesisId: 'h-access',
        tool: 'known_record_idor_read', input: {} }],
      modelMetadata: { provider: 'deepseek', requestedModel: 'deepseek-flash',
        status: 'completed', usage: { prompt_tokens: 12, completion_tokens: 5 } } };
    } });
    const generalIdorProbe = async () => ({ finding: { status: 'confirmed' }, evidence: [
      { check: 'firstOwner', recordId: 1, status: 200, ownerId: 4 },
      { check: 'secondOwner', recordId: 3, status: 200, ownerId: 5 },
      { check: 'crossOwner', recordId: 3, status: 200, ownerId: 5 },
      { check: 'studentRole', recordId: 3, status: 403, ownerId: null },
    ] });
    worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 20,
      env, generalPlannerFactory, generalFetchImpl, generalIdorProbe });
    const final = await waitFor(() => { const run = service.getRun(id); return run.status === 'completed' && run; });
    assert.equal(final.assessmentMode, 'general');
    assert.equal(final.report.schemaVersion, 'general-assessment/1');
    assert.equal(final.report.findings.length, 2);
    assert.equal(final.report.findings.find(item => item.hypothesisId === 'h-access').status, 'confirmed');
    assert.equal(final.report.findings.find(item => item.hypothesisId === 'h-xss').status, 'not_tested');
    assert.equal(final.modelCalls.length, 2);
    assert.equal(final.reportDocuments.status, 'ready', JSON.stringify(final.reportDocuments));
    assert.deepEqual(final.reportDocuments.items.map(item => [item.findingId, item.status]),
      [['finding:h-access', 'ready']]);
    assert.match(final.reportDocuments.items[0].filename, /\.hwpx$/);
    assert.equal(worker.store.getArtifact(final.reportDocuments.items[0].artifactId).kind, 'hwpx-report');
    assert.equal(final.historyWrite.status, 'skipped');
    assert.ok(final.artifacts.some(item => item.kind === 'run-report'));
    assert.ok(fetchCalls.length >= 2);
    assert.ok(fetchCalls.some(call => call.authenticated));
    assert.ok(fetchCalls.every(call => call.origin === 'http://127.0.0.1:4101'
      && (call.method === 'GET' || (call.method === 'POST' && call.path === '/login'))),
    JSON.stringify(fetchCalls));

    await worker.shutdown(); worker = null;
    await service.close(); service = null;
    reopened = createRunService({ storePath, autoStartWorker: false, importLegacy: false,
      envFile: null, env: {} });
    const saved = reopened.getRun(id);
    assert.equal(saved.report.findings.length, 2);
    assert.equal(saved.reportDocuments.items.length, 1);
    assert.equal(saved.modelCalls.length, 2);
    assert.equal(reopened.listRuns().items[0].id, id);
  } finally {
    await worker?.shutdown();
    await service?.close();
    await reopened?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('general worker starts the real isolated board and records a bounded read without parser execution', async () => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'general-board-integration-'));
  const storePath = join(directory, 'runs.sqlite');
  const env = { DEEPSEEK_API_KEY: 'synthetic-test-only',
    CASPER_DB_PYTHON: 'missing-ca3p-python-for-test' };
  let service; let worker;
  try {
    service = createRunService({ storePath, autoStartWorker: false, importLegacy: false,
      envFile: null, env });
    const queued = await service.start({ mode: 'local-lab-general',
      modelId: 'deepseek-flash', fixtureId: 'vul-web-1' });
    const id = queued.run.id;
    worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 20, env,
      generalPlannerFactory: () => ({ async propose(context) {
        if (context.iteration > 1) return { done: true, hypotheses: [], probes: [],
          modelMetadata: { provider: 'deepseek', requestedModel: 'deepseek-flash' } };
        return { done: false, hypotheses: [{ id: 'h-board', category: 'access_control',
          asset: '/api/posts', rationale: 'Board read surface should be observed.',
          evidenceIds: [context.evidence[0].id] }],
        probes: [{ id: 'p-board', hypothesisId: 'h-board', tool: 'http_get',
          input: { path: '/api/posts' } }],
        modelMetadata: { provider: 'deepseek', requestedModel: 'deepseek-flash' } };
      } }),
      reportGenerator: () => assert.fail('unconfirmed findings must not invoke the HWPX generator') });
    const final = await waitFor(() => { const run = service.getRun(id); return run.status === 'completed' && run; });
    assert.match(final.target, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(final.targetContacted, true);
    assert.equal(final.report.schemaVersion, 'general-assessment/1');
    assert.equal(final.report.findings.length, 1);
    assert.equal(final.report.findings[0].status, 'inconclusive');
    assert.equal(final.modelCalls.length, 2);
    assert.deepEqual(final.manifest.data.caseRevisions, []);
    assert.equal(final.reportDocuments.status, 'skipped');
    assert.equal(final.reportDocuments.errorCode, 'NO_CONFIRMED_FINDINGS');
  } finally {
    await worker?.shutdown();
    await service?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
