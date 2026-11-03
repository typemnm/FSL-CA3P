import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunService } from '../../application/run-service.mjs';
import { runWorker } from '../worker.mjs';
import { createGeneralRuntime } from '../../application/general-runtime.mjs';

// The AI verifier is scripted so these runs never reach a real model.
const scriptedRuntime = status => options => createGeneralRuntime({ ...options,
  enableRequiredTemplates: false,
  verifyAttackImpl: async record => ({ schemaVersion: 'verifier/1', attackId: record.id, status,
    reason: 'scripted ' + status, artifacts: [] }) });

const toolCall = (name, args) => ({ role: 'assistant', content: null, tool_calls: [{
  id: name, type: 'function', function: { name, arguments: JSON.stringify(args) },
}] });

async function waitFor(check) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('general integration run did not finish');
}
async function approvePending(worker, service, runId) {
  const pending = await waitFor(() => service.getRun(runId).pendingApproval);
  assert.equal(pending.kind, 'general-probe');
  const result = await worker.decideApproval({ runId, approvalId: pending.id,
    decision: 'approve', actor: 'admin' });
  assert.equal(result.decision, 'approved');
}

test('service, worker, and general runtime turn an AI-confirmed probe into a real HWPX written by a loopback report model',
  { timeout: 60_000 }, async () => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'general-integration-'));
  const storePath = join(directory, 'runs.sqlite');
  const origin = 'http://127.0.0.1:53987';
  // Loopback stand-in for the report LLM: read the sealed finding, then submit a minimal model.
  let reportRequests = 0; let protocolFailure; const written = [];
  const provider = http.createServer(async (req, res) => {
    try {
      assert.equal(`${req.method} ${req.url}`, 'POST /chat/completions');
      assert.equal(req.headers.authorization, 'Bearer synthetic-test-only');
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      assert.equal(input.model, 'deepseek-flash');
      reportRequests += 1;
      const tool = input.messages.find(item => item.role === 'tool' && item.tool_call_id === 'read_bundle');
      let message;
      if (!tool) message = toolCall('read_bundle', { path: 'run/finding.json' });
      else {
        written.push(JSON.parse(JSON.parse(tool.content).content).sourceFindingId);
        message = toolCall('finish_report', { filename: '합성 접근 제어 보고서.hwpx', model: {
          findings: [{ common: { title: '합성 접근 제어 우회', cwe: 'CWE-639',
            cvss: { version: '3.1', score: 6.5, rating: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
            summary: '다른 사용자의 지원서를 읽을 수 있습니다.', remediation: '서버에서 소유자를 확인합니다.' },
          reproduction: [{ step: 1, text: '다른 계정으로 같은 지원서를 요청합니다.' }] }] } });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message }] }));
    } catch (error) {
      protocolFailure = error;
      res.writeHead(500, { 'Content-Type': 'application/json' }); res.end('{"error":"synthetic protocol mismatch"}');
    }
  });
  provider.listen(0, '127.0.0.1'); await once(provider, 'listening');
  const localPython = fileURLToPath(new URL(`../../../.venv/${process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'}`, import.meta.url));
  // Only the loopback fake can receive the synthetic key: provider and proxy settings are all overridden.
  const env = { ...process.env, DEEPSEEK_BASE_URL: `http://127.0.0.1:${provider.address().port}`,
    DEEPSEEK_API_KEY: 'synthetic-test-only', DEEPSEEK_MODEL: 'deepseek-flash',
    HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '', http_proxy: '', https_proxy: '', all_proxy: '',
    NO_PROXY: '127.0.0.1', no_proxy: '127.0.0.1',
    CA3P_REPORT_PYTHON: process.env.CA3P_REPORT_PYTHON || process.env.CASPER_DB_PYTHON
      || (existsSync(localPython) ? localPython : process.platform === 'win32' ? 'py' : 'python3') };
  let service; let worker; let reopened;
  try {
    service = createRunService({ storePath, autoStartWorker: false, importLegacy: false,
      envFile: null, env });
    const queued = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-flash',
      fixtureId: 'vul-web2-daehan', target: origin });
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
        tool: 'http_get', input: { path: '/api/admissions/partner/applications/1' } }],
      modelMetadata: { provider: 'deepseek', requestedModel: 'deepseek-flash',
        status: 'completed', usage: { prompt_tokens: 12, completion_tokens: 5 } } };
    } });
    worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 20,
      env, generalPlannerFactory, generalFetchImpl, generalRuntimeFactory: scriptedRuntime('confirmed') });
    await approvePending(worker, service, id);
    const final = await waitFor(() => { const run = service.getRun(id); return run.status === 'completed' && run; });
    assert.ifError(protocolFailure);
    assert.equal(reportRequests, 2, 'the report model is called twice for the one confirmed finding');
    assert.deepEqual(written, ['finding:h-access']);
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
    assert.ok(fetchCalls.every(call => call.origin === origin
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
    provider.closeAllConnections(); await new Promise(resolve => provider.close(resolve));
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
      generalRuntimeFactory: scriptedRuntime('not_reproduced'),
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
    await approvePending(worker, service, id);
    const final = await waitFor(() => { const run = service.getRun(id); return run.status === 'completed' && run; });
    assert.match(final.target, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(final.targetContacted, true);
    assert.equal(final.report.schemaVersion, 'general-assessment/1');
    assert.equal(final.report.findings.length, 1);
    assert.equal(final.report.findings[0].status, 'not_reproduced');
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
