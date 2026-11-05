import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import guardrailPackage from '../../guardrail/src/index.js';
import { IntruderDeniedError, createGuardedRequest, createRuleset, loadIntruderPlan, run } from '../scripts/intruder.mjs';

const { GuardrailEvaluator } = guardrailPackage;

const ROWS = [
  { id: 3, type: 'news', title: '가을 축제 안내', created_at: '2026-09-01' },
  { id: 2, type: 'notice', title: '수강신청 일정', created_at: '2026-08-20' },
  { id: 1, type: 'notice', title: '장학금 공지', created_at: '2026-08-10' },
];

function isInjection(q) {
  return q.includes("'") || q.includes('--') || q === '%';
}

async function mockVulWeb2Search({ vulnerable = true } = {}) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/api/search') {
      const q = url.searchParams.get('q') ?? '';
      const results = vulnerable && isInjection(q)
        ? ROWS.slice()
        : ROWS.filter(row => q.length > 0 && row.title.includes(q));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ site: 'mock', q, results }));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) };
}

test('intruder confirms SQL injection by firing the catalog payloads and comparing result sets', async () => {
  const target = await mockVulWeb2Search();
  try {
    const report = await run({ origin: target.origin, vulnType: 'sql_injection' });
    assert.equal(report.vulnType, 'sql_injection');
    assert.equal(report.finding.category, 'CWE-89');
    assert.equal(report.finding.status, 'confirmed');
    assert.equal(report.provenance.catalog, 'casper-db.attack_catalog');
    assert.ok(report.provenance.patternId);
    assert.ok(report.provenance.patternRevision >= 1);
    assert.match(report.provenance.definitionSha256, /^[a-f0-9]{64}$/);
    assert.equal(report.evidence[0].check, 'baseline');
    assert.equal(report.evidence[0].resultCount, 0);
    assert.ok(report.finding.hits.length >= 1);
    assert.ok(report.finding.hits.includes('or-string-tautology'));
  } finally { await target.close(); }
});

test('a parameterized (patched) endpoint is not confirmed', async () => {
  const target = await mockVulWeb2Search({ vulnerable: false });
  try {
    const report = await run({ origin: target.origin, vulnType: 'sql_injection' });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.finding.hits.length, 0);
  } finally { await target.close(); }
});

test('the payload set is read from the catalog, not hardcoded', () => {
  const plan = loadIntruderPlan(undefined, 'sql_injection');
  assert.equal(plan.vulnType, 'sql_injection');
  assert.equal(plan.parameter, 'q');
  assert.equal(plan.baseline.resultCount, 0);
  assert.ok(plan.shots.length >= 4);
  assert.deepEqual(plan.shots.map(s => s.stage).sort(), [...plan.shots.map(s => s.stage)].sort());
  assert.ok(plan.shots.every(s => s.resultCountMin === 1));
});

test('a vuln type with no fuzzable httpResponse payload is rejected', () => {
  assert.throws(() => loadIntruderPlan(undefined, 'stored_xss'), /fuzzable/);
});

test('guardrail fails closed on budget, origin change, and reused stage', async () => {
  const origin = 'http://127.0.0.1:54321';
  const plan = loadIntruderPlan(undefined, 'sql_injection');
  const total = Object.keys(plan.stages).length;
  const evaluator = new GuardrailEvaluator(createRuleset({ origin, plan }));
  const base = {
    stage: 'shot_0',
    action: { operation: 'http_request', session: 'attacker', method: plan.stages.shot_0.method, path: plan.stages.shot_0.path },
    trustedContext: {
      targetMode: 'isolated_local_lab', targetOrigin: origin, testProfile: 'payload_fuzz_intruder',
      runId: 'test-run', iteration: 1, networkPolicy: { externalRequests: 'DENY' },
      budget: { requestCount: total, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 },
    },
  };
  assert.equal(evaluator.evaluate(base).ruleId, 'REQUEST-BUDGET');
  const changed = { ...base, trustedContext: { ...base.trustedContext, targetOrigin: 'http://127.0.0.1:54322', budget: { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 } } };
  assert.equal(evaluator.evaluate(changed).ruleId, 'SCOPE-ORIGIN');
  const request = createGuardedRequest({ origin, runId: 'reuse-run', plan, curlImpl: async () => ({ status: 200, bodyJson: { results: [] } }) });
  await request('baseline');
  await assert.rejects(request('baseline'), error => error instanceof IntruderDeniedError && error.ruleId === 'STAGE-UNAVAILABLE');
});

async function mockVulWeb2Config({ leaking = true } = {}) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/api/search') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ site: 'mock', q: url.searchParams.get('q') ?? '', results: [] }));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/_diag/config') {
      if (!leaking) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ mode: 'development', database: '/data/daehan.sqlite', installedPackages: ['lodash@4.17.15'], activeSessions: 1 }));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) };
}

test('intruder confirms A02 info disclosure when /_diag/config returns sensitive fields', async () => {
  const target = await mockVulWeb2Config();
  try {
    const report = await run({ origin: target.origin, vulnType: 'info_disclosure' });
    assert.equal(report.finding.category, 'CWE-200');
    assert.equal(report.finding.status, 'confirmed');
    assert.ok(report.finding.hits.includes('diag-config-exposure'));
  } finally { await target.close(); }
});

test('an endpoint that does not expose the config is not confirmed', async () => {
  const target = await mockVulWeb2Config({ leaking: false });
  try {
    const report = await run({ origin: target.origin, vulnType: 'info_disclosure' });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.finding.hits.length, 0);
  } finally { await target.close(); }
});

test('a server-error baseline cannot produce confirmed hits', async () => {
  let calls = 0;
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'sql_injection',
    curlImpl: async () => ({ status: calls++ === 0 ? 500 : 200,
      bodyJson: { results: calls === 1 ? [] : ROWS } }) });
  assert.equal(report.finding.status, 'inconclusive');
  assert.deepEqual(report.finding.hits, []);
});

test('server-error payload responses cannot be confirmed by result counts', async () => {
  let calls = 0;
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'sql_injection',
    curlImpl: async () => ({ status: calls++ === 0 ? 200 : 500,
      bodyJson: { results: calls === 1 ? [] : ROWS } }) });
  assert.equal(report.finding.status, 'inconclusive');
  assert.deepEqual(report.finding.hits, []);
  assert.ok(report.evidence.slice(1).every(item => item.inconclusive));
});

test('missing response structure leaves payload results inconclusive', async () => {
  let calls = 0;
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'sql_injection',
    curlImpl: async () => ({ status: 200, bodyJson: calls++ === 0 ? { results: [] } : {} }) });
  assert.equal(report.finding.status, 'inconclusive');
  assert.deepEqual(report.finding.hits, []);
});

test('sensitive fields in a forbidden response do not count as an exposure hit', async () => {
  let calls = 0;
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'info_disclosure',
    curlImpl: async () => calls++ === 0 ? { status: 200, bodyJson: { results: [] } }
      : { status: 403, bodyJson: { database: 'sample', installedPackages: [], activeSessions: 1 } } });
  assert.equal(report.finding.status, 'not_confirmed');
  assert.deepEqual(report.finding.hits, []);
});

test('empty or missing success criteria are rejected before requests', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'intruder-criteria-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const catalogPath = join(directory, 'catalog.json');
  for (const criteria of [{}, { containsFields: [] }, { status: '200' }]) {
    const request = { method: 'GET', path: '/api/search' };
    await writeFile(catalogPath, JSON.stringify({ response: { vulnType: 'sql_injection',
      target: { application: 'test' }, payloads: [{ payloadId: 'test', value: 'sample',
        injectionPoint: { parameter: 'q' }, successCheck: { expect: { observe: 'httpResponse',
          baseline: { request, resultCount: 0 }, attack: { request, ...criteria } } } }] } }));
    assert.throws(() => loadIntruderPlan(catalogPath), /supported response criteria/);
  }
});
