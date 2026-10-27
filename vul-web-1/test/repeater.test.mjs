import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readAttackCatalogSync } from '../../casper-db/client.mjs';
import guardrailPackage from '../../guardrail/src/index.js';
import { RepeaterDeniedError, createGuardedRequest, createRuleset, loadPlan, run } from '../scripts/repeater.mjs';

const { GuardrailEvaluator } = guardrailPackage;
const OWNERS = { 1: 'admin', 2: 'admin', 3: 'bob' };

async function mockVulWeb1({ vulnerable = true } = {}) {
  const live = new Set([1, 2, 3]);
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const del = /^\/api\/posts\/(\d+)$/u.exec(url.pathname);
    if (req.method === 'DELETE' && del) {
      const id = Number(del[1]);
      const authorId = url.searchParams.get('authorId');
      const allowed = vulnerable ? authorId === OWNERS[id] : false;
      if (!allowed || !live.has(id)) {
        res.writeHead(allowed ? 404 : 403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'denied' }));
        return;
      }
      live.delete(id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, deletedId: id }));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/posts' && !url.search) {
      const posts = [...live].sort((a, b) => b - a).map(id => ({ id, title: `post ${id}`, authorId: OWNERS[id] }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ posts }));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) };
}

test('repeater confirms the IDOR case loaded from the catalog', async () => {
  const target = await mockVulWeb1();
  try {
    const report = await run({ origin: target.origin, vulnType: 'idor' });
    assert.equal(report.vulnType, 'idor');
    assert.equal(report.finding.category, 'CWE-639');
    assert.equal(report.finding.status, 'confirmed');
    assert.equal(report.provenance.catalog, 'casper-db.attack_catalog');
    assert.ok(report.provenance.patternId);
    assert.ok(report.provenance.patternRevision >= 1);
    assert.match(report.provenance.definitionSha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(report.evidence.map(item => [item.check, item.removed ?? item.status]), [
      ['control', 403], ['tamper', 200], ['verify', true],
    ]);
  } finally { await target.close(); }
});

test('a denied attack is not confirmed by a later server error', async () => {
  const statuses = [200, 403, 500];
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'broken_access_control',
    curlImpl: async () => ({ status: statuses.shift(), bodyJson: {} }) });
  assert.equal(report.finding.status, 'not_confirmed');
});

test('an unexpected attack error leaves the result inconclusive', async () => {
  const statuses = [200, 500, 500];
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'broken_access_control',
    curlImpl: async () => ({ status: statuses.shift(), bodyJson: {} }) });
  assert.equal(report.finding.status, 'inconclusive');
});

test('a failed resource lookup cannot establish that a deleted resource is absent', async () => {
  const statuses = [403, 200, 500];
  const report = await run({ origin: 'http://127.0.0.1:54321', vulnType: 'idor',
    curlImpl: async () => ({ status: statuses.shift(), bodyJson: { posts: [] } }) });
  assert.equal(report.finding.status, 'inconclusive');
  assert.equal(report.evidence[2].status, 500);
  assert.equal(report.evidence[2].removed, null);
});

test('a changed database revision is used and ambiguous applications require a selector', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'repeater-db-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const databasePath = join(directory, 'knowledge.sqlite3');
  const before = loadPlan(undefined, 'idor', { databasePath });
  const catalog = readAttackCatalogSync({ databasePath });
  const definition = structuredClone(catalog.patterns.find(item => item.definition.vulnType === 'idor').definition);
  definition.payloads[0].value += ' revised';
  const input = join(directory, 'catalog.json');
  const moduleRoot = fileURLToPath(new URL('../../casper-db/', import.meta.url));
  const python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
  const importDefinition = async () => {
    await writeFile(input, JSON.stringify({ schemaVersion: '0.1-draft', response: definition }));
    execFileSync(python, ['-m', 'casper_db', '--db', databasePath, 'attack-catalog-import', input,
      '--source-ref', 'test:repeater-db', '--apply'], { cwd: moduleRoot, windowsHide: true,
      env: { ...process.env, PYTHONPATH: join(moduleRoot, 'src'), PYTHONUTF8: '1' } });
  };
  await importDefinition();
  const after = loadPlan(undefined, 'idor', { databasePath });
  assert.equal(after.provenance.patternId, before.provenance.patternId);
  assert.ok(after.provenance.patternRevision > before.provenance.patternRevision);
  assert.notEqual(after.provenance.definitionSha256, before.provenance.definitionSha256);
  definition.target.application = 'other-lab';
  await importDefinition();
  assert.throws(() => loadPlan(undefined, 'idor', { databasePath }), /Ambiguous attack definition/);
  const selected = loadPlan(undefined, 'idor', { databasePath, application: 'vul-web-1' });
  assert.equal(selected.provenance.patternId, after.provenance.patternId);
});

test('a server that does not trust the parameter is not confirmed', async () => {
  const target = await mockVulWeb1({ vulnerable: false });
  try {
    const report = await run({ origin: target.origin, vulnType: 'idor' });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.evidence[1].status, 403);
  } finally { await target.close(); }
});

test('the plan is read from the catalog, not hardcoded', () => {
  const plan = loadPlan(undefined, 'idor');
  assert.equal(plan.vulnType, 'idor');
  assert.equal(plan.parameter, 'authorId');
  assert.equal(plan.stages.control.actor, 'alice');
  assert.equal(plan.stages.control.expectStatus, 403);
  assert.equal(plan.stages.tamper.actor, 'admin');
  assert.equal(plan.stages.tamper.expectStatus, 200);
});

test('a vuln type with no request-tampering case is rejected', () => {
  assert.throws(() => loadPlan(undefined, 'stored_xss'), /request-tampering/);
});

test('guardrail fails closed on budget, origin change, and reused stage', async () => {
  const origin = 'http://127.0.0.1:54321';
  const plan = loadPlan(undefined, 'idor');
  const evaluator = new GuardrailEvaluator(createRuleset({ origin, plan }));
  const base = {
    stage: 'tamper',
    action: { operation: 'http_request', session: 'attacker', method: plan.stages.tamper.method, path: plan.stages.tamper.path },
    trustedContext: {
      targetMode: 'isolated_local_lab', targetOrigin: origin, testProfile: 'request_tamper_repeater',
      runId: 'test-run', iteration: 1, networkPolicy: { externalRequests: 'DENY' },
      budget: { requestCount: 0, mutationCount: 2, deleteCount: 2, xssSubmissionCount: 0 },
    },
  };
  assert.equal(evaluator.evaluate(base).ruleId, 'REQUEST-BUDGET');
  const changed = { ...base, trustedContext: { ...base.trustedContext, targetOrigin: 'http://127.0.0.1:54322', budget: { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 } } };
  assert.equal(evaluator.evaluate(changed).ruleId, 'SCOPE-ORIGIN');
  const request = createGuardedRequest({ origin, runId: 'reuse-run', plan, curlImpl: async () => ({ status: 200, bodyJson: {} }) });
  await request('control');
  await assert.rejects(request('control'), error => error instanceof RepeaterDeniedError && error.ruleId === 'STAGE-UNAVAILABLE');
});

async function mockVulWeb2Admin({ vulnerable = true } = {}) {
  let featured = true;
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/') {
      if (featured) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('home'); }
      else { res.writeHead(500, { 'Content-Type': 'text/html' }); res.end('error'); }
      return;
    }
    if (req.method === 'POST' && url.pathname === '/admin/posts/1/delete') {
      if (vulnerable) { featured = false; res.writeHead(302, { Location: '/admin' }); res.end(); }
      else { res.writeHead(302, { Location: '/login' }); res.end(); }
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())) };
}

test('repeater confirms the unauthorized-delete chain by the home page breaking (A01 + A10)', async () => {
  const target = await mockVulWeb2Admin();
  try {
    const report = await run({ origin: target.origin, vulnType: 'broken_access_control' });
    assert.equal(report.finding.category, 'CWE-862');
    assert.equal(report.finding.status, 'confirmed');
    assert.deepEqual(report.evidence.map(item => [item.check, item.status]), [
      ['control', 200], ['tamper', 302], ['verify', 500],
    ]);
  } finally { await target.close(); }
});

test('a server that blocks the unauthenticated delete keeps the home page up and is not confirmed', async () => {
  const target = await mockVulWeb2Admin({ vulnerable: false });
  try {
    const report = await run({ origin: target.origin, vulnType: 'broken_access_control' });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.evidence[2].status, 200);
  } finally { await target.close(); }
});
