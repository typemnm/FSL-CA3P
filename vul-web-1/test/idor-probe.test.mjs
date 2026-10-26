import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import guardrailPackage from '../../guardrail/src/index.js';
import {
  ProbeDeniedError, createGuardedRequest, createIdorRuleset, loadIdorPlan, probe,
} from '../scripts/idor-probe.mjs';

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
      const posts = [...live].sort((a, b) => b - a)
        .map(id => ({ id, title: `post ${id}`, authorId: OWNERS[id] }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ posts }));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((done, fail) => server.close(error => error ? fail(error) : done())),
  };
}

test('probe confirms the delete IDOR using real guardrail and curl', async () => {
  const target = await mockVulWeb1();
  try {
    const report = await probe({ origin: target.origin });
    assert.equal(report.finding.category, 'CWE-639');
    assert.equal(report.finding.status, 'confirmed');
    assert.equal(report.targetContacted, true);
    assert.deepEqual(report.evidence.map(item => [item.check, item.status ?? item.removed]), [
      ['control', 403],
      ['tamper', 200],
      ['verify', true],
    ]);
    assert.equal(report.evidence[0].authorId, 'alice');
    assert.equal(report.evidence[1].authorId, 'admin');
  } finally {
    await target.close();
  }
});

test('a server that does not trust the parameter is not reported as confirmed', async () => {
  const target = await mockVulWeb1({ vulnerable: false });
  try {
    const report = await probe({ origin: target.origin });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.evidence[1].status, 403);
  } finally {
    await target.close();
  }
});

test('the attack plan is read from the pentest-db catalog, not hardcoded', () => {
  const plan = loadIdorPlan();
  assert.equal(plan.cwe, 'CWE-639');
  assert.equal(plan.parameter, 'authorId');
  assert.equal(plan.stages.control.actor, 'alice');
  assert.equal(plan.stages.control.expectStatus, 403);
  assert.equal(plan.stages.tamper.actor, 'admin');
  assert.equal(plan.stages.tamper.expectStatus, 200);
});

test('guardrail fails closed on origin change, exhausted budget, and reused stage', async () => {
  const origin = 'http://127.0.0.1:54321';
  const plan = loadIdorPlan();
  const evaluator = new GuardrailEvaluator(createIdorRuleset({ origin, plan }));
  const base = {
    stage: 'tamper',
    action: { operation: 'http_request', session: 'attacker', method: plan.stages.tamper.method, path: plan.stages.tamper.path },
    trustedContext: {
      targetMode: 'isolated_local_lab', targetOrigin: origin,
      testProfile: 'client_controlled_delete_idor', runId: 'test-run', iteration: 1,
      networkPolicy: { externalRequests: 'DENY' },
      budget: { requestCount: 0, mutationCount: 2, deleteCount: 2, xssSubmissionCount: 0 },
    },
  };
  assert.equal(evaluator.evaluate(base).ruleId, 'REQUEST-BUDGET');
  const changed = { ...base, trustedContext: { ...base.trustedContext,
    targetOrigin: 'http://127.0.0.1:54322', budget: { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 } } };
  assert.equal(evaluator.evaluate(changed).ruleId, 'SCOPE-ORIGIN');

  const request = createGuardedRequest({ origin, runId: 'reuse-run', plan, curlImpl: async () => ({ status: 200, bodyJson: {} }) });
  await request('control');
  await assert.rejects(request('control'), error => error instanceof ProbeDeniedError && error.ruleId === 'STAGE-UNAVAILABLE');
});
