import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import guardrailPackage from '../../guardrail/src/index.js';
import {
  ProbeDeniedError, createGuardedGet, createIdorRuleset, probeSite, runConfiguredSites,
} from '../scripts/idor-probe.mjs';

const { GuardrailEvaluator } = guardrailPackage;
const sites = {
  daehan: { endpoint: '/api/admissions/partner/applications', ownerField: 'partner_user_id',
    first: 'partner1', second: 'partner2', password: 'Partner2026' },
  wonchang: { endpoint: '/api/staff/mobile/cases', ownerField: 'staff_user_id',
    first: 'staff1', second: 'staff2', password: 'Staff2026' },
};

async function mockUniversity(siteKey, { denyCross = false } = {}) {
  const site = sites[siteKey];
  const requests = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/login') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const username = form.get('username');
      const expectedPassword = username === 'student1' ? 'Welcome2026' : site.password;
      if (![site.first, site.second, 'student1'].includes(username)
        || form.get('password') !== expectedPassword) {
        res.writeHead(401); res.end(); return;
      }
      res.writeHead(302, {
        Location: '/mypage', 'Set-Cookie': `${siteKey}_sid=${username}token; HttpOnly; Path=/`,
      });
      res.end();
      return;
    }
    const match = new RegExp(`^${site.endpoint}/(1|3)$`).exec(url.pathname);
    if (req.method !== 'GET' || !match || url.search) {
      res.writeHead(404); res.end(); return;
    }
    const account = req.headers.cookie?.match(new RegExp(`${siteKey}_sid=([a-z0-9]+)token`))?.[1];
    const recordId = Number(match[1]);
    requests.push({ method: req.method, path: url.pathname, account });
    if (account === 'student1') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end('{"error":"forbidden"}');
      return;
    }
    if (![site.first, site.second].includes(account) || (denyCross && account === site.first && recordId === 3)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{"error":"not found"}');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: recordId, [site.ownerField]: recordId === 1 ? 4 : 5,
      applicant_name: 'private fixture field', contact: 'private@example.invalid' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, requests,
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}

test('both university probes use real guardrail and curl, and report only bounded evidence', async () => {
  for (const siteKey of Object.keys(sites)) {
    const target = await mockUniversity(siteKey);
    try {
      const report = await probeSite({ siteKey, origin: target.origin });
      assert.equal(report.finding.status, 'confirmed');
      assert.equal(report.targetContacted, true);
      assert.ok(report.evidence.every(item => Object.keys(item).sort().join(',')
        === 'check,ownerId,recordId,status'));
      assert.deepEqual(report.evidence.map(item => [item.check, item.recordId, item.status, item.ownerId]), [
        ['firstOwner', 1, 200, 4],
        ['secondOwner', 3, 200, 5],
        ['crossOwner', 3, 200, 5],
        ['studentRole', 3, 403, null],
      ]);
      assert.equal(target.requests.length, 4);
      assert.ok(target.requests.every(item => item.method === 'GET'
        && [1, 3].some(id => item.path === `${sites[siteKey].endpoint}/${id}`)));
      const json = JSON.stringify(report);
      for (const secret of ['sid=', 'Partner2026', 'Staff2026', 'Welcome2026',
        'private fixture field', 'private@example.invalid']) {
        assert.ok(!json.includes(secret), `${siteKey} report must omit ${secret}`);
      }
    } finally {
      await target.close();
    }
  }
});

test('blocked cross-owner access is not reported as a confirmed IDOR', async () => {
  const target = await mockUniversity('daehan', { denyCross: true });
  try {
    const report = await probeSite({ siteKey: 'daehan', origin: target.origin });
    assert.equal(report.finding.status, 'not_confirmed');
    assert.equal(report.evidence[2].status, 404);
  } finally {
    await target.close();
  }
});

test('guardrail blocks mutation, unknown path, and changed known path before curl', async () => {
  let curlCalls = 0;
  const origin = 'http://127.0.0.1:54321';
  const get = createGuardedGet({ siteKey: 'daehan', origin, runId: 'test-guardrail',
    curlImpl: async () => { curlCalls += 1; return { status: 200, bodyJson: {} }; } });
  await assert.rejects(get('firstOwner', { method: 'DELETE' }), error =>
    error instanceof ProbeDeniedError && error.ruleId === 'METHOD-READ-ONLY');
  await assert.rejects(get('firstOwner', { path: '/api/admissions/partner/applications/999' }), error =>
    error instanceof ProbeDeniedError && error.ruleId === 'ENDPOINT-ALLOWLIST');
  await assert.rejects(get('firstOwner', { path: 'http://127.0.0.1:54322/api/admissions/partner/applications/1' }), error =>
    error instanceof ProbeDeniedError && error.ruleId === 'ENDPOINT-ALLOWLIST');
  await assert.rejects(get('firstOwner', { path: '/api/admissions/partner/applications/3' }), error =>
    error instanceof ProbeDeniedError && error.ruleId === 'PROFILE-ACTION-MISMATCH');
  assert.equal(curlCalls, 0);
  await get('firstOwner', { cookie: 'sid=fixedtoken' });
  assert.equal(curlCalls, 1);
  await assert.rejects(get('firstOwner'), error =>
    error instanceof ProbeDeniedError && error.ruleId === 'STAGE-UNAVAILABLE');
  assert.equal(curlCalls, 1);
});

test('the four-request policy fails closed at its budget and on origin changes', () => {
  const origin = 'http://127.0.0.1:54321';
  const evaluator = new GuardrailEvaluator(createIdorRuleset({ siteKey: 'wonchang', origin }));
  const input = {
    stage: 'firstOwner',
    action: { operation: 'http_request', session: 'first-owner', method: 'GET',
      path: '/api/staff/mobile/cases/1' },
    trustedContext: {
      targetMode: 'isolated_local_lab', targetOrigin: origin,
      testProfile: 'known_record_idor_read', runId: 'test-budget', iteration: 1,
      networkPolicy: { externalRequests: 'DENY' },
      budget: { requestCount: 4, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 },
    },
  };
  assert.equal(evaluator.evaluate(input).ruleId, 'REQUEST-BUDGET');
  input.trustedContext.budget.requestCount = 0;
  input.trustedContext.targetOrigin = 'http://127.0.0.1:54322';
  assert.equal(evaluator.evaluate(input).ruleId, 'SCOPE-ORIGIN');
});

test('CLI selection is fixed to the two Compose loopback origins', async () => {
  const requested = [];
  const result = await runConfiguredSites({ probe: async input => {
    requested.push(input);
    return { finding: { status: 'confirmed' } };
  } });
  assert.equal(result.reports.length, 2);
  assert.deepEqual(requested, [
    { siteKey: 'daehan', origin: 'http://127.0.0.1:4101' },
    { siteKey: 'wonchang', origin: 'http://127.0.0.1:4102' },
  ]);
  await assert.rejects(runConfiguredSites({ args: ['--url', 'http://example.com'] }),
    /accepts no URL/);
});
