import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createAttackTool } from '../server.mjs';
import { createAttackToolClient } from '../client.mjs';
import { projectTemplateResponse, TEMPLATE_EXCERPT_BYTES } from '../templates.mjs';
import guardrailPackage from '../../guardrail/src/index.js';

async function templateFixture(t, { oversizedAttack = false } = {}) {
  const sourceBodies = [];
  const target = createServer((request, response) => {
    const baseline = new URL(request.url, 'http://fixture').searchParams.get('q') === 'zzqnomatch';
    const body = JSON.stringify({ results: baseline ? [] : [{ name: 'one' }, { name: 'two' }],
      detail: '가'.repeat(oversizedAttack && !baseline ? 30_000 : 16_000),
      escaped: '\u0001'.repeat(1000) });
    sourceBodies.push(body);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body);
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise(resolve => target.close(resolve)));
  const guardrail = guardrailPackage.createAttackToolGuardrail({
    targetOrigin: 'http://127.0.0.1:' + target.address().port,
  });
  const daemon = await createAttackTool();
  t.after(() => daemon.close());
  const credentials = daemon.registerPrincipal({ agentId: 'large-result-agent', runId: 'large-result-run', guardrail });
  const client = createAttackToolClient({ ...credentials, endpoint: daemon.endpoints[credentials.portIndex] });
  return { sourceBodies, client };
}

test('large baseline and attack JSON retain full verification while RPC evidence stays bounded', async t => {
  const { client, sourceBodies } = await templateFixture(t);
  const result = await client.call('execute_attack_template', {
    templateId: 'sqli-like-tautology', payload: "' OR '1'='1",
  });
  assert.ok(sourceBodies.every(body => Buffer.byteLength(body) < 64 * 1024));
  const oldResult = { baseline: { body: sourceBodies[0], json: JSON.parse(sourceBodies[0]) },
    attack: { body: sourceBodies[1], json: JSON.parse(sourceBodies[1]) } };
  assert.ok(Buffer.byteLength(JSON.stringify(oldResult)) > 128 * 1024,
    'complete body/json pairs would overflow the daemon response limit');
  assert.deepEqual(result.verification, { status: 'confirmed', baselineCount: 0, attackCount: 2 });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 64 * 1024);
  for (const response of [result.baseline, result.attack]) {
    assert.equal(response.status, 200);
    assert.equal(response.headers['content-type'], 'application/json');
    assert.equal(response.truncated, false, 'verification source was complete');
    assert.equal(response.excerptTruncated, true, 'only model-facing evidence was shortened');
    assert.ok(Buffer.byteLength(response.bodyExcerpt) <= TEMPLATE_EXCERPT_BYTES);
    assert.ok(response.bodyBytes > TEMPLATE_EXCERPT_BYTES);
    assert.doesNotMatch(response.bodyExcerpt, /\uFFFD/u);
    assert.equal(Object.hasOwn(response, 'json'), false);
    assert.equal(Object.hasOwn(response, 'body'), false);
  }
  assert.match(result.attack.bodyExcerpt, /"name":"two"/u);
});

test('source truncation remains distinct from excerpt truncation and prevents a confirmed result', async t => {
  const { client } = await templateFixture(t, { oversizedAttack: true });
  const result = await client.call('execute_attack_template', {
    templateId: 'sqli-like-tautology', payload: "' OR '1'='1",
  });
  assert.equal(result.baseline.truncated, false);
  assert.equal(result.baseline.excerptTruncated, true);
  assert.equal(result.attack.truncated, true);
  assert.equal(result.attack.excerptTruncated, true);
  assert.equal(result.verification.status, 'inconclusive');
  assert.equal(result.verification.attackCount, null);
});

test('JSON escaping of response excerpts cannot expand template evidence beyond its RPC budget', () => {
  const source = { status: 200, body: '\u0000'.repeat(64 * 1024), truncated: false };
  const projected = projectTemplateResponse(source);
  assert.equal(Buffer.byteLength(projected.bodyExcerpt), TEMPLATE_EXCERPT_BYTES);
  assert.equal(projected.excerptTruncated, true);
  assert.ok(Buffer.byteLength(JSON.stringify({ baseline: projected, attack: projected })) < 64 * 1024);
});
