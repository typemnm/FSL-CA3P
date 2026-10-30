import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { createAttackTool } from '../server.mjs';
import { createAttackToolClient } from '../client.mjs';
import { listTemplates } from '../templates.mjs';
import guardrailPackage from '../../guardrail/src/index.js';
import { createAttackToolBridge } from '../../packages/adapters/integrations/attack-tool.mjs';

async function fixture(t, safe = false) {
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE items(name TEXT); INSERT INTO items VALUES ('sample')");
  const server = createServer((request, response) => {
    const q = new URL(request.url, 'http://fixture').searchParams.get('q');
    const rows = safe ? db.prepare('SELECT * FROM items WHERE name LIKE ?').all(q)
      : db.prepare("SELECT * FROM items WHERE name LIKE '" + q + "'").all();
    response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ results: rows }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); });
  return 'http://127.0.0.1:' + server.address().port;
}
async function setup(t, extra = {}) {
  const daemon = await createAttackTool(extra);
  t.after(() => daemon.close());
  return daemon;
}
function addClient(daemon, extra = {}) {
  const credentials = daemon.registerPrincipal({ agentId: 'agent-a', runId: 'run-a', ...extra });
  return createAttackToolClient({ ...credentials, endpoint: daemon.endpoints[credentials.portIndex] });
}

test('two ports and two agents preserve request/response identity under concurrency', async t => {
  const daemon = await setup(t);
  const a = addClient(daemon, { execute: async input => ({ value: input.probe.id }), authorize: async () => ({ allowed: true }) });
  const b = addClient(daemon, { agentId: 'agent-b', runId: 'run-b', portIndex: 1,
    execute: async input => ({ value: input.probe.id }), authorize: async () => ({ allowed: true }) });
  assert.notEqual(daemon.endpoints[0], daemon.endpoints[1]);
  assert.equal((await a.initialize()).runId, 'run-a');
  assert.equal((await b.initialize()).agentId, 'agent-b');
  const values = await Promise.all(Array.from({ length: 20 }, (_, id) => (id % 2 ? b : a).call('execute_probe', { probe: { id }, hypothesis: {} })));
  assert.deepEqual(values.map(value => value.value), Array.from({ length: 20 }, (_, id) => id));
});

for (const safe of [false, true]) test('real SQL template packets pass guardrail and compare baseline: safe=' + safe, async t => {
  const targetOrigin = await fixture(t, safe);
  const guardrail = guardrailPackage.createAttackToolGuardrail({ targetOrigin });
  const daemon = await setup(t);
  const client = addClient(daemon, { guardrail });
  assert.equal((await client.listTools()).tools.length, 2);
  const { templates } = await client.call('list_attack_templates', { attackType: 'CWE-89', runtime: 'node' });
  assert.deepEqual(templates, listTemplates({ attackType: 'CWE-89', runtime: 'node' }));
  const original = templates.find(template => template.templateId === 'sqli-like-tautology');
  assert.ok(original);
  const result = await client.call('execute_attack_template', { templateId: original.templateId, payload: original.payloads[0] });
  assert.equal(result.verification.status, safe ? 'not_reproduced' : 'confirmed');
  assert.equal(guardrail.audit().length, 2);
  assert.equal(guardrail.metrics().requestCount, 2);
});

test('denied capability never reaches executor; AI cannot replace target or run authority', async t => {
  let calls = 0;
  const daemon = await setup(t);
  const client = addClient(daemon, { authorize: async () => ({ allowed: false }), execute: async () => { calls += 1; } });
  await assert.rejects(client.call('execute_probe', { probe: {}, hypothesis: {} }), { code: 'GUARDRAIL_DENIED' });
  await assert.rejects(client.call('execute_probe', { probe: {}, hypothesis: {}, runId: 'other' }), { code: 'INVALID_ARGUMENTS' });
  await assert.rejects(client.call('execute_attack_template', { templateId: 'sqli-like-tautology', payload: 'x', origin: 'http://other' }), { code: 'CAPABILITY_UNAVAILABLE' });
  assert.equal(calls, 0);
  assert.equal(daemon.metrics().denied, 1);
});

test('bearer principals are bound to one listener; unauthenticated callers cannot invoke tools', async t => {
  const daemon = await setup(t);
  const identity = daemon.registerPrincipal({ agentId: 'a', runId: 'r', portIndex: 0 });
  const wrongPort = createAttackToolClient({ ...identity, endpoint: daemon.endpoints[1] });
  await assert.rejects(wrongPort.initialize(), { code: 'ATTACK_TOOL_HTTP_ERROR' });
  const response = await fetch(daemon.endpoints[0] + '/rpc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(response.status, 401);
});

test('timeout cancels host operation and serialized queued work never starts after cancellation', async t => {
  let aborted = false;
  const daemon = await setup(t, { timeoutMs: 100 });
  const client = addClient(daemon, { authorize: async () => ({ allowed: true }), execute: async (_, { signal }) => new Promise(resolve => {
    signal.addEventListener('abort', () => { aborted = true; resolve({ cancelled: true }); }, { once: true });
  }) });
  await assert.rejects(client.call('execute_probe', { probe: {}, hypothesis: {} }), { code: 'REQUEST_TIMEOUT' });
  assert.equal(aborted, true);
});

test('slow request body times out without running a capability', async t => {
  let calls = 0;
  const daemon = await setup(t, { timeoutMs: 100 });
  const credentials = daemon.registerPrincipal({ agentId: 'slow', runId: 'r', authorize: async () => ({ allowed: true }), execute: async () => { calls += 1; } });
  const response = await new Promise((resolve, reject) => {
    const request = httpRequest(daemon.endpoints[0] + '/rpc', { method: 'POST', headers: {
      'content-type': 'application/json', authorization: 'Bearer ' + credentials.token, 'content-length': '1000',
    } }, response => { const parts = []; response.on('data', part => parts.push(part)); response.on('end', () => resolve(JSON.parse(Buffer.concat(parts)))); });
    request.on('error', reject); request.write('{');
    t.after(() => request.destroy());
  });
  assert.equal(response.error.code, 'REQUEST_TIMEOUT'); assert.equal(calls, 0);
});

test('bridge creates category workers and reauthorizes every request', async t => {
  let authorized = 0;
  const bridge = await createAttackToolBridge({ runId: 'run', targetOrigin: 'http://127.0.0.1:4101',
    authorize: async () => { authorized += 1; return { allowed: true }; }, execute: async ({ probe }) => ({ evidence: [{ id: probe.id }] }) });
  t.after(() => bridge.close());
  const results = await Promise.all(['sql_injection', 'xss'].map((category, id) => bridge.execute({ probe: { id }, hypothesis: { category } })));
  assert.equal(authorized, 2); assert.equal(bridge.agentIds.length, 2);
  assert.equal(results[1].evidence[0].id, 1);
  assert.equal(listTemplates({ library: 'other' }).length, 0);
  assert.deepEqual(bridge.templates, listTemplates());
});

test('invalid templates and oversized JSON never execute target requests', async t => {
  let calls = 0;
  const daemon = await setup(t);
  const client = addClient(daemon, { guardrail: { execute: async () => { calls += 1; } } });
  await assert.rejects(client.call('execute_attack_template', { templateId: 'sqli-like-tautology', payload: 'anything' }), { code: 'INVALID_TEMPLATE' });
  const original = listTemplates().find(template => template.templateId === 'sqli-like-tautology');
  await assert.rejects(client.call('execute_attack_template', { templateId: original.templateId, payload: original.payloads[0], origin: 'http://other' }), { code: 'INVALID_TEMPLATE' });
  await assert.rejects(client.call('list_attack_templates', { library: 'a'.repeat(130 * 1024) }));
  assert.equal(calls, 0);
});
