import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createAttackTool } from '../server.mjs';
import { createAttackToolClient } from '../client.mjs';
import { createAttackToolBridge } from '../../packages/adapters/integrations/attack-tool.mjs';
import { validateTemplate } from '../template-catalog.mjs';
import guardrailPackage from '../../guardrail/src/index.js';

const original = JSON.parse(readFileSync(new URL('../templates/sqli-like-tautology.json', import.meta.url), 'utf8'));

function alternate() {
  const template = structuredClone(original);
  template.templateId = 'lookup-count';
  template.target.endpoint = template.request.packet.path = '/api/lookup';
  template.payloads = ['lookup-candidate'];
  template.verify.baseline.q = 'lookup-baseline';
  template.verify.attack.expectMin = 3;
  return template;
}

function mutableCatalog(initial) {
  let values = structuredClone(initial);
  return {
    list: () => structuredClone(values),
    get: id => structuredClone(values.find(template => template.templateId === id) ?? null),
    replace(next) { values = structuredClone(next); },
  };
}

async function connect(t, catalog, guardrail) {
  const daemon = await createAttackTool({ catalog, ports: [0] });
  t.after(() => daemon.close());
  const credentials = daemon.registerPrincipal({ agentId: 'catalog-agent', runId: 'catalog-run', guardrail });
  const client = createAttackToolClient({ ...credentials, endpoint: daemon.endpoints[0] });
  return { daemon, client };
}

test('bounded tool schemas retain reference-only listings while runtime enforces template and payload pairs', async t => {
  const second = alternate();
  const reference = structuredClone(original);
  reference.templateId = 'reference-post';
  reference.target.method = reference.request.packet.method = 'POST';
  let requests = 0;
  const { client } = await connect(t, mutableCatalog([original, second, reference]), {
    execute: async () => { requests += 1; return { status: 200, json: [] }; },
  });
  const { tools } = await client.listTools();
  const schema = tools.find(tool => tool.name === 'execute_attack_template').inputSchema;
  assert.deepEqual(schema.properties, { templateId: { type: 'string', maxLength: 128 },
    payload: { type: 'string', maxLength: 4096 } });
  assert.equal(Object.hasOwn(schema, 'oneOf'), false);
  assert.equal((await client.call('list_attack_templates', {})).templates.length, 3);
  assert.equal((await client.call('list_attack_templates', { library: 'other' })).templates.length, 0);
  assert.deepEqual((await client.call('list_attack_templates', { attackType: 'CWE-89' })).templates.map(item => item.templateId),
    [original.templateId, second.templateId, reference.templateId]);
  await assert.rejects(client.call('execute_attack_template', { templateId: second.templateId, payload: original.payloads[0] }),
    { code: 'INVALID_TEMPLATE' });
  await assert.rejects(client.call('execute_attack_template', { templateId: reference.templateId, payload: reference.payloads[0] }),
    { code: 'UNSUPPORTED_TEMPLATE' });
  assert.equal(requests, 0);
});

test('template listing uses bounded numeric pagination and preserves filtered offsets', async t => {
  const values = Array.from({ length: 61 }, (_, index) => ({ ...structuredClone(original),
    templateId: `catalog-${String(index).padStart(3, '0')}` }));
  const { client } = await connect(t, mutableCatalog(values));
  const first = await client.call('list_attack_templates', {});
  assert.equal(first.total, 61);
  assert.equal(first.templates.length, 25);
  assert.equal(first.nextOffset, 25);
  const second = await client.call('list_attack_templates', { attackType: 'CWE-89', limit: 25, offset: first.nextOffset });
  const last = await client.call('list_attack_templates', { attackType: 'CWE-89', limit: 25, offset: second.nextOffset });
  assert.equal(last.nextOffset, null);
  assert.deepEqual([...first.templates, ...second.templates, ...last.templates].map(template => template.templateId),
    values.map(template => template.templateId));
  assert.deepEqual(await client.call('list_attack_templates', { runtime: 'other', offset: 1000 }),
    { templates: [], total: 0, nextOffset: null });
  for (const input of [{ limit: 0 }, { limit: 101 }, { limit: '25' }, { limit: 1.5 },
    { offset: -1 }, { offset: 1001 }, { offset: '0' }, { runtime: 1 }, { unknown: 1 }]) {
    await assert.rejects(client.call('list_attack_templates', input), { code: 'INVALID_ARGUMENTS' });
  }
});

test('large catalogs keep discovery and every template page below the RPC byte limit without lost entries', async t => {
  const values = Array.from({ length: 9 }, (_, index) => {
    const template = structuredClone(original);
    template.templateId = `large-${index}`;
    template.payloads = Array.from({ length: 10 }, (_, payloadIndex) => `${index}:${payloadIndex}:` + 'x'.repeat(4090));
    return validateTemplate(template);
  });
  assert.ok(Buffer.byteLength(JSON.stringify(values)) > 128 * 1024);
  const { client } = await connect(t, mutableCatalog(values), { execute: async () => ({ status: 200, json: [] }) });
  const capabilities = await client.listTools();
  assert.ok(Buffer.byteLength(JSON.stringify(capabilities)) < 4096);
  assert.ok(capabilities.tools.some(tool => tool.name === 'execute_attack_template'));
  const collected = [];
  let offset = 0, pages = 0;
  do {
    const page = await client.call('list_attack_templates', { limit: 100, offset });
    assert.equal(page.total, values.length);
    assert.ok(page.templates.length > 0, 'pagination must always advance');
    assert.ok(Buffer.byteLength(JSON.stringify(page)) < 128 * 1024 - 4096);
    collected.push(...page.templates.map(template => template.templateId));
    assert.ok(page.nextOffset === null || page.nextOffset > offset);
    offset = page.nextOffset;
    pages += 1;
  } while (offset !== null);
  assert.ok(pages > 1, 'the byte budget must split a large requested page');
  assert.deepEqual(collected, values.map(template => template.templateId));
  assert.equal(new Set(collected).size, values.length);
});

test('a selected second template renders its path and verification thresholds from the run snapshot', async t => {
  const second = alternate();
  const catalog = mutableCatalog([original, second]);
  const requests = [];
  const target = createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requests.push({ path: url.pathname, q: url.searchParams.get('q') });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ results: url.searchParams.get('q') === 'lookup-baseline' ? [] : [{ id: 1 }, { id: 2 }] }));
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise(resolve => target.close(resolve)));
  const targetOrigin = `http://127.0.0.1:${target.address().port}`;
  const { daemon, client } = await connect(t, catalog,
    guardrailPackage.createAttackToolGuardrail({ targetOrigin, allowedPaths: ['/api/lookup'] }));

  // An active assessment keeps the starting definition even after its live payload and success rule change.
  const changed = structuredClone(second);
  changed.request.packet.path = changed.target.endpoint = '/api/changed';
  changed.payloads = ['changed-candidate'];
  changed.verify.attack.expectMin = 1;
  catalog.replace([changed]);
  const exposed = daemon.templates;
  exposed[1].request.packet.path = '/api/tampered';
  const result = await client.call('execute_attack_template', { templateId: second.templateId, payload: second.payloads[0] });
  assert.deepEqual(requests, [{ path: '/api/lookup', q: 'lookup-baseline' }, { path: '/api/lookup', q: 'lookup-candidate' }]);
  assert.deepEqual(result.verification, { status: 'not_reproduced', baselineCount: 0, attackCount: 2 });
  assert.deepEqual((await client.call('list_attack_templates', {})).templates.map(template => template.templateId),
    [original.templateId, second.templateId]);
  await assert.rejects(client.call('execute_attack_template', { templateId: second.templateId, payload: changed.payloads[0] }),
    { code: 'INVALID_TEMPLATE' });

  catalog.replace([]);
  assert.equal((await client.call('list_attack_templates', {})).templates.length, 2);
  const next = await connect(t, catalog, { execute: async () => assert.fail('An empty catalog cannot execute') });
  assert.deepEqual((await next.client.call('list_attack_templates', {})).templates, []);
  assert.equal((await next.client.listTools()).tools.some(tool => tool.name === 'execute_attack_template'), false);
});

test('application bridge exposes the same injected catalog snapshot as its daemon', async t => {
  const second = alternate();
  const catalog = mutableCatalog([original, second]);
  const bridge = await createAttackToolBridge({ templateCatalog: catalog, runId: 'bridge-catalog',
    targetOrigin: 'http://127.0.0.1:4101', authorize: async () => ({ allowed: true }), execute: async () => ({ evidence: [] }) });
  t.after(() => bridge.close());
  catalog.replace([]);
  assert.deepEqual(bridge.templates.map(template => template.templateId), [original.templateId, second.templateId]);
  const result = await bridge.execute({ probe: { id: 'probe-a' }, hypothesis: { category: 'sql_injection' } });
  assert.deepEqual(result, { evidence: [] });
});

test('adding an executable template never extends the server configured allowed paths', async t => {
  const second = alternate();
  let requests = 0;
  const guardrail = guardrailPackage.createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101',
    allowedPaths: ['/api/search'], fetchImpl: async () => { requests += 1; assert.fail('A catalog cannot authorize its own path'); } });
  const { client } = await connect(t, mutableCatalog([original, second]), guardrail);
  await assert.rejects(client.call('execute_attack_template', { templateId: second.templateId, payload: second.payloads[0] }),
    { code: 'GUARDRAIL_DENIED' });
  assert.equal(requests, 0);
  assert.equal(guardrail.metrics().requestCount, 0);
});
