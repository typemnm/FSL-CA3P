import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';
import { createTemplateCatalog } from '../../../attack-tool/template-catalog.mjs';

const sample = JSON.parse(await readFile(new URL('../../../attack-tool/templates/sqli-like-tautology.json', import.meta.url), 'utf8'));
const template = id => ({ ...structuredClone(sample), templateId: id, title: `Template ${id}` });

async function setup(t, { authenticate = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-template-api-'));
  const filePath = join(directory, 'templates.json');
  const catalog = createTemplateCatalog({ filePath });
  const auth = createAuthentication({ enabled: authenticate,
    ...(authenticate ? { users: ['admin', 'operator', 'viewer'].map(role => hashAccount(role, 'password', role)) } : {}) });
  const server = createDashboardServer({
    runtime: { close: async () => {}, subscribe: () => () => {}, getState: () => ({}) }, auth,
    templateCatalog: catalog, dbManagement: {}, maintenanceCheck: async () => false,
    platformProvider: async () => ({ modules: [] }),
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (path = '', { method = 'GET', body, headers = {} } = {}) => fetch(`${base}/api/attack-templates${path}`, {
    method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  async function login(role) {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: role, password: 'password' }) });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': (await response.json()).csrfToken };
  }
  return { catalog, filePath, base, request, login };
}

test('template API supports validated bulk import, editing, stale revision rejection and persistent deletion', async t => {
  const { request, filePath } = await setup(t);
  const first = template('custom-sql-a'), second = template('custom-sql-b');
  first.payloads = ['Authorization: attack-sample', '<script>alert(1)</script>'];
  const preview = await request('', { method: 'POST', body: { templates: [first, second], dryRun: true } });
  assert.equal(preview.status, 200);
  assert.equal((await preview.json()).created, 2);
  assert.equal(createTemplateCatalog({ filePath }).get(first.templateId), null);
  const imported = await request('', { method: 'POST', body: [first, second] });
  assert.equal(imported.status, 201);
  assert.equal((await imported.json()).created, 2);
  const duplicate = await request('', { method: 'POST', body: first });
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).unchanged, 1);

  const filtered = await (await request('?q=custom-sql&attackType=CWE-89&runtime=node')).json();
  assert.equal(filtered.total, 2);
  assert.equal(filtered.executionSupport[first.templateId].supported, true);
  assert.match(filtered.revisions[first.templateId], /^[a-f0-9]{64}$/);
  const before = await (await request('/custom-sql-a')).json();
  assert.deepEqual(before.template.payloads, first.payloads);
  const changed = { ...first, description: '사람이 수정한 템플릿' };
  const updated = await request('/custom-sql-a', { method: 'PUT', body: { template: changed, expectedRevision: before.revision } });
  assert.equal(updated.status, 200);
  const after = await updated.json();
  assert.equal(after.template.description, changed.description);
  assert.notEqual(after.revision, before.revision);
  assert.equal(createTemplateCatalog({ filePath }).get(first.templateId).description, changed.description);
  assert.equal((await request('/custom-sql-a', { method: 'PUT', body: { template: first, expectedRevision: before.revision } })).status, 409);
  assert.equal((await request('/custom-sql-a', { method: 'DELETE', body: { expectedRevision: before.revision } })).status, 409);
  assert.equal((await request('/custom-sql-a', { method: 'DELETE', body: { expectedRevision: after.revision } })).status, 200);
  assert.equal((await request('/custom-sql-a')).status, 404);
  assert.equal(createTemplateCatalog({ filePath }).get(first.templateId), null);

  // Builtins use the same UI operations and survive a fresh catalog instance.
  const builtin = await (await request('/sqli-like-tautology')).json();
  const editedBuiltin = await request('/sqli-like-tautology', { method: 'PUT', body: {
    template: { ...builtin.template, description: '기본 템플릿 편집' }, expectedRevision: builtin.revision,
  } });
  assert.equal(editedBuiltin.status, 200);
  const builtinRevision = (await editedBuiltin.json()).revision;
  assert.equal((await request('/sqli-like-tautology', { method: 'DELETE', body: { expectedRevision: builtinRevision } })).status, 200);
  assert.equal(createTemplateCatalog({ filePath }).list().some(item => item.templateId === sample.templateId), false);
});

test('template API denies non-admin mutation and requires CSRF while viewers can inspect source', async t => {
  const { request, login } = await setup(t, { authenticate: true });
  assert.equal((await request()).status, 401);
  const viewer = await login('viewer'), operator = await login('operator'), admin = await login('admin');
  const detail = await request('/sqli-like-tautology', { headers: viewer });
  assert.equal(detail.status, 200);
  const { revision } = await detail.json();
  for (const headers of [viewer, operator]) {
    for (const [path, method, body] of [
      ['', 'POST', template('denied')],
      ['/sqli-like-tautology', 'PUT', { template: sample, expectedRevision: revision }],
      ['/sqli-like-tautology', 'DELETE', { expectedRevision: revision }],
    ]) assert.equal((await request(path, { method, body, headers })).status, 403);
  }
  assert.equal((await request('', { method: 'POST', body: template('no-csrf'), headers: { Cookie: admin.Cookie } })).status, 403);
  assert.equal((await request('', { method: 'POST', body: template('cross-origin'), headers: { ...admin, Origin: 'https://foreign.example' } })).status, 403);
  assert.equal((await request('', { method: 'POST', body: template('allowed'), headers: admin })).status, 201);
});

test('template import failures never persist a partial batch and HTTP input stays bounded', async t => {
  const { request, base } = await setup(t);
  const first = template('batch-first');
  let response = await request('', { method: 'POST', body: [first, { ...template('batch-invalid'), payloads: [] }] });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).index, 1);
  assert.equal((await request('/batch-first')).status, 404);
  response = await request('', { method: 'POST', body: [first, { ...sample, payloads: ['different'] }] });
  assert.equal(response.status, 409);
  assert.equal((await request('/batch-first')).status, 404);
  assert.equal((await request('?unknown=value')).status, 400);
  assert.equal((await request('?q=a&q=b')).status, 400);
  assert.equal((await request('', { method: 'PATCH', body: {} })).status, 405);
  assert.equal((await request('/missing')).status, 404);
  response = await fetch(`${base}/api/attack-templates`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(response.status, 415);
  response = await fetch(`${base}/api/attack-templates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{invalid' });
  assert.equal(response.status, 400);
  response = await request('', { method: 'POST', body: { data: 'x'.repeat(1024 * 1024) } });
  assert.equal(response.status, 413);
});
