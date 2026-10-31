import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createTemplateCatalog, validateTemplate } from '../template-catalog.mjs';
import { renderTemplate, templateExecutionSupport, verifyTemplate } from '../templates.mjs';

const directory = new URL('../templates/', import.meta.url);
const builtins = await Promise.all((await readdir(directory)).filter(file => file.endsWith('.json')).map(async file =>
  JSON.parse(await readFile(new URL(file, directory), 'utf8'))));
const byId = new Map(builtins.map(template => [template.templateId, template]));
const requestedIds = ['search-sqli-template', 'access-control-idor-template',
  'json5-inherited-filter-template', 'unauth-featured-post-delete-template',
  'student-request-idor-template', 'wonchang-staff-idor-template',
  'diag-config-disclosure-template', 'snakeyaml-type-tag-template'];
const executableIds = ['search-sqli-template', 'sqli-like-tautology', 'json5-inherited-filter-template',
  'access-control-idor-template', 'wonchang-staff-idor-template', 'student-request-idor-template',
  'unauth-featured-post-delete-template', 'diag-config-disclosure-template', 'snakeyaml-type-tag-template'];
const referenceIds = ['lodash-prototype-canary-template', 'commons-text-interpolation-template'];

test('builtins contain unique requested and dependency templates that pass the storage contract', () => {
  assert.equal(byId.size, builtins.length);
  for (const id of [...requestedIds, ...referenceIds]) assert.ok(byId.has(id), id);
  for (const template of builtins) {
    assert.deepEqual(validateTemplate(template), template);
    assert.equal(template.trust, 'unverified');
    assert.equal(template.executor, 'guardrail');
  }
});

test('the requested search template renders its payload and distinguishes negative and positive evidence', () => {
  const template = byId.get('search-sqli-template');
  const catalog = { get: id => byId.get(id) };
  const rendered = renderTemplate({ templateId: template.templateId, payload: template.payloads[0] }, catalog);
  assert.deepEqual(rendered.baseline, { method: 'GET', path: '/api/search', query: { q: 'zzqnomatch' } });
  assert.deepEqual(rendered.packet, { method: 'GET', path: '/api/search', query: { q: "' OR '1'='1" } });
  const response = rows => ({ status: 200, json: { results: rows } });
  assert.equal(verifyTemplate(response([]), response([{ id: 1 }]), template).status, 'confirmed');
  assert.equal(verifyTemplate(response([]), response([]), template).status, 'not_reproduced');
  assert.equal(verifyTemplate({ status: 403 }, response([{ id: 1 }]), template).status, 'inconclusive');
});

test('session and custom-verifier templates remain references and cannot be silently executed', () => {
  const catalog = { get: id => byId.get(id) };
  for (const id of referenceIds) {
    const template = byId.get(id), support = templateExecutionSupport(template);
    assert.equal(support.supported, false, id);
    assert.ok(support.reason, id);
    assert.throws(() => renderTemplate({ templateId: id, payload: template.payloads[0] }, catalog),
      { code: 'UNSUPPORTED_TEMPLATE' });
  }
  assert.equal(byId.get('access-control-idor-template').verify.mode, 'ownershipComparison');
  assert.equal(byId.get('access-control-idor-template').request.packet.headers, undefined);
});

test('the shared catalog exposes the added dependency templates through exact filters', () => {
  const catalog = createTemplateCatalog({ filePath: fileURLToPath(new URL('./absent-builtin-catalog.json', import.meta.url)) });
  assert.deepEqual(catalog.list({ library: 'json5' }).map(item => item.templateId), ['json5-inherited-filter-template']);
  assert.deepEqual(catalog.list({ library: 'lodash' }).map(item => item.templateId), ['lodash-prototype-canary-template']);
  assert.deepEqual(catalog.list({ runtime: 'java' }).map(item => item.templateId).sort(),
    ['commons-text-interpolation-template', 'snakeyaml-type-tag-template', 'wonchang-staff-idor-template'].sort());
});

test('HTTP-observable catalog templates execute and lodash/commons-text stay references', () => {
  const catalog = { get: id => byId.get(id) };
  for (const id of executableIds) {
    const template = byId.get(id), support = templateExecutionSupport(template);
    assert.equal(support.supported, true, id);
    const rendered = renderTemplate({ templateId: id, payload: template.payloads[0] }, catalog);
    assert.equal(rendered.packet.method, template.request.packet.method);
    assert.equal(Boolean(rendered.followUp), template.verify.mode === 'statusSequence');
  }
  for (const id of referenceIds) {
    assert.equal(templateExecutionSupport(byId.get(id)).supported, false, id);
  }
});

test('JSON5 inherited filters confirm only when the attack result count and type marker match', () => {
  const template = byId.get('json5-inherited-filter-template');
  const catalog = { get: id => byId.get(id) };
  const rendered = renderTemplate({ templateId: template.templateId, payload: template.payloads[0] }, catalog);
  assert.deepEqual(rendered.baseline, { method: 'GET', path: '/api/search', query: { filters: '{}' } });
  assert.deepEqual(rendered.packet, { method: 'GET', path: '/api/search',
    query: { filters: '{__proto__:{type:"notice",limit:1}}' } });
  const rows = results => ({ status: 200, json: { results } });
  assert.equal(verifyTemplate(rows([{ type: 'news' }, { type: 'notice' }]),
    rows([{ type: 'notice' }]), template).status, 'confirmed');
  assert.equal(verifyTemplate(rows([{ type: 'news' }]), rows([{ type: 'news' }]), template).status, 'not_reproduced');
  assert.equal(verifyTemplate(rows([{ type: 'news' }]), { status: 500, body: 'err' }, template).status, 'inconclusive');
});

test('IDOR ownership comparison confirms distinct owner markers on both 200 responses', () => {
  const cases = [
    ['access-control-idor-template', '/api/admissions/partner/applications/1',
      '/api/admissions/partner/applications/3', '"partner_user_id":4', '"partner_user_id":5'],
    ['wonchang-staff-idor-template', '/api/staff/mobile/cases/1',
      '/api/staff/mobile/cases/3', '"staff_user_id":4', '"staff_user_id":5'],
    ['student-request-idor-template', '/api/mypage/requests/1',
      '/api/mypage/requests/2', '"user_id":2', '"user_id":3'],
  ];
  const catalog = { get: id => byId.get(id) };
  for (const [id, baselinePath, attackPath, own, other] of cases) {
    const template = byId.get(id);
    const rendered = renderTemplate({ templateId: id, payload: template.payloads[0] }, catalog);
    assert.deepEqual(rendered.baseline, { method: 'GET', path: baselinePath });
    assert.deepEqual(rendered.packet, { method: 'GET', path: attackPath });
    const body = text => ({ status: 200, body: text });
    assert.equal(verifyTemplate(body(`{${own}}`), body(`{${other}}`), template).status, 'confirmed', id);
    assert.equal(verifyTemplate(body(`{${own}}`), body(`{${own}}`), template).status, 'not_reproduced', id);
    assert.equal(verifyTemplate({ status: 302, body: '' }, body(`{${other}}`), template).status, 'inconclusive', id);
  }
});

test('unauthenticated featured delete confirms POST 302 then follow-up GET 500', () => {
  const template = byId.get('unauth-featured-post-delete-template');
  const catalog = { get: id => byId.get(id) };
  const rendered = renderTemplate({ templateId: template.templateId, payload: '1' }, catalog);
  assert.deepEqual(rendered.baseline, { method: 'GET', path: '/' });
  assert.deepEqual(rendered.packet, { method: 'POST', path: '/admin/posts/1/delete' });
  assert.deepEqual(rendered.followUp, { method: 'GET', path: '/' });
  assert.equal(verifyTemplate({ status: 200 }, { status: 302 }, template, { status: 500 }).status, 'confirmed');
  assert.equal(verifyTemplate({ status: 200 }, { status: 403 }, template, { status: 200 }).status, 'not_reproduced');
  assert.equal(verifyTemplate({ status: 500 }, { status: 302 }, template, { status: 500 }).status, 'inconclusive');
  assert.equal(verifyTemplate({ status: 200 }, { status: 302 }, template).status, 'inconclusive');
});

test('diag config disclosure confirms the public JSON field set', () => {
  const template = byId.get('diag-config-disclosure-template');
  const catalog = { get: id => byId.get(id) };
  const rendered = renderTemplate({ templateId: template.templateId, payload: template.payloads[0] }, catalog);
  assert.deepEqual(rendered.baseline, { method: 'GET', path: '/' });
  assert.deepEqual(rendered.packet, { method: 'GET', path: '/_diag/config' });
  assert.equal(verifyTemplate({ status: 200 }, { status: 200, json: {
    database: 'x', installedPackages: [], activeSessions: 1 } }, template).status, 'confirmed');
  assert.equal(verifyTemplate({ status: 200 }, { status: 200, json: { database: 'x' } }, template).status, 'not_reproduced');
  assert.equal(verifyTemplate({ status: 200 }, { status: 404, json: {} }, template).status, 'inconclusive');
});

test('SnakeYAML tag acceptance confirms baseline and canary markers without treating RCE as found', () => {
  const template = byId.get('snakeyaml-type-tag-template');
  const catalog = { get: id => byId.get(id) };
  const rendered = renderTemplate({ templateId: template.templateId, payload: template.payloads[0] }, catalog);
  assert.equal(rendered.packet.method, 'POST');
  assert.equal(rendered.packet.path, '/admin/schedule/preview');
  assert.equal(rendered.packet.body.payload, '!!java.util.ArrayList [CA3P_SNAKEYAML_CANARY]');
  assert.equal(rendered.baseline.body.payload, 'events: [{title: CA3P_SNAKEYAML_BASELINE}]');
  assert.equal(verifyTemplate({ status: 200, body: 'CA3P_SNAKEYAML_BASELINE' },
    { status: 200, body: '[CA3P_SNAKEYAML_CANARY]' }, template).status, 'confirmed');
  assert.equal(verifyTemplate({ status: 200, body: 'CA3P_SNAKEYAML_BASELINE' },
    { status: 200, body: 'plain text' }, template).status, 'not_reproduced');
});
