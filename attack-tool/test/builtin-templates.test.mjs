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
const requestedIds = ['search-sqli-template', 'access-control-idor-template'];
const referenceIds = ['access-control-idor-template', 'json5-inherited-filter-template',
  'lodash-prototype-canary-template', 'commons-text-interpolation-template', 'snakeyaml-type-tag-template'];

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
  assert.deepEqual(catalog.list({ runtime: 'java' }).map(item => item.templateId),
    ['commons-text-interpolation-template', 'snakeyaml-type-tag-template']);
});
