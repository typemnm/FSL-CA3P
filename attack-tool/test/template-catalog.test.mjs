import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { createTemplateCatalog, templateRevision, validateTemplate, templateSchema, TEMPLATE_BYTES } from '../template-catalog.mjs';
import { renderTemplate, templateExecutionSupport, verifyTemplate } from '../templates.mjs';

const original = JSON.parse(await readFile(new URL('../templates/sqli-like-tautology.json', import.meta.url), 'utf8'));
const builtinTemplates = await Promise.all((await readdir(new URL('../templates/', import.meta.url)))
  .filter(name => name.endsWith('.json')).map(async name => JSON.parse(await readFile(new URL(`../templates/${name}`, import.meta.url), 'utf8'))));
const builtinCount = builtinTemplates.length;
const example = (templateId, extra = {}) => ({ ...structuredClone(original), templateId, ...extra });
async function setup(t) {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-templates-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const filePath = join(dir, 'catalog.json');
  return { catalog: createTemplateCatalog({ filePath }), filePath, dir };
}

test('builtin JSON and strict schema have isolated public values', async t => {
  const { catalog } = await setup(t);
  assert.deepEqual(catalog.get(original.templateId), original);
  assert.equal(templateSchema.additionalProperties, false);
  const values = catalog.list(); values.find(value => value.templateId === original.templateId).payloads.push('mutated');
  assert.deepEqual(catalog.get(original.templateId).payloads, original.payloads);
});

test('single, array and wrapped imports persist; identical IDs are idempotent', async t => {
  const { catalog, filePath } = await setup(t);
  assert.equal((await catalog.import(example('one'))).created, 1);
  assert.equal((await catalog.import([example('two'), example('three')])).created, 2);
  const result = await catalog.import({ templates: [example('four'), example('one')] });
  assert.equal(result.created, 1); assert.equal(result.unchanged, 1); assert.equal(result.total, builtinCount + 4);
  assert.equal(createTemplateCatalog({ filePath }).list().length, builtinCount + 4);
  const reordered = Object.fromEntries(Object.entries(example('one')).reverse());
  assert.equal((await catalog.import(reordered)).unchanged, 1);
});

test('dry run and invalid later rows never partially commit', async t => {
  const { catalog } = await setup(t);
  const result = await catalog.import({ templates: [example('planned')], dryRun: true });
  assert.equal(result.created, 1); assert.equal(result.dryRun, true); assert.equal(result.total, builtinCount + 1);
  assert.equal(catalog.get('planned'), null);
  await assert.rejects(catalog.import([example('pending'), { ...original, description: 'conflict' }]),
    { status: 409, code: 'TEMPLATE_CONFLICT', index: 1 });
  assert.equal(catalog.get('pending'), null);
  await assert.rejects(catalog.import([example('pending'), example('invalid', { payloads: [] })]),
    { status: 400, code: 'INVALID_TEMPLATE', index: 1, field: 'template.payloads' });
  assert.equal(catalog.get('pending'), null);
  await assert.rejects(catalog.import([example('same'), example('same', { title: 'Different' })]), { status: 409 });
  assert.equal(catalog.get('same'), null);
});

test('builtin and custom updates require current revisions and preserve IDs', async t => {
  const { catalog, filePath } = await setup(t);
  const changed = { ...original, title: 'Updated builtin' }, oldRevision = templateRevision(original);
  const update = await catalog.update(original.templateId, changed, { expectedRevision: oldRevision });
  assert.equal(update.revision, templateRevision(changed));
  assert.deepEqual(createTemplateCatalog({ filePath }).get(original.templateId), changed);
  await assert.rejects(catalog.update(original.templateId, original, { expectedRevision: oldRevision }), { status: 409 });
  await assert.rejects(catalog.update(original.templateId, original), { status: 409 });
  await assert.rejects(catalog.update(original.templateId, example('renamed'), { expectedRevision: update.revision }),
    { status: 400, field: 'template.templateId' });
  await catalog.import(example('custom'));
  const custom = catalog.get('custom');
  await catalog.update('custom', { ...custom, description: 'New content' }, { expectedRevision: templateRevision(custom) });
  assert.equal(catalog.get('custom').description, 'New content');
  await catalog.remove('custom', { expectedRevision: templateRevision(catalog.get('custom')) });
  assert.equal(catalog.get('custom'), null);
  assert.deepEqual(JSON.parse(await readFile(filePath, 'utf8')).deletedTemplateIds, []);
});

test('builtin deletion persists as a tombstone and import restores it', async t => {
  const { catalog, filePath } = await setup(t);
  const remaining = catalog.list().filter(template => template.templateId !== original.templateId);
  await catalog.remove(original.templateId, { expectedRevision: templateRevision(original) });
  assert.equal(createTemplateCatalog({ filePath }).get(original.templateId), null);
  assert.deepEqual(catalog.list(), remaining);
  await assert.rejects(catalog.remove(original.templateId, { expectedRevision: templateRevision(original) }), { status: 404 });
  assert.equal((await catalog.import(original)).created, 1);
  const modified = { ...original, title: 'Restored and changed' };
  await catalog.update(original.templateId, modified, { expectedRevision: templateRevision(original) });
  await assert.rejects(catalog.remove(original.templateId, { expectedRevision: templateRevision(original) }), { status: 409 });
  assert.equal(catalog.get(original.templateId).title, modified.title);
});

test('concurrent imports across instances preserve all templates', async t => {
  const { catalog, filePath } = await setup(t);
  await Promise.all(Array.from({ length: 12 }, (_, index) => createTemplateCatalog({ filePath }).import(example(`parallel-${index}`))));
  assert.equal(catalog.list().length, builtinCount + 12);
  assert.equal(JSON.parse(await readFile(filePath, 'utf8')).templates.length, 12);
});

test('filesystem locking prevents lost updates across independent processes', async t => {
  const { catalog, filePath, dir } = await setup(t);
  const module = new URL('../template-catalog.mjs', import.meta.url).href, script = join(dir, 'writer.mjs');
  await writeFile(script, `import { createTemplateCatalog } from ${JSON.stringify(module)};\nconst template = ${JSON.stringify(original)};\ntemplate.templateId = process.argv[3];\nawait createTemplateCatalog({filePath:process.argv[2]}).import(template);\n`);
  await Promise.all(['process-a', 'process-b', 'process-c'].map(id => promisify(execFile)(process.execPath, [script, filePath, id])));
  assert.equal(catalog.list().length, builtinCount + 3);
});

test('invalid authority/code fields, paths and oversized payloads are rejected', async t => {
  const { catalog } = await setup(t);
  const invalid = [example('../escape'), example('authority', { origin: 'https://other.invalid' }),
    example('command', { execute: 'shell command' }), example('trusted', { trust: 'trusted' }),
    example('token', { request: { packet: { ...original.request.packet, headers: { authorization: 'secret' } } } }),
    example('dots', { target: { method: 'GET', endpoint: '/api/../search' }, request: { packet: { ...original.request.packet, path: '/api/../search' } } }),
    example('mismatch', { target: { method: 'GET', endpoint: '/different' } }),
    example('unicode', { payloads: ['가'.repeat(2000)] })];
  for (const value of invalid) await assert.rejects(catalog.import(value), { status: 400 });
  await assert.rejects(catalog.import(Array.from({ length: 101 }, (_, i) => example(`item-${i}`))), { status: 400 });
  await assert.rejects(catalog.import({ templates: [], dryRun: true }), { status: 400 });
  assert.equal(catalog.list().length, builtinCount);
});

test('corrupt persisted state fails closed without replacing the original file', async t => {
  const { catalog, filePath } = await setup(t);
  await writeFile(filePath, '{broken');
  assert.throws(() => catalog.list(), { status: 503, code: 'CATALOG_UNAVAILABLE' });
  await assert.rejects(catalog.import(example('new')), { status: 503 });
  assert.equal(await readFile(filePath, 'utf8'), '{broken');
});

test('the whole JSON template is bounded so a daemon page can always hold one entry', async t => {
  const { catalog, filePath } = await setup(t);
  const oversized = example('oversized', { payloads: Array.from({ length: 20 }, (_, i) => `${i}` + 'x'.repeat(4000)) });
  assert.ok(Buffer.byteLength(JSON.stringify(oversized)) > TEMPLATE_BYTES);
  await assert.rejects(catalog.import(oversized), { status: 400, field: 'template' });
  assert.equal(catalog.get('oversized'), null);
  await writeFile(filePath, JSON.stringify({ schemaVersion: 1, templates: [oversized], deletedTemplateIds: [] }));
  assert.throws(() => catalog.list(), { status: 503, code: 'CATALOG_UNAVAILABLE' });
});

test('search combines human metadata with exact dependency filters', async t => {
  const { catalog } = await setup(t);
  const dependencyIds = catalog.list({ q: 'node:sqlite' }).map(template => template.templateId);
  const endpointIds = catalog.list({ q: '/api/search' }).map(template => template.templateId);
  assert.ok(dependencyIds.includes(original.templateId));
  assert.ok(endpointIds.includes(original.templateId));
  await catalog.import(example('searchable', { title: 'Custom Title', description: 'Human explanation' }));
  assert.equal(catalog.list({ q: 'CUSTOM TITLE', attackType: 'CWE-89', runtime: 'node' }).length, 1);
  const sorted = ids => ids.sort((a, b) => a.localeCompare(b));
  assert.deepEqual(catalog.list({ q: 'node:sqlite' }).map(template => template.templateId), sorted([...dependencyIds, 'searchable']));
  assert.deepEqual(catalog.list({ q: '/api/search' }).map(template => template.templateId), sorted([...endpointIds, 'searchable']));
  assert.equal(catalog.list({ q: 'human', runtime: 'python' }).length, 0);
});

test('render uses declared endpoint and thresholds; unsupported modes remain references', async t => {
  const { catalog } = await setup(t), custom = example('declared-path');
  custom.target.endpoint = custom.request.packet.path = '/custom-search';
  custom.verify.baseline.expect = 2; custom.verify.attack.expectMin = 4;
  await catalog.import(custom);
  const rendered = renderTemplate({ templateId: custom.templateId, payload: custom.payloads[1] }, catalog);
  assert.equal(rendered.packet.path, '/custom-search'); assert.equal(rendered.baseline.path, '/custom-search');
  const response = count => ({ status: 200, json: { results: Array.from({ length: count }, () => ({})) } });
  assert.equal(verifyTemplate(response(2), response(4), custom).status, 'confirmed');
  assert.equal(verifyTemplate(response(2), response(3), custom).status, 'not_reproduced');
  assert.equal(verifyTemplate(response(0), response(4), custom).status, 'inconclusive');
  const reference = example('reference-only'); reference.verify.mode = 'manualReview';
  assert.equal(validateTemplate(reference).templateId, 'reference-only');
  assert.equal(templateExecutionSupport(reference).supported, false);
  await catalog.import(reference);
  assert.throws(() => renderTemplate({ templateId: 'reference-only', payload: reference.payloads[0] }, catalog), { code: 'UNSUPPORTED_TEMPLATE' });
  assert.throws(() => renderTemplate({ templateId: custom.templateId, payload: 'other' }, catalog), { code: 'INVALID_TEMPLATE' });
});
