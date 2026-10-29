import { readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdir, open, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

export const TEMPLATE_IMPORT_LIMIT = 100;
export const TEMPLATE_BYTES = 64 * 1024;
export const TEMPLATE_CATALOG_BYTES = 4 * 1024 * 1024;
export const TEMPLATE_CATALOG_LIMIT = 1000;
const schema = JSON.parse(readFileSync(new URL('./schemas/attack-template.schema.json', import.meta.url), 'utf8'));
export const templateSchema = structuredClone(schema);
const builtinDirectory = new URL('./templates/', import.meta.url);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fault = (status, code, message, extra = {}) => Object.assign(new Error(message), { status, code, ...extra });

function invalid(field, reason) {
  throw fault(400, 'INVALID_TEMPLATE', `${field}: ${reason}`, { field });
}

// Validation and the downloadable schema share one contract. These are the
// schema keywords used by this contract; templates never contain runnable code.
function validate(value, rule, field) {
  if (rule.$ref) return validate(value, schema.$defs[rule.$ref.split('/').at(-1)], field);
  if (Object.hasOwn(rule, 'const') && value !== rule.const) invalid(field, `must be ${JSON.stringify(rule.const)}`);
  if (rule.enum && !rule.enum.includes(value)) invalid(field, 'unsupported value');
  if (rule.type === 'object') {
    if (!record(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid(field, 'must be an object');
    const keys = Object.keys(value);
    if (rule.maxProperties !== undefined && keys.length > rule.maxProperties) invalid(field, `maximum ${rule.maxProperties} properties`);
    for (const key of rule.required ?? []) if (!Object.hasOwn(value, key)) invalid(`${field}.${key}`, 'required');
    for (const key of keys) {
      if (['__proto__', 'constructor', 'prototype'].includes(key)) invalid(`${field}.${key}`, 'reserved property');
      if (rule.propertyNames) validate(key, { type: 'string', ...rule.propertyNames }, `${field}.${key}`);
      const child = rule.properties?.[key];
      if (child) validate(value[key], child, `${field}.${key}`);
      else if (rule.additionalProperties === false) invalid(`${field}.${key}`, 'unknown property');
      else if (record(rule.additionalProperties)) validate(value[key], rule.additionalProperties, `${field}.${key}`);
    }
  } else if (rule.type === 'array') {
    if (!Array.isArray(value)) invalid(field, 'must be an array');
    if (value.length < (rule.minItems ?? 0) || value.length > (rule.maxItems ?? Infinity)) invalid(field, `must contain ${rule.minItems ?? 0}–${rule.maxItems ?? 'unlimited'} items`);
    if (rule.uniqueItems && new Set(value.map(item => JSON.stringify(item))).size !== value.length) invalid(field, 'duplicate values');
    value.forEach((item, index) => validate(item, rule.items, `${field}[${index}]`));
  } else if (rule.type === 'string') {
    if (typeof value !== 'string') invalid(field, 'must be a string');
    if (Array.from(value).length < (rule.minLength ?? 0) || Array.from(value).length > (rule.maxLength ?? Infinity)) invalid(field, 'invalid string length');
    if (rule.pattern && !new RegExp(rule.pattern, 'u').test(value)) invalid(field, 'invalid format');
  } else if (rule.type === 'integer') {
    if (!Number.isSafeInteger(value) || value < (rule.minimum ?? -Infinity) || value > (rule.maximum ?? Infinity)) invalid(field, 'invalid integer');
  }
}

export function validateTemplate(value) {
  validate(value, schema, 'template');
  const packet = value.request.packet;
  if (value.target.method !== packet.method || value.target.endpoint !== packet.path) invalid('template.target', 'must match request.packet method and path');
  if (new URL(packet.path, 'http://template.invalid').pathname !== packet.path) invalid('template.target.endpoint', 'must be a canonical path without dot segments');
  if (value.payloads.some(payload => Buffer.byteLength(payload, 'utf8') > 4096)) invalid('template.payloads', 'each payload must fit 4096 UTF-8 bytes');
  if (Buffer.byteLength(value.verify.baseline.q ?? '', 'utf8') > 4096) invalid('template.verify.baseline.q', 'must fit 4096 UTF-8 bytes');
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > TEMPLATE_BYTES) invalid('template', 'must fit 64 KiB of JSON');
  return structuredClone(value);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (record(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const templateRevision = template => createHash('sha256').update(canonical(template)).digest('hex');

function builtins() {
  try {
    return readdirSync(builtinDirectory).filter(name => name.endsWith('.json')).sort().map(name =>
      validateTemplate(JSON.parse(readFileSync(new URL(name, builtinDirectory), 'utf8'))));
  } catch {
    throw fault(503, 'CATALOG_UNAVAILABLE', 'Builtin template files could not be read or validated.');
  }
}

function stored(filePath) {
  try {
    if (statSync(filePath).size > TEMPLATE_CATALOG_BYTES) throw new Error('Storage limit');
    const value = JSON.parse(readFileSync(filePath, 'utf8'));
    if (!record(value) || value.schemaVersion !== 1 || Object.keys(value).some(key => !['schemaVersion', 'templates', 'deletedTemplateIds'].includes(key))
      || !Array.isArray(value.templates) || value.templates.length > TEMPLATE_CATALOG_LIMIT
      || !Array.isArray(value.deletedTemplateIds) || value.deletedTemplateIds.length > TEMPLATE_CATALOG_LIMIT
      || value.deletedTemplateIds.some(id => typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(id))
      || new Set(value.deletedTemplateIds).size !== value.deletedTemplateIds.length) throw new Error('Invalid catalog shape');
    value.templates = value.templates.map(validateTemplate);
    if (new Set(value.templates.map(item => item.templateId)).size !== value.templates.length) throw new Error('Duplicate templates');
    return value;
  } catch (error) {
    if (error.code === 'ENOENT') return { schemaVersion: 1, templates: [], deletedTemplateIds: [] };
    throw fault(503, 'CATALOG_UNAVAILABLE', 'Template catalog could not be read or validated.');
  }
}

function effective(state) {
  const deleted = new Set(state.deletedTemplateIds), map = new Map();
  for (const template of builtins()) {
    if (map.has(template.templateId)) throw fault(503, 'CATALOG_UNAVAILABLE', 'Duplicate builtin template ID.');
    map.set(template.templateId, template);
  }
  for (const template of state.templates) map.set(template.templateId, template);
  for (const id of deleted) map.delete(id);
  return map;
}

export function filterTemplates(templates, { attackType, runtime, framework, library, q } = {}) {
  return structuredClone(templates.filter(template => (!attackType || [template.attackType.name, template.attackType.cwe].includes(attackType))
    && !Object.entries({ runtime, framework, library }).some(([key, value]) => value && value !== template.dependency[key])
    && (!q || [template.templateId, template.title, template.description, template.attackType.name, template.attackType.cwe,
      ...Object.values(template.dependency), template.target.endpoint].filter(Boolean).join(' ').toLowerCase().includes(q.toLowerCase()))));
}

function importRequest(input) {
  let values = input, dryRun = false;
  if (record(input) && Object.hasOwn(input, 'templates')) {
    if (Object.keys(input).some(key => !['templates', 'dryRun'].includes(key))) invalid('request', 'unknown import property');
    if (Object.hasOwn(input, 'dryRun') && typeof input.dryRun !== 'boolean') invalid('request.dryRun', 'must be boolean');
    values = input.templates; dryRun = input.dryRun === true;
    if (!Array.isArray(values)) invalid('request.templates', 'must be an array');
  }
  if (!Array.isArray(values)) values = [values];
  if (!values.length || values.length > TEMPLATE_IMPORT_LIMIT) invalid('request.templates', `must contain 1–${TEMPLATE_IMPORT_LIMIT} templates`);
  return { values: values.map((value, index) => {
    try { return validateTemplate(value); }
    catch (error) { error.index = index; error.message = `templates[${index}]: ${error.message}`; throw error; }
  }), dryRun };
}

// Filesystem locking coordinates separate API processes. A crashed writer leaves
// a lock and fails closed instead of overwriting a possibly newer catalog.
async function locked(filePath, operation) {
  await mkdir(dirname(filePath), { recursive: true });
  const lockPath = filePath + '.lock', started = Date.now();
  let lock;
  while (!lock) {
    try { lock = await open(lockPath, 'wx', 0o600); }
    catch (error) {
      // Windows can report a delete-pending lock as EPERM while another writer
      // releases its handle; retry without removing a lock owned by that writer.
      if (error.code !== 'EEXIST' && !(process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code))) throw error;
      if (Date.now() - started > 5000) throw fault(503, 'CATALOG_BUSY', 'Template catalog is busy; retry after the active writer finishes.');
      await delay(20);
    }
  }
  try { return await operation(); }
  finally { await lock.close(); await unlink(lockPath); }
}

async function persist(filePath, state) {
  if (effective(state).size > TEMPLATE_CATALOG_LIMIT || state.deletedTemplateIds.length > TEMPLATE_CATALOG_LIMIT) throw fault(400, 'CATALOG_LIMIT', `Catalog supports at most ${TEMPLATE_CATALOG_LIMIT} templates.`);
  const output = JSON.stringify(state, null, 2) + '\n';
  if (Buffer.byteLength(output) > TEMPLATE_CATALOG_BYTES) throw fault(400, 'CATALOG_LIMIT', 'Catalog supports at most 4 MiB of custom templates.');
  const temp = filePath + '.' + randomUUID() + '.tmp';
  try { await writeFile(temp, output, { mode: 0o600, flag: 'wx' }); await rename(temp, filePath); }
  finally { await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}

function requireRevision(current, expectedRevision) {
  if (!current) throw fault(404, 'TEMPLATE_NOT_FOUND', 'Template not found.');
  if (typeof expectedRevision !== 'string' || templateRevision(current) !== expectedRevision) throw fault(409, 'TEMPLATE_CONFLICT', 'Template changed; reload before saving or deleting.');
}

export function createTemplateCatalog({ filePath = process.env.CA3P_ATTACK_TEMPLATES_PATH
  ?? fileURLToPath(new URL('../.runtime/attack-templates.json', import.meta.url)) } = {}) {
  filePath = resolve(filePath);
  return {
    filePath,
    list(filters = {}) {
      const templates = [...effective(stored(filePath)).values()].sort((a, b) => a.templateId.localeCompare(b.templateId));
      return filterTemplates(templates, filters);
    },
    get(templateId) { return structuredClone(effective(stored(filePath)).get(templateId) ?? null); },
    async import(input) {
      const { values, dryRun } = importRequest(input);
      return locked(filePath, async () => {
        const state = stored(filePath), map = effective(state);
        let created = 0, unchanged = 0;
        for (const [index, value] of values.entries()) {
          const existing = map.get(value.templateId);
          if (existing) {
            if (canonical(existing) !== canonical(value)) throw fault(409, 'TEMPLATE_CONFLICT', `templates[${index}]: Template ${value.templateId} already has different content; use update or a new templateId.`, { index, field: 'template.templateId' });
            unchanged += 1;
          } else {
            map.set(value.templateId, value); created += 1;
            state.templates = state.templates.filter(item => item.templateId !== value.templateId);
            state.templates.push(value);
            state.deletedTemplateIds = state.deletedTemplateIds.filter(id => id !== value.templateId);
          }
        }
        if (map.size > TEMPLATE_CATALOG_LIMIT || Buffer.byteLength(JSON.stringify(state, null, 2) + '\n') > TEMPLATE_CATALOG_BYTES) throw fault(400, 'CATALOG_LIMIT', 'Template catalog storage limit exceeded.');
        if (!dryRun && created) await persist(filePath, state);
        return { created, unchanged, total: map.size, dryRun, templates: values };
      });
    },
    async update(templateId, input, { expectedRevision } = {}) {
      const template = validateTemplate(input);
      if (template.templateId !== templateId) invalid('template.templateId', 'cannot change during update');
      return locked(filePath, async () => {
        const state = stored(filePath);
        requireRevision(effective(state).get(templateId), expectedRevision);
        state.templates = state.templates.filter(item => item.templateId !== templateId);
        state.templates.push(template);
        await persist(filePath, state);
        return { template, revision: templateRevision(template) };
      });
    },
    async remove(templateId, { expectedRevision } = {}) {
      return locked(filePath, async () => {
        const state = stored(filePath);
        requireRevision(effective(state).get(templateId), expectedRevision);
        state.templates = state.templates.filter(item => item.templateId !== templateId);
        // Builtin files need tombstones. Removing a custom overlay is sufficient
        // and avoids accumulating deleted custom IDs throughout catalog use.
        if (builtins().some(item => item.templateId === templateId)) state.deletedTemplateIds.push(templateId);
        await persist(filePath, state);
        return { deleted: true, templateId };
      });
    },
  };
}

export const defaultTemplateCatalog = createTemplateCatalog();
