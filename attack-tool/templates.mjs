import { defaultTemplateCatalog } from './template-catalog.mjs';
export const TEMPLATE_EXCERPT_BYTES = 4096;
const EXECUTABLE_MODES = new Set(['resultCount', 'inheritedFilter', 'ownershipComparison',
  'containsFields', 'statusSequence', 'tagAcceptance', 'textContains']);
const ID_PAYLOAD = /^[1-9][0-9]{0,8}$/u;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fault = (code, message) => Object.assign(new Error(message), { code });

export function listTemplates(filters = {}, catalog = defaultTemplateCatalog) {
  return catalog.list(filters);
}

function querySlot(packet) {
  const query = packet?.query;
  if (!record(query) || Object.keys(query).length !== 1) return null;
  const [name, value] = Object.entries(query)[0];
  return value === '{{payload}}' ? name : null;
}

function bodySlot(packet) {
  const body = packet?.body;
  if (!record(body) || Object.keys(body).length !== 1) return null;
  const [name, value] = Object.entries(body)[0];
  return value === '{{payload}}' ? name : null;
}

export function templateExecutionSupport(template) {
  const packet = template?.request?.packet;
  const mode = template?.verify?.mode;
  if (template?.executor !== 'guardrail' || template?.trust !== 'unverified' || !record(packet)
    || !EXECUTABLE_MODES.has(mode)) {
    return { supported: false, reason: 'Unsupported executor, trust state, or verifier mode.' };
  }
  if (mode === 'resultCount') {
    if (packet.method !== 'GET' || packet.body !== undefined || querySlot(packet) !== 'q') {
      return { supported: false, reason: 'resultCount requires GET with a q payload slot.' };
    }
    if (typeof template.verify.baseline?.q !== 'string'
      || !Number.isSafeInteger(template.verify.baseline.expect) || template.verify.baseline.expect < 0
      || !Number.isSafeInteger(template.verify.attack?.expectMin)
      || template.verify.attack.expectMin <= template.verify.baseline.expect) {
      return { supported: false, reason: 'resultCount needs a negative baseline q and a higher attack threshold.' };
    }
    return { supported: true, reason: 'GET q result-count comparison.' };
  }
  if (mode === 'inheritedFilter') {
    if (packet.method !== 'GET' || packet.body !== undefined || querySlot(packet) !== 'filters') {
      return { supported: false, reason: 'inheritedFilter requires GET with a filters payload slot.' };
    }
    if (template.verify.attack?.status !== 200 || template.verify.attack.expect !== 1
      || typeof template.verify.attack.contains !== 'string') {
      return { supported: false, reason: 'inheritedFilter needs an exact attack result count and type marker.' };
    }
    return { supported: true, reason: 'GET filters inheritance comparison.' };
  }
  if (mode === 'ownershipComparison') {
    const idQuery = querySlot(packet) === 'id';
    if (packet.method !== 'GET' || packet.body !== undefined || (!packet.path.includes(':id') && !idQuery)
      || typeof template.verify.baseline?.path !== 'string'
      || template.verify.baseline.status !== 200 || template.verify.attack?.status !== 200
      || typeof template.verify.baseline.contains !== 'string'
      || typeof template.verify.attack.contains !== 'string'
      || template.verify.baseline.contains === template.verify.attack.contains) {
      return { supported: false, reason: 'ownershipComparison needs a :id path or id query and distinct owner markers.' };
    }
    return { supported: true, reason: 'Role-bound GET ownership comparison.' };
  }
  if (mode === 'containsFields') {
    if (packet.method !== 'GET' || packet.body !== undefined
      || template.verify.attack?.status !== 200
      || !Array.isArray(template.verify.attack.fields) || !template.verify.attack.fields.length) {
      return { supported: false, reason: 'containsFields needs a GET path and response field names.' };
    }
    return { supported: true, reason: 'Unauthenticated GET field disclosure comparison.' };
  }
  if (mode === 'statusSequence') {
    if (packet.method !== 'POST'
      || template.verify.baseline?.method !== 'GET' || typeof template.verify.baseline.path !== 'string'
      || template.verify.followUp?.method !== 'GET' || typeof template.verify.followUp.path !== 'string'
      || !Number.isInteger(template.verify.baseline.status)
      || !Number.isInteger(template.verify.attack?.status)
      || !Number.isInteger(template.verify.followUp.status)) {
      return { supported: false, reason: 'statusSequence needs POST :id plus GET baseline and follow-up statuses.' };
    }
    return { supported: true, reason: 'Unauthenticated POST then follow-up status comparison.' };
  }
  if (mode === 'tagAcceptance') {
    if (packet.method !== 'POST' || bodySlot(packet) !== 'payload'
      || typeof template.verify.baseline?.body?.payload !== 'string'
      || template.verify.baseline.status !== 200 || template.verify.attack?.status !== 200
      || typeof template.verify.baseline.contains !== 'string'
      || typeof template.verify.attack.contains !== 'string') {
      return { supported: false, reason: 'tagAcceptance needs POST payload baseline/attack body markers.' };
    }
    return { supported: true, reason: 'Admin POST YAML tag-acceptance comparison.' };
  }
  if (mode === 'textContains') {
    if (!['GET', 'POST'].includes(packet.method)
      || !Number.isInteger(template.verify.baseline?.status)
      || !Number.isInteger(template.verify.attack?.status)
      || typeof template.verify.attack.contains !== 'string') {
      return { supported: false, reason: 'textContains needs baseline/attack statuses and an attack marker.' };
    }
    return { supported: true, reason: 'Baseline/attack body marker comparison.' };
  }
  return { supported: false, reason: 'Unsupported packet and verifier; execution still requires the target guardrail policy.' };
}

function fillMap(value, payload) {
  if (!record(value)) return undefined;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, item === '{{payload}}' ? payload : item]));
}

function substituteId(path, payload) {
  if (!path.includes(':id')) return path;
  if (!ID_PAYLOAD.test(payload)) throw fault('INVALID_TEMPLATE', 'Path templates require a positive integer payload.');
  return path.replace(':id', payload);
}

function step(method, path, { query, body, payload } = {}) {
  const filledQuery = fillMap(query, payload);
  const filledBody = fillMap(body, payload);
  const resolved = substituteId(path, payload ?? '1');
  const result = { method, path: resolved };
  if (filledQuery && Object.keys(filledQuery).length) result.query = filledQuery;
  if (filledBody && Object.keys(filledBody).length) result.body = filledBody;
  return result;
}

export function renderTemplate(input, catalog = defaultTemplateCatalog) {
  const template = input && catalog.get(input.templateId);
  if (!input || Object.keys(input).some(key => !['templateId', 'payload'].includes(key))
    || !template || !template.payloads.includes(input.payload)) {
    throw fault('INVALID_TEMPLATE', 'Unknown template or payload.');
  }
  if (!templateExecutionSupport(template).supported) throw fault('UNSUPPORTED_TEMPLATE', 'Template execution is not supported.');
  const packet = template.request.packet;
  const mode = template.verify.mode;
  const payload = input.payload;
  if (mode === 'resultCount') {
    return { template: structuredClone(template),
      baseline: step('GET', packet.path, { query: { q: template.verify.baseline.q } }),
      packet: step('GET', packet.path, { query: { q: payload } }) };
  }
  if (mode === 'inheritedFilter') {
    return { template: structuredClone(template),
      baseline: step('GET', packet.path, { query: template.verify.baseline.query ?? { filters: '{}' } }),
      packet: step('GET', packet.path, { query: packet.query, payload }) };
  }
  if (mode === 'ownershipComparison') {
    return { template: structuredClone(template),
      baseline: step('GET', template.verify.baseline.path, { query: template.verify.baseline.query }),
      packet: step('GET', packet.path, { query: packet.query, payload }) };
  }
  if (mode === 'containsFields') {
    const control = template.verify.baseline.path ?? packet.path;
    return { template: structuredClone(template),
      baseline: step('GET', control, { query: template.verify.baseline.query }),
      packet: step('GET', packet.path) };
  }
  if (mode === 'statusSequence') {
    return { template: structuredClone(template),
      baseline: step(template.verify.baseline.method, template.verify.baseline.path),
      packet: step(packet.method, packet.path, { body: packet.body, payload }),
      followUp: step(template.verify.followUp.method, template.verify.followUp.path) };
  }
  if (mode === 'textContains') {
    const baseline = template.verify.baseline;
    return { template: structuredClone(template),
      baseline: step(baseline.method ?? 'GET', baseline.path ?? packet.path,
        { query: baseline.query, body: baseline.body }),
      packet: step(packet.method, packet.path, { query: packet.query, body: packet.body, payload }) };
  }
  return { template: structuredClone(template),
    baseline: step('POST', packet.path, { body: template.verify.baseline.body }),
    packet: step('POST', packet.path, { body: packet.body, payload }) };
}

function responseText(response) {
  if (typeof response?.body === 'string') return response.body;
  if (response?.json !== undefined) return JSON.stringify(response.json);
  return '';
}

function resultRows(response) {
  if (response?.truncated || response?.status !== 200) return null;
  let body = response.json;
  if (body === undefined) { try { body = JSON.parse(response.body); } catch { return null; } }
  const rows = Array.isArray(body) ? body : body?.results;
  return Array.isArray(rows) ? rows : null;
}

function hasStatus(response, expected) {
  return Number.isInteger(expected) && response?.status === expected;
}

function hasText(response, needle) {
  return typeof needle === 'string' && needle.length > 0 && responseText(response).includes(needle);
}

export function verifyTemplate(baseline, attack, template, followUp) {
  const mode = template?.verify?.mode;
  if (mode === 'resultCount') {
    const baselineCount = resultRows(baseline)?.length ?? null;
    const attackCount = resultRows(attack)?.length ?? null;
    const expectedBaseline = template?.verify?.baseline?.expect ?? 0;
    const expectedAttack = template?.verify?.attack?.expectMin ?? 1;
    return { status: baselineCount !== expectedBaseline || attackCount === null ? 'inconclusive'
      : attackCount >= expectedAttack ? 'confirmed' : 'not_reproduced', baselineCount, attackCount };
  }
  if (mode === 'inheritedFilter') {
    const baselineRows = resultRows(baseline);
    const attackRows = resultRows(attack);
    const expected = template.verify.attack.expect;
    if (!baselineRows || attackRows === null || !hasStatus(attack, 200)) {
      return { status: 'inconclusive', baselineCount: baselineRows?.length ?? null,
        attackCount: attackRows?.length ?? null };
    }
    const matched = attackRows.length === expected && hasText(attack, template.verify.attack.contains);
    return { status: matched ? 'confirmed' : 'not_reproduced',
      baselineCount: baselineRows.length, attackCount: attackRows.length };
  }
  if (mode === 'ownershipComparison') {
    if (baseline?.truncated || attack?.truncated) return { status: 'inconclusive' };
    const baseOk = hasStatus(baseline, template.verify.baseline.status)
      && hasText(baseline, template.verify.baseline.contains);
    const attackOk = hasStatus(attack, template.verify.attack.status)
      && hasText(attack, template.verify.attack.contains);
    if (!hasStatus(baseline, template.verify.baseline.status) || !hasStatus(attack, template.verify.attack.status)) {
      return { status: 'inconclusive' };
    }
    return { status: baseOk && attackOk ? 'confirmed' : 'not_reproduced' };
  }
  if (mode === 'containsFields') {
    if (attack?.truncated || !hasStatus(attack, template.verify.attack.status)) return { status: 'inconclusive' };
    let body = attack.json;
    if (!record(body)) { try { body = JSON.parse(attack.body); } catch { return { status: 'inconclusive' }; } }
    if (!record(body)) return { status: 'inconclusive' };
    const missing = template.verify.attack.fields.filter(field => !Object.hasOwn(body, field));
    return { status: missing.length ? 'not_reproduced' : 'confirmed' };
  }
  if (mode === 'statusSequence') {
    if (!followUp) return { status: 'inconclusive' };
    const baseOk = hasStatus(baseline, template.verify.baseline.status);
    const attackOk = hasStatus(attack, template.verify.attack.status);
    let followOk = hasStatus(followUp, template.verify.followUp.status);
    if (!baseOk) return { status: 'inconclusive' };
    if (typeof template.verify.followUp.contains === 'string') {
      followOk = followOk && hasText(followUp, template.verify.followUp.contains);
    }
    return { status: attackOk && followOk ? 'confirmed' : 'not_reproduced' };
  }
  if (mode === 'textContains') {
    if (baseline?.truncated || attack?.truncated) return { status: 'inconclusive' };
    if (!hasStatus(baseline, template.verify.baseline.status)) return { status: 'inconclusive' };
    if (!hasStatus(attack, template.verify.attack.status)) return { status: 'not_reproduced' };
    if (typeof template.verify.baseline.contains === 'string'
      && !hasText(baseline, template.verify.baseline.contains)) {
      return { status: 'not_reproduced' };
    }
    return { status: hasText(attack, template.verify.attack.contains) ? 'confirmed' : 'not_reproduced' };
  }
  if (mode === 'tagAcceptance') {
    if (baseline?.truncated || attack?.truncated) return { status: 'inconclusive' };
    if (!hasStatus(baseline, template.verify.baseline.status) || !hasStatus(attack, template.verify.attack.status)) {
      return { status: 'inconclusive' };
    }
    const baseOk = hasText(baseline, template.verify.baseline.contains);
    const attackOk = hasText(attack, template.verify.attack.contains);
    return { status: baseOk && attackOk ? 'confirmed' : 'not_reproduced' };
  }
  return { status: 'inconclusive' };
}

/** Keep response evidence bounded independently of the complete source used by verification. */
export function projectTemplateResponse(response) {
  const body = typeof response?.body === 'string' ? response.body
    : response?.json === undefined ? '' : JSON.stringify(response.json);
  const bytes = Buffer.from(body, 'utf8');
  const excerptTruncated = bytes.length > TEMPLATE_EXCERPT_BYTES;
  // Streaming decode drops an incomplete UTF-8 character at the excerpt boundary.
  const bodyExcerpt = excerptTruncated
    ? new TextDecoder('utf-8').decode(bytes.subarray(0, TEMPLATE_EXCERPT_BYTES), { stream: true })
    : body;
  return { status: Number.isInteger(response?.status) ? response.status : null,
    headers: { 'content-type': String(response?.headers?.['content-type'] ?? '').slice(0, 256) },
    truncated: response?.truncated === true, bodyExcerpt, excerptTruncated, bodyBytes: bytes.length };
}
