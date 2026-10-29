import { defaultTemplateCatalog } from './template-catalog.mjs';
export const TEMPLATE_EXCERPT_BYTES = 4096;

export function listTemplates(filters = {}, catalog = defaultTemplateCatalog) {
  return catalog.list(filters);
}

export function templateExecutionSupport(template) {
  const packet = template?.request?.packet;
  if (template?.executor !== 'guardrail' || template?.trust !== 'unverified') return { supported: false, reason: 'Unsupported executor or trust state.' };
  if (packet?.method !== 'GET' || packet.body !== undefined || !packet.query
    || Object.keys(packet.query).length !== 1 || packet.query.q !== '{{payload}}') return { supported: false, reason: 'Execution currently supports GET packets with the q payload slot.' };
  if (template.verify?.mode !== 'resultCount' || typeof template.verify.baseline?.q !== 'string'
    || !Number.isSafeInteger(template.verify.baseline.expect) || template.verify.baseline.expect < 0
    || !Number.isSafeInteger(template.verify.attack?.expectMin) || template.verify.attack.expectMin <= template.verify.baseline.expect
    || Object.keys(template.verify.baseline).some(key => !['q', 'expect'].includes(key))
    || Object.keys(template.verify.attack).some(key => key !== 'expectMin')) return { supported: false, reason: 'Execution currently supports resultCount with a higher attack threshold than the baseline.' };
  return { supported: true, reason: 'Supported packet and verifier; execution still requires the target guardrail policy.' };
}

export function renderTemplate(input, catalog = defaultTemplateCatalog) {
  const template = input && catalog.get(input.templateId);
  if (!input || Object.keys(input).some(key => !['templateId', 'payload'].includes(key))
    || !template || !template.payloads.includes(input.payload)) {
    throw Object.assign(new Error('Unknown template or payload.'), { code: 'INVALID_TEMPLATE' });
  }
  if (!templateExecutionSupport(template).supported) throw Object.assign(new Error('Template execution is not supported.'), { code: 'UNSUPPORTED_TEMPLATE' });
  return { template: structuredClone(template), baseline: { method: 'GET', path: template.request.packet.path,
    query: { q: template.verify.baseline.q } },
  packet: { method: 'GET', path: template.request.packet.path, query: { q: input.payload } } };
}

export function verifyTemplate(baseline, attack, template) {
  const count = response => {
    if (response?.truncated || response?.status !== 200) return null;
    let body = response.json;
    if (body === undefined) { try { body = JSON.parse(response.body); } catch { return null; } }
    const rows = Array.isArray(body) ? body : body?.results;
    return Array.isArray(rows) ? rows.length : null;
  };
  const baselineCount = count(baseline), attackCount = count(attack);
  const expectedBaseline = template?.verify?.baseline?.expect ?? 0;
  const expectedAttack = template?.verify?.attack?.expectMin ?? 1;
  return { status: baselineCount !== expectedBaseline || attackCount === null ? 'inconclusive'
    : attackCount >= expectedAttack ? 'confirmed' : 'not_reproduced', baselineCount, attackCount };
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
