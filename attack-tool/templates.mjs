import { readFileSync } from 'node:fs';

const template = JSON.parse(readFileSync(new URL('./templates/sqli-like-tautology.json', import.meta.url), 'utf8'));
export const TEMPLATE_EXCERPT_BYTES = 4096;

export function listTemplates({ attackType, runtime, framework, library } = {}) {
  if (attackType && ![template.attackType.name, template.attackType.cwe].includes(attackType)) return [];
  if (Object.entries({ runtime, framework, library }).some(([key, value]) => value && value !== template.dependency[key])) return [];
  return [structuredClone(template)];
}

export function renderTemplate(input) {
  if (!input || Object.keys(input).some(key => !['templateId', 'payload'].includes(key))
    || input.templateId !== template.templateId || !template.payloads.includes(input.payload)) {
    throw Object.assign(new Error('Unknown template or payload.'), { code: 'INVALID_TEMPLATE' });
  }
  return { template: structuredClone(template), baseline: { method: 'GET', path: '/api/search',
    query: { q: template.verify.baseline.q } },
  packet: { method: 'GET', path: '/api/search', query: { q: input.payload } } };
}

export function verifyTemplate(baseline, attack) {
  const count = response => {
    if (response?.truncated || response?.status !== 200) return null;
    let body = response.json;
    if (body === undefined) { try { body = JSON.parse(response.body); } catch { return null; } }
    const rows = Array.isArray(body) ? body : body?.results;
    return Array.isArray(rows) ? rows.length : null;
  };
  const baselineCount = count(baseline), attackCount = count(attack);
  return { status: baselineCount !== 0 || attackCount === null ? 'inconclusive'
    : attackCount >= 1 ? 'confirmed' : 'not_reproduced', baselineCount, attackCount };
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
