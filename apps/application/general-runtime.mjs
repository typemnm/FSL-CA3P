import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emptyRun, assertIdentifier, redact } from '../../packages/contracts/index.mjs';
import { verifyAttack } from '../../packages/verifier/index.mjs';
import { writeReportHandoff } from '../../packages/verifier/report-handoff.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, validateGeneralLoopBudget } from '../../packages/contracts/general-loop-budget.mjs';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import generalCore from '../../agent/src/general-assessment.js';
import generalPlanner from '../../agent/src/general-model-planner.js';
import { readKnowledgeCatalogReadOnly } from '../../packages/adapters/integrations/knowledge-db.mjs';
import { collectWebInfo, evidenceFromTargetInfo } from '../../packages/adapters/integrations/web-parser.mjs';
import { createAttackToolBridge } from '../../packages/adapters/integrations/attack-tool.mjs';

const { runGeneralAssessment } = generalCore;
const { createGeneralModelPlannerFromEnv } = generalPlanner;
const ACTIVE = new Set(['preparing', 'running', 'stopping']);
const MODELS = new Set(['deepseek-flash', 'deepseek-v4-pro']);
// Planner prompt cap 65,536 − 8,192 margin − 39,894 measured worst non-web_info context (daehan inventory 13,859,
// initial evidence 3,833, 40 hypotheses 19,867, system/rest/probe IDs 2,335) − 24 one-line overviews × 441 = 6,866.
// Measured with the default loop budget (maxProbes 24); a larger maxProbes shrinks the headroom the core prompt has.
const WEB_INFO_EVIDENCE_BUDGET_BYTES = 6800;
const MAX_BODY_BYTES = 24 * 1024;
const MAX_INITIAL_PAGES = 14;
// The first plan sees all operator-reviewed URLs. Later plans can reduce only
// optional detail if their accumulated hypotheses and evidence fill the prompt.
const MAX_PREVIEW_INVENTORY_BYTES = 24 * 1024;
const PREVIEW_RETRY_BUDGETS = [20 * 1024, 16 * 1024, 13 * 1024,
  10 * 1024, 8 * 1024, 6800];
const MAX_PREVIEW_PAGES = 48;
const PREVIEW_OMISSION_FIELDS = ['queryParameterNames', 'title', 'technologies',
  'libraries', 'forms', 'paths', 'errors'];
const CATALOG_SOURCE = 'casper-db/attack-catalog';
const FIXTURES = Object.freeze({
  'vul-web2-daehan': {
    name: '대한대학교', siteKey: 'daehan', origin: 'http://127.0.0.1:4101',
    routes: ['/', '/about', '/admissions', '/colleges', '/academics', '/research',
      '/campus', '/facilities', '/notices', '/news', '/schedule', '/faq', '/login',
      '/mypage', '/admin', '/api/search', '/api/admissions/partner/applications/1'],
    files: {
      'vul-web2/README.md': '../../vul-web2/README.md',
      'vul-web2/package.json': '../../vul-web2/package.json',
      'vul-web2/src/server.mjs': '../../vul-web2/src/server.mjs',
      'vul-web2/src/sites.mjs': '../../vul-web2/src/sites.mjs',
      'vul-web2/src/db.mjs': '../../vul-web2/src/db.mjs',
      'vul-web2/docs/사전_침해분석_및_취약점_보고서.md': '../../vul-web2/docs/사전_침해분석_및_취약점_보고서.md',
    },
    manifest: 'vul-web2/package.json',
  },
  'vul-web2-wonchang': {
    name: '원창대학교', siteKey: 'wonchang', origin: 'http://127.0.0.1:4102',
    routes: ['/', '/about', '/admissions', '/colleges', '/academics', '/research',
      '/campus', '/facilities', '/notices', '/news', '/schedule', '/faq', '/login',
      '/mypage', '/admin', '/api/search', '/api/staff/mobile/cases/1'],
    files: {
      'vul-web2/README.md': '../../vul-web2/README.md',
      'vul-web2/wonchang/pom.xml': '../../vul-web2/wonchang/pom.xml',
      'vul-web2/wonchang/src/main/java/edu/wonchang/portal/PortalController.java': '../../vul-web2/wonchang/src/main/java/edu/wonchang/portal/PortalController.java',
      'vul-web2/wonchang/src/main/java/edu/wonchang/portal/Store.java': '../../vul-web2/wonchang/src/main/java/edu/wonchang/portal/Store.java',
      'vul-web2/wonchang/src/main/java/edu/wonchang/portal/SiteCatalog.java': '../../vul-web2/wonchang/src/main/java/edu/wonchang/portal/SiteCatalog.java',
      'vul-web2/wonchang/src/main/java/edu/wonchang/portal/SpringHeaderFilter.java': '../../vul-web2/wonchang/src/main/java/edu/wonchang/portal/SpringHeaderFilter.java',
      'vul-web2/docs/사전_침해분석_및_취약점_보고서.md': '../../vul-web2/docs/사전_침해분석_및_취약점_보고서.md',
    },
    manifest: 'vul-web2/wonchang/pom.xml',
  },
});

const fault = (status, message) => Object.assign(new Error(message), { status });
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const safeText = value => String(value).replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/giu, '$1 [redacted]')
  .replace(/\b(password|passwd|api[_-]?key|secret|token|session|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu, '$1=[redacted]');
const DEMO_PASSWORDS = ['admin1234', 'Welcome2026', 'Partner2026', 'Staff2026'];
function safeSourceExcerpt(value) {
  // The registered university seed stores disposable demo passwords as sha1 literals.
  // Keep the surrounding source for analysis while excluding password values.
  let excerpt = safeText(value)
    .replace(/\bsha1\(\s*(['"])[^'"\r\n]*\1\s*\)/giu, 'sha1([redacted])');
  for (const password of DEMO_PASSWORDS) excerpt = excerpt.replaceAll(password, '[redacted]');
  return excerpt;
}
const safeHeaderValue = value => utf8Prefix(safeText(value)
  .replace(/(['"])nonce-[A-Za-z0-9+/_=-]{6,}\1/giu, '$1nonce-[redacted]$1')
  .replace(/\/\/[^/@\s]+:[^/@\s]+@/gu, '//[redacted]@'), 256);
function utf8Prefix(value, maxBytes) {
  const characters = [];
  let bytes = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character, 'utf8');
    if (bytes + size > maxBytes) break;
    characters.push(character);
    bytes += size;
  }
  return characters.join('');
}
function previewText(value, maxBytes) {
  if (typeof value !== 'string') return '';
  return utf8Prefix(safeText(redact(value)).replace(/[\u0000-\u001f\u007f]/gu, ' '), maxBytes);
}
function previewUrl(value, origin) {
  try {
    const url = new URL(value);
    return url.origin === origin ? url : null;
  } catch { return null; }
}
function previewPathname(value, origin) {
  const url = previewUrl(value, origin);
  if (!url) return null;
  // Opaque path segments often carry reset/session tokens. Keep route shape,
  // but never place their raw values in a model prompt.
  return url.pathname.split('/').map(segment =>
    /^[A-Za-z0-9._~%-]{24,}$/u.test(segment) ? '[opaque-segment]' : segment).join('/');
}
function previewPath(value, origin, maxBytes = 96) {
  const path = previewPathname(value, origin);
  return path ? utf8Prefix(path, maxBytes) : null;
}
function previewComponent(value, library = false) {
  const name = previewText(value?.name, 52);
  if (!name) return null;
  const version = previewText(value?.version, 24);
  const identified = /^\d+(?:\.\d+){0,3}(?:[-+][a-z0-9.]{1,16})?$/iu.test(version)
    ? `${name} ${version}` : name;
  return library && value?.source === 'indicator' ? `${identified} [indicator]` : identified;
}
function previewForm(value, origin) {
  const path = previewPath(value?.action, origin, 72);
  if (!path) return null;
  const method = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD)$/iu.test(value?.method ?? '')
    ? value.method.toUpperCase() : 'UNKNOWN';
  const fields = Array.isArray(value?.fields) ? value.fields.slice(0, 5)
    .map(field => previewText(field?.name, 24)).filter(Boolean) : [];
  return utf8Prefix(`${method} ${path}${fields.length ? ` (${fields.join(', ')})` : ''}`, 128);
}
function previewError(value) {
  const code = value?.code;
  return typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/u.test(code)
    ? code : 'PARSER_PREVIEW_FAILED';
}
export function modelPreviewPages(parserPreview, origin, maxBytes = MAX_PREVIEW_INVENTORY_BYTES) {
  if (!parserPreview) return { pages: [], bytes: 0 };
  if (parserPreview.pages.length > MAX_PREVIEW_PAGES) {
    throw new TypeError('Parser preview contains more URLs than the supported model inventory.');
  }
  const source = parserPreview.pages;
  const compact = maxBytes <= 10 * 1024;
  const makeRows = pathLimit => source.map((page, index) => {
    const url = previewUrl(page?.url, origin);
    const path = previewPathname(page?.url, origin) ?? '[invalid-url]';
    const queryNames = url ? [...new Set(url.searchParams.keys())] : [];
    const omitted = { queryParameterNames: queryNames.length,
      title: typeof page?.title === 'string' && page.title ? 1 : 0,
      technologies: Array.isArray(page?.technologies) ? page.technologies.length : 0,
      libraries: Array.isArray(page?.libraries) ? page.libraries.length : 0,
      forms: Array.isArray(page?.forms) ? page.forms.length : 0,
      paths: Array.isArray(page?.paths) ? page.paths.length : 0,
      errors: Array.isArray(page?.errors) ? page.errors.length : 0 };
    return { index: index + 1, path: utf8Prefix(path, pathLimit),
      ...(Buffer.byteLength(path, 'utf8') > pathLimit ? { pathTruncated: true } : {}),
      status: Number.isInteger(page?.status) ? page.status : null,
      ...(!compact ? { technologies: [], libraries: [], forms: [], paths: [], errors: [] } : {}),
      ...(page?.truncated === true ? { pageTruncated: true } : {}),
      omitted: compact ? PREVIEW_OMISSION_FIELDS.map(key => omitted[key]) : omitted };
  });
  let rows = makeRows(96);
  const bytes = () => Buffer.byteLength(JSON.stringify(rows), 'utf8');
  for (const pathLimit of [64, 40, 24, 16]) {
    if (bytes() <= maxBytes) break;
    rows = makeRows(pathLimit);
  }
  if (bytes() > maxBytes) {
    throw new TypeError('All parser preview URL rows cannot fit the bounded model inventory.');
  }
  const candidates = source.map(page => ({
    title: previewText(page?.title, 80),
    technologies: (Array.isArray(page?.technologies) ? page.technologies : [])
      .slice(0, 24).map(previewComponent).filter(Boolean),
    libraries: (Array.isArray(page?.libraries) ? page.libraries : [])
      .slice(0, 24).map(value => previewComponent(value, true)).filter(Boolean),
    forms: (Array.isArray(page?.forms) ? page.forms : [])
      .slice(0, 16).map(form => previewForm(form, origin)).filter(Boolean),
    paths: (Array.isArray(page?.paths) ? page.paths : [])
      .slice(0, 24).map(path => previewPath(path?.url, origin, 80)).filter(Boolean)
      .filter(path => !/\.(?:css|m?js|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|pdf|zip|mp4|webm)$/iu.test(path)),
    errors: (Array.isArray(page?.errors) ? page.errors : []).slice(0, 12).map(previewError),
    queryParameterNames: (previewUrl(page?.url, origin)
      ? [...new Set(previewUrl(page.url, origin).searchParams.keys())] : [])
      .slice(0, 8).map(key => previewText(key, 24)).filter(Boolean),
  }));
  const add = (index, key, item) => {
    if (!item) return;
    const omissionKey = compact ? PREVIEW_OMISSION_FIELDS.indexOf(key) : key;
    if (!rows[index][key]) rows[index][key] = [];
    rows[index][key].push(item);
    rows[index].omitted[omissionKey] -= 1;
    if (bytes() > maxBytes) {
      rows[index][key].pop();
      rows[index].omitted[omissionKey] += 1;
      if (!rows[index][key].length && (compact || key === 'queryParameterNames')) delete rows[index][key];
    }
  };
  // Give every URL its first error and detected technology/library before
  // optional form/path detail. Omission counts remain explicit on each row.
  for (let index = 0; index < rows.length; index += 1) {
    for (const key of ['errors', 'technologies', 'libraries']) add(index, key, candidates[index][key][0]);
  }
  for (let index = 0; index < rows.length; index += 1) {
    if (!candidates[index].title) continue;
    rows[index].title = candidates[index].title;
    rows[index].omitted[compact ? 1 : 'title'] = 0;
    if (bytes() > maxBytes) {
      delete rows[index].title;
      rows[index].omitted[compact ? 1 : 'title'] = 1;
    }
  }
  for (let index = 0; index < rows.length; index += 1) {
    for (const key of ['forms', 'paths', 'queryParameterNames']) add(index, key, candidates[index][key][0]);
  }
  for (let round = 1; round < 8; round += 1) {
    for (let index = 0; index < rows.length; index += 1) {
      for (const key of ['errors', 'technologies', 'libraries', 'forms', 'paths', 'queryParameterNames']) {
        add(index, key, candidates[index][key][round]);
      }
    }
  }
  return { pages: rows, bytes: bytes(), compact };
}
const evidenceId = (prefix, value) => prefix + '-' + createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
const eventIdentifier = value => typeof value === 'string'
  && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) ? value : undefined;
const eventIdentifiers = (value, limit) => Array.isArray(value)
  ? value.slice(0, limit).map(eventIdentifier).filter(Boolean) : undefined;
const eventCount = value => Number.isSafeInteger(value) && value >= 0 ? value : undefined;
function eventMetadataText(value, maxBytes, { asset = false } = {}) {
  if (typeof value !== 'string' || !value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) return undefined;
  let text = value.trim();
  if (asset) {
    if (/^https?:\/\//iu.test(text)) {
      try { text = new URL(text).pathname; } catch { return undefined; }
    }
    // An event only needs the affected location, never query values or fragments.
    text = text.split(/[?#]/u, 1)[0];
  }
  return utf8Prefix(safeSourceExcerpt(text), maxBytes) || undefined;
}
export function projectGeneralEvent(event, limits) {
  const stage = eventIdentifier(event.stage) ?? 'unknown';
  const request = {};
  const response = {};
  for (const key of ['hypothesisId', 'probeId', 'tool']) {
    const value = eventIdentifier(event[key]);
    if (value) request[key] = value;
  }
  for (const [key, limit] of [['hypothesisIds', 128], ['probeIds', limits.maxProbes]]) {
    const values = eventIdentifiers(event[key], limit);
    if (values) request[key] = values;
  }
  if (Array.isArray(event.hypothesisSummaries)) request.hypothesisSummaries = event.hypothesisSummaries
    .slice(0, 32).filter(record)
    .map(item => ({ id: eventIdentifier(item.id),
      category: eventMetadataText(item.category, 128),
      asset: eventMetadataText(item.asset, 256, { asset: true }) }))
    .filter(item => item.id && item.category && item.asset);
  if (Array.isArray(event.probeLinks)) request.probeLinks = event.probeLinks
    .slice(0, limits.maxProbes)
    .map(link => ({ probeId: eventIdentifier(link?.probeId),
      hypothesisId: eventIdentifier(link?.hypothesisId), tool: eventIdentifier(link?.tool) }))
    .filter(link => link.probeId && link.hypothesisId && link.tool);
  if (typeof event.done === 'boolean') request.done = event.done;
  for (const key of ['status', 'reason', 'stopReason']) {
    const value = eventIdentifier(event[key]);
    if (value) response[key] = value;
  }
  const evidenceIds = eventIdentifiers(event.evidenceIds, limits.maxEvidenceItems);
  if (evidenceIds) response.evidenceIds = evidenceIds;
  if (Array.isArray(event.evidenceSummaries)) response.evidenceSummaries = event.evidenceSummaries
    .slice(0, limits.maxEvidenceItems).filter(record)
    .map(item => ({ id: eventIdentifier(item.id), kind: eventMetadataText(item.kind, 128),
      asset: eventMetadataText(item.asset, 256, { asset: true }) }))
    .filter(item => item.id && item.kind)
    .map(item => item.asset ? item : { id: item.id, kind: item.kind });
  if (record(event.progress)) {
    const progress = {};
    for (const key of ['hypothesisCount', 'probeCount', 'evidenceCount',
      'confirmedProbeCount', 'notReproducedProbeCount', 'inconclusiveProbeCount',
      'blockedProbeCount', 'remainingProbeBudget']) {
      const count = eventCount(event.progress[key]);
      if (count !== undefined) progress[key] = count;
    }
    response.progress = progress;
  }
  if (record(event.coverage)) {
    const coverage = {};
    for (const key of ['totalHypotheses', 'confirmed', 'notReproduced', 'inconclusive', 'notTested']) {
      const count = eventCount(event.coverage[key]);
      if (count !== undefined) coverage[key] = count;
    }
    response.coverage = coverage;
  }
  const rejectedCount = eventCount(event.rejectedCount);
  if (rejectedCount !== undefined) response.rejectedCount = rejectedCount;
  const detail = response.status ?? response.stopReason
    ?? (request.probeId ? '검사 ' + request.probeId : '관측과 판단 기록');
  return { stage, title: '범용 점검 · ' + stage, detail, request, response };
}
async function invokeHook(callback, ...args) {
  if (!callback) return undefined;
  try { return await callback(...args); }
  catch (error) {
    const failure = new Error('Assessment probe authorization or recording failed.');
    failure.code = typeof error?.code === 'string' ? error.code : 'PROBE_HOOK_FAILED';
    failure.fatalProbe = true;
    throw failure;
  }
}

function safePath(value, origin) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 200
    || !value.startsWith('/') || value.startsWith('//') || /[\u0000-\u001f\\#]/u.test(value)) return null;
  let url;
  try { url = new URL(value, origin); } catch { return null; }
  if (url.origin !== origin || url.username || url.password || url.hash
    || url.pathname.includes('..') || /%(?:2f|5c|00)/iu.test(value)) return null;
  if ([...url.searchParams].length > 6
    || [...url.searchParams].some(([key, val]) => key.length > 40 || val.length > 100)) return null;
  return url;
}

async function limitedBody(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (size < MAX_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      const piece = value.subarray(0, MAX_BODY_BYTES - size);
      chunks.push(piece); size += piece.length;
      if (piece.length < value.length) break;
    }
  } finally {
    try { await reader.cancel(); } catch { /* A complete response may already be closed. */ }
  }
  return Buffer.concat(chunks).toString('utf8');
}

function htmlAttribute(attributes, name) {
  const pattern = new RegExp('(?:^|\\s)' + name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'iu');
  const match = pattern.exec(attributes);
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? null;
}

function surfaceFromHtml(html, origin) {
  const links = [];
  const forms = [];
  const hrefPattern = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/giu;
  for (const match of html.matchAll(hrefPattern)) {
    const url = safePath(match[1], origin);
    if (url && !links.includes(url.pathname)) links.push(url.pathname);
    if (links.length >= 24) break;
  }
  const formPattern = /<form\b([^>]*)>/giu;
  for (const match of html.matchAll(formPattern)) {
    const action = htmlAttribute(match[1], 'action') ?? '/';
    const method = htmlAttribute(match[1], 'method')?.toUpperCase() ?? 'GET';
    const url = safePath(action, origin);
    const rest = html.slice(match.index + match[0].length, match.index + match[0].length + 8192);
    const end = rest.search(/<\/form\b|<form\b/iu);
    const body = end < 0 ? rest : rest.slice(0, end);
    const fields = [];
    for (const field of body.matchAll(/<(input|select|textarea)\b([^>]*)>/giu)) {
      const name = htmlAttribute(field[2], 'name');
      if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/u.test(name)) continue;
      const type = field[1].toLowerCase() === 'input'
        ? htmlAttribute(field[2], 'type')?.toLowerCase() ?? 'text' : field[1].toLowerCase();
      if (type.length > 40 || /[\u0000-\u001f\u007f]/u.test(type)) continue;
      fields.push({ name: safeText(name), type: safeText(type) });
      if (fields.length >= 20) break;
    }
    if (url) forms.push({ path: url.pathname, method: method === 'POST' ? 'POST' : 'GET', fields });
    if (forms.length >= 12) break;
  }
  return { links, forms };
}

function responseSummary(path, response, body, origin) {
  const type = utf8Prefix(safeText(response.headers.get('content-type')?.split(';', 1)[0]
    ?? 'unknown'), 120);
  const headers = Object.fromEntries(['content-security-policy', 'x-frame-options',
    'x-content-type-options', 'strict-transport-security'].map(name =>
    [name, response.headers.has(name)]));
  const securityHeaderValues = Object.fromEntries([
    'content-security-policy', 'x-frame-options', 'x-content-type-options',
    'strict-transport-security', 'access-control-allow-origin',
    'access-control-allow-credentials', 'access-control-allow-methods',
  ].flatMap(name => {
    const value = response.headers.get(name);
    return value === null ? [] : [[name, safeHeaderValue(value)]];
  }));
  const surface = type.includes('html') ? surfaceFromHtml(body, origin) : { links: [], forms: [] };
  return { path, status: response.status, contentType: type,
    securityHeaderPresence: headers, securityHeaderValues, ...surface };
}

/**
 * Builds a tool-agnostic AttackRecord from one executed probe: the hypothesis, the tool and its input, and the
 * tool's own bounded evidence. A result that already carries an AttackRecord keeps its exchanges.
 */
export function recordForProbe({ probe, hypothesis, execution, origin, relatedEvidence = [] }) {
  const summaries = items => items.map(({ id, kind, asset, summary }) => ({ id, kind, ...(asset ? { asset } : {}), summary }));
  const info = { goal: 'Decide whether the hypothesis ' + hypothesis.category + ' at ' + hypothesis.asset + ' is valid',
    hypothesis: { id: hypothesis.id, category: hypothesis.category, asset: hypothesis.asset, rationale: hypothesis.rationale },
    tool: probe.tool, input: probe.input, relatedEvidence: summaries(relatedEvidence).slice(-8),
    ...(typeof probe.input?.sessionRole === 'string' ? { session: probe.input.sessionRole } : {}) };
  if (execution.attackRecord) return { ...execution.attackRecord, info: { ...info, ...execution.attackRecord.info } };
  const url = typeof probe.input?.path === 'string' ? new URL(probe.input.path, origin).href : undefined;
  return { schemaVersion: 'attack-record/1', id: probe.id, kind: String(hypothesis.category).slice(0, 64),
    target: { origin }, info,
    request: { method: url ? 'GET' : 'READ', ...(url ? { url } : { file: String(probe.input?.file ?? probe.tool) }),
      headers: {}, body: null },
    response: { status: Number.isInteger(execution.result?.status) ? execution.result.status : null,
      bodyText: JSON.stringify(summaries(execution.evidence ?? [])) } };
}

/**
 * Judges one AttackRecord with the AI verifier and maps the result to the core verdict.
 * The core accepts a non-inconclusive verdict only when it cites this probe's evidence, and rejects an empty reason.
 */
export async function judgeAttackRecord(record, { evidenceId, outDir, sessions = {}, verify = verifyAttack,
  model, env, envFile, signal, browserFactory } = {}) {
  try {
    const directory = outDir ?? await mkdtemp(join(tmpdir(), 'ca3p-verify-'));
    await mkdir(directory, { recursive: true });
    const result = await verify(record, { outDir: directory, sessions, model, env, envFile, signal, browserFactory });
    if (outDir) await writeReportHandoff(result, { outDir: directory });
    const reason = utf8Prefix(String(result.reason ?? ''), 500).trim() || 'verifier_no_reason';
    return ['confirmed', 'not_reproduced'].includes(result.status)
      ? { status: result.status, completed: true, evidenceIds: [evidenceId], reason }
      : { status: 'inconclusive', evidenceIds: [evidenceId], reason };
  } catch (error) {
    if (error?.name === 'AbortError' || error?.fatalProbe) throw error;
    return { status: 'inconclusive', evidenceIds: [evidenceId], reason: 'verifier_failed' };
  }
}

/** Real assessment of registered local targets; tool execution is read-oriented and bounded. */
export function createGeneralRuntime({ fixtureId, targetOrigin, modelId,
  runIdFactory = () => 'general-' + randomUUID(), env = process.env, envFile,
  signal, onModelCall, beforeProbe, afterProbe, caseSnapshot, unavailableInputs = [],
  historyProvider, plannerFactory, fetchImpl = fetch,
  catalogReader = readKnowledgeCatalogReadOnly,
  webParserCollect = collectWebInfo, parserPreview, verificationRoot, verifyAttackImpl = verifyAttack, verifierModel,
  limits = GENERAL_LOOP_BUDGET_DEFAULTS } = {}) {
  if (!Object.hasOwn(FIXTURES, fixtureId)) throw new TypeError('Choose a registered local fixture.');
  if (!MODELS.has(modelId)) throw new TypeError('A registered DeepSeek model is required for a general assessment.');
  if (typeof runIdFactory !== 'function' || typeof fetchImpl !== 'function'
    || typeof catalogReader !== 'function'
    || typeof webParserCollect !== 'function' || typeof verifyAttackImpl !== 'function') {
    throw new TypeError('Invalid general runtime dependency.');
  }
  for (const callback of [onModelCall, beforeProbe, afterProbe, historyProvider, plannerFactory]) {
    if (callback !== undefined && typeof callback !== 'function') throw new TypeError('Invalid general runtime callback.');
  }
  limits = validateGeneralLoopBudget(limits);
  const config = FIXTURES[fixtureId];
  const origin = validateUniversityOrigin(targetOrigin ?? config.origin);
  if (parserPreview && (parserPreview.targetKind !== 'lab' || parserPreview.fixtureId !== fixtureId
    || parserPreview.origin !== origin || !Array.isArray(parserPreview.pages))) {
    throw new TypeError('Parser preview does not match this university run.');
  }
  const previewProjection = modelPreviewPages(parserPreview, origin);
  const preParsedPages = previewProjection.pages;
  const crawl = parserPreview?.crawl;
  const previewCrawl = parserPreview ? {
    maxPages: Number.isInteger(crawl?.maxPages) ? crawl.maxPages : MAX_PREVIEW_PAGES,
    visited: Number.isInteger(crawl?.visited) ? crawl.visited : parserPreview.pages.length,
    queued: Number.isInteger(crawl?.queued) ? crawl.queued : 0,
    truncated: crawl?.truncated === true,
    stopReason: ['page-limit', 'time-limit', 'safety-block', 'candidate-limit',
      'page-content-limit'].includes(crawl?.stopReason)
      ? crawl.stopReason : null,
  } : null;
  const instanceId = randomUUID();
  const listeners = new Set();
  const initial = () => ({ ...emptyRun(), mode: 'local-lab-general', assessmentMode: 'general',
    testProfile: 'general', fixtureId, target: origin,
    coreTargetOrigin: origin, simulated: false, targetContacted: false,
    totalSteps: 1, iterations: 0, modelId, provider: 'deepseek' });
  let run = initial();
  let controller = null;
  let task = null;
  let closed = false;
  // Session cookies stay only in this runtime process. Inventory and reports keep role labels.
  const sessionCookies = new Map();

  function getState() {
    if (ACTIVE.has(run.status)) run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    return structuredClone({ run, mode: run.mode, instanceId,
      lab: { available: true, generalSupported: true, generalAvailable: true, model: modelId, provider: 'deepseek' } });
  }
  function publish() {
    const state = getState();
    for (const listener of listeners) {
      try { listener(structuredClone(state)); } catch { /* Listener failures cannot stop an assessment. */ }
    }
  }
  function appendEvent(data) {
    const event = { id: run.id + ':event-' + (run.events.length + 1), time: new Date().toISOString(),
      module: 'agent', type: 'info', source: 'agent/general-assessment',
      simulated: false, targetContacted: run.targetContacted, ...data };
    run.events.push(event);
    run.snapshots.agent = event;
    run.step = run.events.length;
    run.totalSteps = Math.max(1, run.step);
    publish();
  }
  async function checkedRequest(url, { id, iteration = 0, tool = 'http_get', session = 'public',
    method = 'GET', headers, signal: requestSignal } = {}) {
    const probe = { id, probeId: id, iteration, tool, session, method, url: url.href };
    const reservation = await invokeHook(beforeProbe, probe);
    let summary;
    try {
      const timeout = AbortSignal.timeout(5000);
      const combined = requestSignal ? AbortSignal.any([requestSignal, timeout]) : timeout;
      const response = await fetchImpl(url, { method, headers, redirect: 'manual', signal: combined });
      run.targetContacted = true;
      const body = method === 'HEAD' ? '' : await limitedBody(response);
      summary = responseSummary(url.pathname + url.search, response, body, url.origin);
      return summary;
    } finally {
      await invokeHook(afterProbe, probe, { status: summary?.status ?? null,
        evidenceId: summary ? evidenceId('http', id) : null }, reservation);
    }
  }
  async function verifyFixtureIdentity(allowedOrigin, currentSignal) {
    const checks = [
      { id: 'identity-home', path: '/', expect: body => body.includes(config.name) },
      { id: 'identity-api', path: '/api/search?q=ca3p-identity',
        expect: body => {
          try { return JSON.parse(body)?.site === config.name; } catch { return false; }
        } },
    ];
    for (const check of checks) {
      currentSignal?.throwIfAborted();
      const url = new URL(check.path, allowedOrigin);
      const probe = { id: check.id, probeId: check.id, iteration: 0, tool: 'fixture_identity',
        session: 'public', method: 'GET', url: url.href };
      const reservation = await invokeHook(beforeProbe, probe);
      let response;
      try {
        const timeout = AbortSignal.timeout(5000);
        response = await fetchImpl(url, { method: 'GET', redirect: 'manual',
          signal: currentSignal ? AbortSignal.any([currentSignal, timeout]) : timeout });
        run.targetContacted = true;
        const body = await limitedBody(response);
        if (response.status !== 200 || !check.expect(body)) {
          throw Object.assign(new Error('The target does not match the registered university fixture.'),
            { code: 'FIXTURE_IDENTITY_MISMATCH' });
        }
      } finally {
        await invokeHook(afterProbe, probe, { status: response?.status ?? null }, reservation);
      }
    }
  }
  function fixedSessionSpecs() {
    const rolePage = config.siteKey === 'daehan' ? '/admissions/partner' : '/staff/mobile';
    const owner = config.siteKey === 'daehan'
      ? { account: 'partner1', password: 'Partner2026' }
      : { account: 'staff1', password: 'Staff2026' };
    return [
      { role: 'student', account: 'student1', password: 'Welcome2026',
        paths: ['/mypage', rolePage] },
      { role: 'owner', ...owner, paths: [rolePage] },
      { role: 'admin', account: 'admin', password: 'admin1234', paths: ['/admin'] },
    ];
  }
  async function loginForInventory(allowedOrigin, spec, currentSignal) {
    const path = '/login';
    const url = new URL(path, allowedOrigin);
    const probe = { id: 'inventory-login-' + spec.role, probeId: 'inventory-login-' + spec.role,
      iteration: 1, tool: 'fixture_session', session: spec.role, method: 'POST', url: url.href };
    const reservation = await invokeHook(beforeProbe, probe);
    let response;
    try {
      const timeout = AbortSignal.timeout(5000);
      const body = new URLSearchParams({ username: spec.account, password: spec.password });
      response = await fetchImpl(url, { method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body, signal: currentSignal ? AbortSignal.any([currentSignal, timeout]) : timeout });
      run.targetContacted = true;
      const cookie = response.headers.get('set-cookie')?.split(';', 1)[0]?.trim();
      await limitedBody(response);
      const statusOkay = response.status === 302
        && response.headers.get('location') === '/mypage';
      if (!statusOkay || !cookie || cookie.length > 512 || /[\r\n]/u.test(cookie)
        || !/^[A-Za-z][A-Za-z0-9_-]{0,39}=[A-Za-z0-9._~-]{8,500}$/u.test(cookie)) {
        return null;
      }
      return cookie;
    } finally {
      await invokeHook(afterProbe, probe, { status: response?.status ?? null }, reservation);
    }
  }
  async function authenticatedObservation(allowedOrigin, currentSignal) {
    const pages = [];
    const evidence = [];
    for (const spec of fixedSessionSpecs()) {
      currentSignal?.throwIfAborted();
      let cookie;
      try { cookie = await loginForInventory(allowedOrigin, spec, currentSignal); }
      catch (error) {
        if (currentSignal?.aborted || error?.fatalProbe) throw error;
      }
      if (!cookie) {
        evidence.push({ id: evidenceId('auth-error', spec.role),
          source: 'fixture-session/' + fixtureId, kind: 'unavailable',
          asset: 'role:' + spec.role,
          summary: 'Fixed demo ' + spec.role + ' session could not be prepared; authenticated surfaces remain unobserved.' });
        continue;
      }
      sessionCookies.set(spec.role, cookie);
      for (const [index, path] of spec.paths.entries()) {
        const url = safePath(path, allowedOrigin);
        if (!url) continue;
        try {
          const page = await checkedRequest(url, { id: 'inventory-auth-' + spec.role + '-' + index,
            tool: 'http_get', session: spec.role, headers: { cookie }, iteration: 1,
            signal: currentSignal });
          const recordPage = { ...page, sessionRole: spec.role };
          pages.push(recordPage);
          evidence.push({ id: evidenceId('auth-page', spec.role + ':' + path),
            source: 'http/' + fixtureId + '/role:' + spec.role,
            kind: 'authenticated-surface', asset: path,
            summary: 'Fixed demo ' + spec.role + ' GET ' + path + ' returned HTTP ' + page.status
              + '; response body and session cookie were not retained.' });
        } catch (error) {
          if (currentSignal?.aborted || error?.fatalProbe) throw error;
          pages.push({ path, sessionRole: spec.role, status: null, error: 'request_unavailable' });
          evidence.push({ id: evidenceId('auth-page-error', spec.role + ':' + path),
            source: 'http/' + fixtureId + '/role:' + spec.role,
            kind: 'unavailable', asset: path,
            summary: 'Fixed demo ' + spec.role + ' GET ' + path + ' could not be observed.' });
        }
      }
    }
    return { pages, evidence };
  }
  async function sourceReferences() {
    const entries = [];
    try {
      const raw = await readFile(new URL(config.files[config.manifest], import.meta.url), 'utf8');
      if (config.manifest.endsWith('.json')) {
        const parsed = JSON.parse(raw);
        const dependencies = { ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) };
        entries.push({ source: 'repository/' + config.manifest, status: 'available',
          kind: 'dependency-manifest', dependencies: Object.entries(dependencies).slice(0, 50)
            .map(([name, version]) => ({ name, version: String(version).slice(0, 40) })) });
      } else {
        const names = [...raw.matchAll(/<artifactId>([^<]{1,100})<\/artifactId>/gu)]
          .slice(0, 50).map(match => match[1]);
        entries.push({ source: 'repository/' + config.manifest, status: 'available',
          kind: 'dependency-manifest', artifactIds: names });
      }
    } catch {
      entries.push({ source: 'repository/' + config.manifest, status: 'unavailable',
        reason: 'manifest_read_failed' });
    }
    if (caseSnapshot?.caseRevisions) entries.push({ source: 'casper-db/case-snapshot',
      status: 'available', kind: 'historical-reference', currentRunVerified: false,
      revisions: caseSnapshot.caseRevisions.slice(0, 50),
      summaries: Array.isArray(caseSnapshot.caseSummaries)
        ? caseSnapshot.caseSummaries.slice(0, 30).map(item => ({
          caseId: safeText(item.caseId ?? '').slice(0, 100),
          revision: item.revision,
          title: safeText(item.title ?? '').slice(0, 160),
          vulnerabilityType: safeText(item.vulnerabilityType ?? '').slice(0, 80),
          endpoint: safeText(item.endpoint ?? '').slice(0, 200),
          method: safeText(item.method ?? '').slice(0, 12),
          description: safeText(item.description ?? '').slice(0, 300),
          status: item.status, patchStatus: item.patchStatus,
        })) : [],
      ...(!Array.isArray(caseSnapshot.caseSummaries)
        ? { summaryStatus: 'case_summaries_not_exposed' } : {}) });
    else entries.push({ source: 'casper-db/case-snapshot', status: 'unavailable',
      reason: unavailableInputs.includes('casper-db') ? 'snapshot_unavailable' : 'not_applicable' });
    if (typeof caseSnapshot?.path !== 'string') {
      entries.push({ source: CATALOG_SOURCE, status: 'unavailable',
        reason: unavailableInputs.includes('casper-db') ? 'snapshot_unavailable'
          : caseSnapshot ? 'snapshot_missing_path' : 'snapshot_missing' });
    } else try {
      // Read the same frozen database that supplied the historical-case context.
      const catalog = await catalogReader({ databasePath: caseSnapshot.path,
        python: env.CASPER_DB_PYTHON });
      if (catalog?.schemaVersion !== 'casper-attack-catalog-1'
        || !Array.isArray(catalog.patterns)) throw new Error('Invalid attack catalog.');
      if (catalog.status === 'not_configured') {
        entries.push({ source: CATALOG_SOURCE, status: 'unavailable',
          reason: 'catalog_not_configured' });
      } else {
        if (catalog.status !== 'ok' || catalog.provenance?.source !== 'casper-db.attack_catalog'
          || !/^[a-f0-9]{64}$/u.test(catalog.provenance.sha256)) {
          throw new Error('Invalid attack catalog provenance.');
        }
        entries.push({ source: CATALOG_SOURCE, status: 'available',
          kind: 'draft-advisory', catalogVersion: catalog.schemaVersion,
          sha256: catalog.provenance.sha256, currentRunVerified: false,
          entries: catalog.patterns.filter(item => item?.definition?.target?.application === fixtureId)
            .slice(0, 20).map(item => ({
              patternId: safeText(item.pattern_id ?? '').slice(0, 100),
              revision: Number.isSafeInteger(item.revision) ? item.revision : null,
              category: safeText(item.definition.vulnType ?? '').slice(0, 80),
              endpoint: safeText(item.definition.target.endpoint ?? '').slice(0, 200),
              payloadIds: (Array.isArray(item.definition.payloads) ? item.definition.payloads : [])
                .slice(0, 20).map(payload => safeText(payload?.payloadId ?? '').slice(0, 100)),
            })) });
      }
    } catch {
      entries.push({ source: CATALOG_SOURCE, status: 'unavailable',
        reason: 'catalog_read_failed' });
    }
    try {
      const history = await historyProvider?.();
      entries.push({ source: 'run-store/previous-runs',
        status: Array.isArray(history) ? 'available' : 'unavailable',
        kind: 'historical-reference', currentRunVerified: false,
        runs: Array.isArray(history) ? history.slice(0, 20).map(item => ({
          runId: safeText(item.runId ?? 'unknown').slice(0, 128),
          mode: safeText(item.mode ?? 'unknown').slice(0, 80),
          status: safeText(item.status ?? 'unknown').slice(0, 40),
          modelId: safeText(item.modelId ?? 'unknown').slice(0, 80),
          completedAt: item.completedAt ?? null,
          findings: Array.isArray(item.findings) ? item.findings.slice(0, 20).map(finding => ({
            category: safeText(finding.category ?? 'unknown').slice(0, 120),
            status: safeText(finding.status ?? 'unknown').slice(0, 40),
            evidenceCount: Number.isSafeInteger(finding.evidenceCount)
              ? finding.evidenceCount : null,
          })) : [],
        })) : [],
        ...(!Array.isArray(history) ? { reason: 'history_provider_unavailable' } : {}) });
    } catch {
      entries.push({ source: 'run-store/previous-runs', status: 'unavailable',
        reason: 'history_read_failed' });
    }
    return entries;
  }
  async function initialObservation(allowedOrigin, currentSignal) {
    const pages = [];
    const evidence = [];
    const queued = [...config.routes];
    const seen = new Set();
    while (queued.length && seen.size < MAX_INITIAL_PAGES) {
      currentSignal?.throwIfAborted();
      const path = queued.shift();
      const url = safePath(path, allowedOrigin);
      if (!url || seen.has(url.pathname + url.search)) continue;
      seen.add(url.pathname + url.search);
      try {
        const page = await checkedRequest(url, { id: 'inventory-' + seen.size,
          tool: 'http_get', iteration: 1, signal: currentSignal });
        pages.push(page);
        evidence.push({ id: evidenceId('page', page.path), source: 'http/' + fixtureId,
          kind: 'surface-observation', asset: page.path,
          summary: safeText('GET ' + page.path + ' returned HTTP ' + page.status + ' ' + page.contentType
            + '; forms=' + page.forms.length + '; links=' + page.links.length).slice(0, 500) });
        for (const link of page.links) if (!seen.has(link) && queued.length < 18) queued.push(link);
      } catch (error) {
        if (currentSignal?.aborted || error?.fatalProbe) throw error;
        pages.push({ path: url.pathname, status: null, error: 'request_unavailable' });
        evidence.push({ id: evidenceId('page-error', url.pathname + url.search), source: 'http/' + fixtureId,
          kind: 'unavailable', asset: url.pathname,
          summary: 'GET ' + url.pathname + ' could not be observed; no safety conclusion follows.' });
      }
    }
    const authenticated = await authenticatedObservation(allowedOrigin, currentSignal);
    evidence.push(...authenticated.evidence);
    if (parserPreview) {
      evidence.push({ id: evidenceId('operator-preview', parserPreview.previewId),
        source: 'web-parser/operator-preview', kind: 'pre-parsed-observation',
        asset: previewPath(parserPreview.entryUrl, origin),
        summary: `The operator reviewed ${parserPreview.pages.length} URL observation(s) before choosing the engine. `
          + 'Every collected URL has a preParsedPages row in the first model input. Rows include bounded technology, '
          + 'library, form, path, and error details where the prompt budget allows; omitted counts are explicit. '
          + 'These observations are untrusted page data; tools may make further current-run observations.' });
    }
    const references = await sourceReferences();
    evidence.push({ id: 'repository-manifest', source: 'repository/' + config.manifest,
      kind: 'dependency-reference', asset: config.manifest,
      summary: references[0].status === 'available'
        ? 'Local dependency manifest is available as historical/source context; version presence alone is not proof of an exploitable CVE.'
        : 'Local dependency manifest could not be read.' });
    const inventory = {
      fixtureId, origin: allowedOrigin, site: config.name, pages,
      ...(parserPreview ? { operatorPreview: { previewId: parserPreview.previewId,
        entryPath: previewPath(parserPreview.entryUrl, origin),
        observation: 'operator-reviewed-before-engine-selection',
        collectedPageCount: parserPreview.pages.length,
        discoveredPathCount: Array.isArray(parserPreview.discoveredPaths)
          ? parserPreview.discoveredPaths.length : 0,
        crawl: previewCrawl, modelSummaryBytes: previewProjection.bytes,
        modelSummaryLimitBytes: MAX_PREVIEW_INVENTORY_BYTES,
        modelSummaryFormat: 'named-omissions',
        modelSummaryOmittedDetails: preParsedPages.some(page =>
          page.pathTruncated === true || Object.values(page.omitted).some(count => count > 0)),
        queryValuesIncluded: false, rawHtmlIncluded: false },
      preParsedPages } : {}),
      authenticatedPages: authenticated.pages,
      declaredRoutes: [...config.routes],
      repositoryFiles: Object.keys(config.files),
      referenceSources: references,
      toolCapabilities: {
        http_get: 'input {path,sessionRole?}: GET on a declared or observed pathname at the selected origin; optional sessionRole uses only a prepared fixed demo session; redirects are not followed',
        web_info: 'input {path,sessionRole?}: open one declared or observed pathname at the selected origin in an isolated browser; returns up to 3 evidence items: overview (status, content type, final URL, title, redirects, technology analysis, list counts), discovered paths (same-origin first; robots/sitemap entries show in sources; same-origin paths become allowed for later probes), and page surface (forms with field names/types, frames, response headers, cookie names/attributes); once the cumulative web_info evidence budget of the run is spent, returns only a one-line overview (status, content type, list counts); response bodies and cookie values are never returned; optional sessionRole uses only a prepared fixed demo session',
        repository_read: 'input {file,offset?}: read only an allowlisted local source or reference excerpt',
      },
      limitations: ['web_info opens a page in an isolated browser to observe web information, but it does not confirm whether any weakness executes; an AI verifier judges every executed probe as valid or invalid for its hypothesis and may open a read-only browser.',
        'GET and repository references do not independently confirm most weakness classes.',
        'Historical cases and source reports are context, not current-run proof.',
        'Initial public discovery is bounded to ' + MAX_INITIAL_PAGES + ' routes; other declared routes require a model probe.',
        ...(parserPreview ? ['The first model input contains one bounded summary row per collected parser URL. Query values and raw HTML are excluded; each row gives counts for any omitted model-summary details, and operatorPreview.crawl reports incomplete collection.'] : []),
        'Authenticated observation uses only fixed demo accounts and records status and surface metadata, never response bodies.'],
    };
    return { inventory, evidence };
  }
  async function execute(allowedOrigin, currentSignal) {
    const planner = plannerFactory
      ? await plannerFactory({ modelId, env, envFile, signal: currentSignal })
      : createGeneralModelPlannerFromEnv({ env: { ...env, DEEPSEEK_MODEL: modelId }, envFile });
    if (!planner || typeof planner.propose !== 'function') throw new TypeError('General planner is unavailable.');
    let observed = false;
    let inventory;
    const probeHypotheses = new Map();
    const failedModelCalls = [];
    let evidenceCount = 0;
    // Additional web_info evidence has its own budget. The planner reduces
    // optional preview detail if both sources later fill the prompt.
    let webInfoBytes = 0;
    const allowedPaths = new Set(config.routes.map(path => new URL(path, allowedOrigin).pathname));
    if (parserPreview) {
      for (const value of [...parserPreview.pages.map(page => page.url),
        ...(parserPreview.discoveredPaths ?? []),
        ...parserPreview.pages.flatMap(page => (page.paths ?? []).map(path => path.url))]) {
        try {
          const url = new URL(value);
          if (url.origin === allowedOrigin) {
            const safe = safePath(url.pathname + url.search, allowedOrigin);
            if (safe) allowedPaths.add(safe.pathname);
          }
        } catch { /* Ignore malformed paths from observed pages. */ }
      }
    }
    const extendPaths = page => {
      for (const path of [...(page.links ?? []), ...(page.forms ?? []).map(form => form.path)]) {
        const url = safePath(path, allowedOrigin);
        if (url) allowedPaths.add(url.pathname);
      }
    };
    const observer = { async observe() {
      if (observed) return { inventory, evidence: [] };
      const initial = await initialObservation(allowedOrigin, currentSignal);
      observed = true; inventory = { ...initial.inventory, attackTool: {
        transport: 'http-json', flow: ['agent', 'attack-tool', 'guardrail', 'executor'],
        endpoints: attackTool.endpoints, templates: attackTool.templates,
        templateExecution: 'Only the registered runtime policy can enable a matching template; this run exposes reference templates.',
      } };
      [...inventory.pages, ...inventory.authenticatedPages].forEach(extendPaths);
      return { ...initial, inventory };
    } };
    const policy = { async authorize({ probe, hypothesis }) {
      // Bind the model hypothesis before crossing the daemon boundary. The daemon
      // rechecks the host's policy with this trusted association on every call.
      if (hypothesis) probeHypotheses.set(probe.id, structuredClone(hypothesis));
      if (probe.tool === 'http_get' || probe.tool === 'web_info') {
        const input = probe.input;
        if (!record(input) || Object.keys(input).some(key => !['path', 'sessionRole'].includes(key))
          || input.sessionRole !== undefined && (typeof input.sessionRole !== 'string'
            || !sessionCookies.has(input.sessionRole))) {
          return { allowed: false, reason: 'invalid_' + probe.tool + '_input' };
        }
        const url = safePath(probe.input.path, allowedOrigin);
        return { allowed: !!url && allowedPaths.has(url.pathname), reason: 'path_out_of_scope' };
      }
      if (probe.tool === 'repository_read') return {
        allowed: Object.hasOwn(config.files, probe.input.file)
          && (probe.input.offset === undefined || Number.isSafeInteger(probe.input.offset)
            && probe.input.offset >= 0 && probe.input.offset <= 32 * 1024),
        reason: 'file_out_of_scope' };
      return { allowed: false, reason: 'tool_unavailable' };
    } };
    const executor = { async execute({ probe, signal: executionSignal }) {
      const probeSignal = executionSignal
        ? AbortSignal.any([currentSignal, executionSignal].filter(Boolean)) : currentSignal;
      if (probe.tool === 'http_get') {
        const url = safePath(probe.input.path, allowedOrigin);
        const sessionRole = probe.input.sessionRole;
        const cookie = sessionRole === undefined ? null : sessionCookies.get(sessionRole);
        try {
          const result = await checkedRequest(url, { id: probe.id, iteration: run.iterations,
            tool: probe.tool, session: sessionRole ?? 'public',
            ...(cookie ? { headers: { cookie } } : {}), signal: probeSignal });
          extendPaths(result);
          const labelledResult = sessionRole === undefined ? result : { ...result, sessionRole };
          return { kind: 'http_get', result: labelledResult, evidence: [{ id: evidenceId('probe', probe.id),
            source: 'http/' + fixtureId + (sessionRole ? '/role:' + sessionRole : ''),
            kind: 'http-response', asset: result.path,
            summary: utf8Prefix(safeText('GET ' + result.path
              + (sessionRole ? ' as fixed ' + sessionRole : '') + ': HTTP ' + result.status
              + ' ' + result.contentType + '; security headers '
              + JSON.stringify(result.securityHeaderPresence) + '; values '
              + JSON.stringify(result.securityHeaderValues)), 1200) }] };
        } catch (error) {
          if (probeSignal?.aborted || error?.fatalProbe) throw error;
          return { kind: 'http_get', error: 'request_unavailable',
            evidence: [{ id: evidenceId('probe', probe.id), source: 'http/' + fixtureId,
              kind: 'unavailable', asset: probe.input.path,
              summary: 'HTTP read failed or timed out; the hypothesis remains unverified.' }] };
        }
      }
      if (probe.tool === 'web_info') {
        const url = safePath(probe.input.path, allowedOrigin);
        const sessionRole = probe.input.sessionRole;
        const cookie = sessionRole === undefined ? null : sessionCookies.get(sessionRole);
        // The core ends the run when one execution returns more evidence than it has room for.
        const remaining = limits.maxEvidenceItems - evidenceCount;
        // A page can reflect a fixed session value (header, URL) or carry URL userinfo; keep both out.
        const evidenceText = value => [...sessionCookies.values()].reduce(
          (text, pair) => text.replaceAll(pair.slice(pair.indexOf('=') + 1), '[redacted]'),
          safeText(value).replace(/\/\/[^/@\s]+:[^/@\s]+@/gu, '//[redacted]@'));
        // Session cookies are stored as a `name=value` pair; web-parser wants { name, value }.
        const cookiePair = cookie ? [{ name: cookie.slice(0, cookie.indexOf('=')),
          value: cookie.slice(cookie.indexOf('=') + 1) }] : null;
        const probeRecord = { id: probe.id, probeId: probe.id, iteration: run.iterations,
          tool: probe.tool, session: sessionRole ?? 'public', method: 'GET', url: url.href };
        const reservation = await invokeHook(beforeProbe, probeRecord);
        let observedStatus = null;
        const bytes = items => items.reduce((sum, item) => sum + Buffer.byteLength(JSON.stringify(item), 'utf8'), 0);
        try {
          const { info, summary } = await webParserCollect(url.href, {
            ...(cookiePair ? { cookies: cookiePair } : {}), signal: probeSignal });
          observedStatus = info.navigation.status ?? null;
          // Extend scope with the same-origin http(s) paths web-parser discovered (like extendPaths).
          for (const entry of info.paths ?? []) {
            if (!entry?.sameOrigin || entry.wildcard) continue;
            let discovered;
            try { discovered = new URL(entry.url); } catch { continue; }
            if (discovered.origin !== allowedOrigin) continue;
            const safe = safePath(discovered.pathname + discovered.search, allowedOrigin);
            if (safe) allowedPaths.add(safe.pathname);
          }
          const options = { idBase: evidenceId('probe', probe.id), sessionRole, remaining,
            source: 'web-parser/' + fixtureId + (sessionRole ? '/role:' + sessionRole : ''),
            asset: url.pathname + url.search, safeText: evidenceText, safeHeaderValue };
          let evidence = evidenceFromTargetInfo(info, options);
          // The planner resends all evidence each call; past the budget only a one-line overview fits.
          if (webInfoBytes + bytes(evidence) > WEB_INFO_EVIDENCE_BUDGET_BYTES) {
            evidence = evidenceFromTargetInfo(info, { ...options, mode: 'minimal' });
          }
          webInfoBytes += bytes(evidence);
          return { kind: 'web_info', result: summary, evidence };
        } catch (error) {
          if (probeSignal?.aborted || error?.fatalProbe) throw error;
          const evidence = [{ id: evidenceId('probe', probe.id), source: 'web-parser/' + fixtureId,
            kind: 'unavailable', asset: probe.input.path,
            summary: 'web_info browser observation failed or timed out; the hypothesis remains unverified.' }]
            .slice(0, remaining);
          webInfoBytes += bytes(evidence);
          return { kind: 'web_info', error: 'request_unavailable', evidence };
        } finally {
          await invokeHook(afterProbe, probeRecord, { status: observedStatus,
            evidenceId: evidenceId('probe', probe.id) }, reservation);
        }
      }
      if (probe.tool === 'repository_read') {
        const file = probe.input.file;
        const offset = probe.input.offset ?? 0;
        try {
          const content = await readFile(new URL(config.files[file], import.meta.url), 'utf8');
          const excerpt = safeSourceExcerpt(content.slice(offset, offset + 1300));
          return { kind: 'repository_read', evidence: [{ id: evidenceId('probe', probe.id),
            source: 'repository/' + file, kind: 'source-excerpt', asset: file,
            summary: utf8Prefix('Reference excerpt at byte/character offset ' + offset + ': ' + excerpt, 1800) }] };
        } catch {
          return { kind: 'repository_read', evidence: [{ id: evidenceId('probe', probe.id),
            source: 'repository/' + file, kind: 'unavailable', asset: file,
            summary: 'Requested local reference could not be read.' }] };
        }
      }
      return { kind: probe.tool, evidence: [] };
    } };
    // Evidence already judged per hypothesis, so each verdict covers everything known so far.
    const judgedEvidence = new Map();
    const verifier = { async verify({ hypothesis, probe, execution, evidence, signal }) {
      const id = execution.evidence[0].id;
      const own = new Set(execution.evidence.map(item => item.id));
      const earlier = judgedEvidence.get(hypothesis.id) ?? [];
      const cited = evidence.filter(item => hypothesis.evidenceIds.includes(item.id) && !own.has(item.id));
      judgedEvidence.set(hypothesis.id, [...earlier, ...execution.evidence]);
      const sessions = Object.fromEntries([...sessionCookies].map(([role, cookie]) => [role,
        [{ name: cookie.slice(0, cookie.indexOf('=')), value: cookie.slice(cookie.indexOf('=') + 1) }]]));
      // Every executed result goes to the AI verifier, which decides valid or invalid for the hypothesis.
      return judgeAttackRecord(recordForProbe({ probe, hypothesis, execution, origin: allowedOrigin,
        relatedEvidence: [...cited, ...earlier] }), { evidenceId: id, sessions, verify: verifyAttackImpl,
        outDir: verificationRoot ? join(verificationRoot, probe.id) : undefined, model: verifierModel,
        env, envFile, signal });
    } };
    const wrappedPlanner = { async propose(context) {
      let plan;
      try {
        try { plan = await planner.propose(context); }
        catch (error) {
          if (!parserPreview || error?.code !== 'GENERAL_PLANNER_CONTEXT_TOO_LARGE') throw error;
          // The first inventory is detailed. As later hypotheses and evidence
          // accumulate, keep every URL while reducing only optional row detail.
          for (const budgetBytes of PREVIEW_RETRY_BUDGETS) {
            const projection = modelPreviewPages(parserPreview, origin, budgetBytes);
            const reduced = { ...context, inventory: { ...context.inventory,
              preParsedPages: projection.pages,
              operatorPreview: { ...context.inventory.operatorPreview,
                modelSummaryBytes: projection.bytes, modelSummaryLimitBytes: budgetBytes,
                modelSummaryFormat: projection.compact ? 'compact-omissions' : 'named-omissions',
                ...(projection.compact ? { modelSummaryOmittedFields: PREVIEW_OMISSION_FIELDS } : {}),
                modelSummaryOmittedDetails: projection.pages.some(page =>
                  page.pathTruncated === true || Object.values(page.omitted).some(count => count > 0)) } } };
            try {
              plan = await planner.propose(reduced);
              // The report and following iterations must describe the inventory
              // the model actually received, not the over-budget first attempt.
              context.inventory.preParsedPages = projection.pages;
              context.inventory.operatorPreview = reduced.inventory.operatorPreview;
              inventory = { ...inventory, preParsedPages: projection.pages,
                operatorPreview: reduced.inventory.operatorPreview };
              break;
            }
            catch (retryError) {
              if (retryError?.code !== 'GENERAL_PLANNER_CONTEXT_TOO_LARGE') throw retryError;
              error = retryError;
            }
          }
          if (!plan) throw error;
        }
      }
      catch (error) {
        const attempts = planner instanceof generalPlanner.GeneralModelPlanner
          && Array.isArray(error?.modelAttempts) ? error.modelAttempts : [];
        for (const attempt of attempts) {
          failedModelCalls.push(attempt);
          await onModelCall?.(attempt);
        }
        if (attempts.length && error?.code === 'GENERAL_PLANNER_SCHEMA_ERROR') throw error;
        const failed = { provider: 'deepseek', requestedModel: modelId,
          status: 'failed', iteration: context.iteration };
        if (planner instanceof generalPlanner.GeneralModelPlanner
          && error?.code === 'GENERAL_PLANNER_SCHEMA_ERROR'
          && typeof error.message === 'string' && error.message.length <= 200
          && !/[\r\n]/u.test(error.message)) {
          // The planner's own schema errors contain fixed field names, never model output.
          failed.validationError = error.message;
        }
        if (error?.code === 'DEEPSEEK_INCOMPLETE_RESPONSE'
          && ['length', 'content_filter', 'tool_calls', 'insufficient_system_resource'].includes(error.finishReason)) {
          failed.finishReason = error.finishReason;
        }
        failedModelCalls.push(failed);
        await onModelCall?.(failed);
        throw error;
      }
      const trustedPlanner = planner instanceof generalPlanner.GeneralModelPlanner;
      const attempts = trustedPlanner && Array.isArray(plan?.modelAttempts)
        ? plan.modelAttempts : [plan?.modelMetadata];
      for (const attempt of attempts) if (attempt) await onModelCall?.(attempt);
      if (!trustedPlanner && plan && typeof plan === 'object' && Object.hasOwn(plan, 'modelAttempts')) {
        plan = { ...plan };
        delete plan.modelAttempts;
      }
      return plan;
    } };
    const availableTools = ['http_get', 'web_info', 'repository_read'];
    // Each vulnerability worker receives its own authenticated logical client.
    // The daemon owns the transport, while target and policy authority remain in
    // this runtime; model input cannot install an executor or change its scope.
    const attackTool = await createAttackToolBridge({ runId: run.id, targetOrigin: allowedOrigin,
      authorize: ({ probe }) => policy.authorize({ probe,
        hypothesis: probeHypotheses.get(probe.id) }),
      execute: input => executor.execute(input),
    });
    const toolExecutor = { execute: ({ probe }) => attackTool.execute({ probe,
      hypothesis: probeHypotheses.get(probe.id), signal: currentSignal }) };
    let report;
    try {
      ({ report } = await runGeneralAssessment({
        target: { fixtureId, origin: allowedOrigin }, observer, planner: wrappedPlanner,
        policy, executor: toolExecutor, verifier, availableTools, limits, signal: currentSignal,
        onEvent: async event => {
          // The core reports its stored evidence count (initial observation included) before each probe.
          evidenceCount = event.progress?.evidenceCount ?? evidenceCount;
          const iteration = eventCount(event.iteration) ?? run.iterations;
          run.iterations = Math.max(run.iterations, iteration);
          appendEvent({ ...projectGeneralEvent(event, limits), iteration });
        },
      }));
      report.attackTool = { transport: 'http-json',
        flow: ['agent', 'attack-tool', 'guardrail', 'executor'],
        endpoints: attackTool.endpoints, agentIds: [...attackTool.agentIds],
        templateIds: attackTool.templates.map(template => template.templateId),
        metrics: attackTool.metrics() };
    } finally {
      await attackTool.close();
      probeHypotheses.clear();
    }
    report.runId = run.id;
    report.modelCalls.push(...failedModelCalls);
    report.fixtureId = fixtureId;
    if (parserPreview) report.parserPreview = parserPreview;
    report.targetContacted = run.targetContacted;
    report.scope = { fixtureId, origin: allowedOrigin,
      methods: ['GET'],
      sessionBootstrap: 'POST /login using fixed demo accounts',
      toolIds: availableTools, allowedPaths: [...allowedPaths].sort(), ...limits };
    return report;
  }
  async function runTask() {
    try {
      const runSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      runSignal.throwIfAborted();
      const allowedOrigin = origin;
      run.target = allowedOrigin; run.coreTargetOrigin = allowedOrigin;
      await verifyFixtureIdentity(allowedOrigin, runSignal);
      run.status = 'running'; publish();
      const report = await execute(allowedOrigin, runSignal);
      run.report = report;
      run.status = report.status === 'cancelled' ? 'stopped' : report.status;
      run.error = report.status === 'failed' ? report.error?.code ?? 'GENERAL_ASSESSMENT_FAILED' : undefined;
      run.reviewItems = report.findings.map(finding => ({
        id: run.id + ':' + finding.id, title: finding.category + ' · ' + finding.asset,
        description: finding.rationale, evidenceId: finding.evidenceIds[0] ?? null,
        evidence: finding.evidenceIds.join(', '), vulnerabilityConfirmed: finding.status === 'confirmed',
        status: finding.status, simulated: false,
      }));
    } catch (error) {
      run.status = controller.signal.aborted || signal?.aborted ? 'stopped' : 'failed';
      run.error = run.status === 'stopped' ? '사용자가 실행을 중지했습니다.'
        : safeText(error?.code ?? 'GENERAL_RUNTIME_FAILED');
      appendEvent({ stage: 'general.failed', title: run.status === 'stopped' ? '범용 점검 중지' : '범용 점검 실패',
        type: 'error', detail: run.error });
    } finally {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
      run.totalSteps = Math.max(1, run.events.length);
      sessionCookies.clear();
      task = null;
      publish();
    }
  }
  function startLab(options = {}) {
    if (closed) throw fault(503, 'General runtime is closed.');
    if (task || ACTIVE.has(run.status)) throw fault(409, 'A general assessment is already active.');
    if (!record(options) || Object.keys(options).length) throw fault(400, 'General assessment accepts no runtime options.');
    const id = assertIdentifier(runIdFactory(), 'runId');
    controller = new AbortController();
    sessionCookies.clear();
    run = { ...initial(), id, coreRunId: id, status: 'preparing', startedAt: new Date().toISOString() };
    task = Promise.resolve().then(runTask);
    publish();
    return getState();
  }
  function stop(id) {
    if (!id || id !== run.id) throw fault(404, 'General assessment not found.');
    if (ACTIVE.has(run.status)) { run.status = 'stopping'; controller.abort(); publish(); }
    return getState();
  }
  async function close() {
    closed = true;
    if (ACTIVE.has(run.status)) stop(run.id);
    await task;
    listeners.clear();
  }
  return { getState, startLab, stop, close, subscribe(listener) {
    listeners.add(listener); return () => listeners.delete(listener);
  } };
}
