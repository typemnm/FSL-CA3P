import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emptyRun, assertIdentifier } from '../../packages/contracts/index.mjs';
import { verifyAttack } from '../../packages/verifier/index.mjs';
import { writeReportHandoff } from '../../packages/verifier/report-handoff.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, validateGeneralLoopBudget } from '../../packages/contracts/general-loop-budget.mjs';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import generalCore from '../../agent/src/general-assessment.js';
import generalPlanner from '../../agent/src/general-model-planner.js';
import hitlApproval from '../../agent/src/hitl-approval.js';
import { readKnowledgeCatalogReadOnly } from '../../packages/adapters/integrations/knowledge-db.mjs';
import { collectWebInfo, evidenceFromTargetInfo } from '../../packages/adapters/integrations/web-parser.mjs';
import { createAttackToolBridge, renderTemplate, verifyTemplate, templateExecutionSupport, projectTemplateResponse } from '../../packages/adapters/integrations/attack-tool.mjs';
import { createAssessmentPlanner, createLocalJsonClient, isGeneralPlannerModel, LOCAL_PLANNER_MODEL_ID } from '../../packages/models/local-planner.mjs';

const { runGeneralAssessment } = generalCore;
const { createGeneralModelPlannerFromEnv } = generalPlanner;
const { createApprovalController } = hitlApproval;
const ACTIVE = new Set(['preparing', 'running', 'stopping']);
// Planner prompt cap 65,536 − 8,192 margin − 39,894 measured worst non-web_info context (daehan inventory 13,859,
// initial evidence 3,833, 40 hypotheses 19,867, system/rest/probe IDs 2,335) − 24 one-line overviews × 441 = 6,866.
// Measured with the default loop budget (maxProbes 24); a larger maxProbes shrinks the headroom the core prompt has.
const WEB_INFO_EVIDENCE_BUDGET_BYTES = 6800;
const MAX_BODY_BYTES = 24 * 1024;
const MAX_INITIAL_PAGES = 14;
const CATALOG_SOURCE = 'casper-db/attack-catalog';
const FIXTURES = Object.freeze({
  'vul-web-1': {
    name: '로컬 게시판', siteKey: null, origin: null,
    routes: ['/', '/api/session', '/api/posts', '/api/posts/1'],
    files: {
      'vul-web-1/server.js': '../../vul-web-1/server.js',
      'vul-web-1/package.json': '../../vul-web-1/package.json',
      'vul-web-1/README.md': '../../vul-web-1/README.md',
    },
    manifest: 'vul-web-1/package.json',
  },
  'vul-web2-daehan': {
    name: '대한대학교', siteKey: 'daehan', origin: 'http://127.0.0.1:4101',
    routes: ['/', '/about', '/admissions', '/colleges', '/academics', '/research',
      '/campus', '/facilities', '/notices', '/news', '/schedule', '/faq', '/login',
      '/mypage', '/admin', '/api/search', '/_diag/config',
      '/api/admissions/partner/applications/1', '/api/admissions/partner/applications/3',
      '/api/mypage/requests/1', '/api/mypage/requests/2', '/admin/posts/1/delete'],
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
      '/mypage', '/admin', '/api/search', '/_diag/config', '/admin/schedule/preview',
      '/api/staff/mobile/cases/1', '/api/staff/mobile/cases/3',
      '/api/mypage/requests/1', '/api/mypage/requests/2', '/admin/posts/1/delete'],
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
function templateIdentity(template) {
  const templateId = template?.templateId;
  const category = template?.attackType?.name;
  const asset = template?.target?.endpoint;
  if (typeof templateId !== 'string' || typeof category !== 'string' || typeof asset !== 'string') return undefined;
  return {
    templateId, category, asset,
    ...(typeof template.attackType?.cwe === 'string' ? { cwe: template.attackType.cwe } : {}),
  };
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

const APPROVAL_SECRET_FIELD = /(?:password|passwd|api[_-]?key|secret|token|session|cookie|authorization|credential|private[_-]?key)/iu;
function approvalFields(value) {
  if (!value) return [];
  const entries = value instanceof URLSearchParams ? [...value] : Object.entries(value);
  return entries.slice(0, 6).map(([name, fieldValue]) => ({
    name: utf8Prefix(safeText(name).replace(/[\u0000-\u001f\u007f]/gu, ' '), 48),
    value: APPROVAL_SECRET_FIELD.test(name) ? '[redacted]'
      : utf8Prefix(safeText(fieldValue).replace(/[\u0000-\u001f\u007f]/gu, ' '), 160),
  }));
}

function approvalPlan(probe, origin, renderedTemplate) {
  if (probe.tool === 'repository_read') return {
    summary: { method: 'READ', path: utf8Prefix(safeText(probe.input.file), 512),
      ...(probe.input.offset === undefined ? {} : { offset: probe.input.offset }), requestCount: 1 },
  };
  if (probe.tool === 'execute_attack_template') {
    const rendered = renderedTemplate;
    if (!rendered || rendered.template?.templateId !== probe.input.templateId) {
      throw fault(409, 'The approved template plan is unavailable.');
    }
    const packets = [['baseline', rendered.baseline], ['attack', rendered.packet],
      ['followUp', rendered.followUp]].filter(([, packet]) => !!packet);
    const steps = packets.map(([phase, packet]) => {
      const query = packet.query ? new URLSearchParams(packet.query).toString() : '';
      const url = safePath(packet.path + (query ? '?' + query : ''), origin);
      if (!url) throw fault(409, 'Approved template path is invalid.');
      return { phase, method: packet.method, path: url.pathname,
        ...(url.search ? { query: approvalFields(url.searchParams) } : {}),
        ...(packet.body ? { body: approvalFields(packet.body),
          bodySha256: createHash('sha256').update(new URLSearchParams(packet.body).toString()).digest('hex') } : {}) };
    });
    const attack = steps.find(step => step.phase === 'attack');
    return {
      summary: { method: attack.method, path: attack.path,
        ...(attack.query ? { query: attack.query } : {}),
        sessionRole: rendered.template.sessionRole ?? 'public',
        templateId: rendered.template.templateId,
        templateTitle: utf8Prefix(safeText(rendered.template.title ?? ''), 120),
        templateDescription: utf8Prefix(safeText(rendered.template.description ?? ''), 240),
        requestCount: steps.length, steps },
      binding: { template: rendered.template, packets: packets.map(([phase, packet]) => ({ phase, packet })) },
    };
  }
  const url = safePath(probe.input.path, origin);
  if (!url) throw fault(409, 'Approved probe path is invalid.');
  return { summary: { method: 'GET', path: url.pathname,
    ...(url.search ? { query: approvalFields(url.searchParams) } : {}),
    sessionRole: probe.input.sessionRole ?? 'public', requestCount: 1 } };
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

/** Real assessment of registered local targets with bounded policy-controlled probes. */
export function createGeneralRuntime({ fixtureId, targetOrigin, modelId,
  runIdFactory = () => 'general-' + randomUUID(), env = process.env, envFile,
  signal, onModelCall, beforeProbe, afterProbe, onWebInfo, caseSnapshot, unavailableInputs = [],
  historyProvider, plannerFactory, boardFactory, cleanupRegistryPath, fetchImpl = fetch,
  catalogReader = readKnowledgeCatalogReadOnly, templateCatalog,
  webParserCollect = collectWebInfo, verificationRoot, verifyAttackImpl = verifyAttack, verifierModel,
  limits = GENERAL_LOOP_BUDGET_DEFAULTS, approvalRequired = false, approvalTimeoutMs = 1_800_000 } = {}) {
  if (!Object.hasOwn(FIXTURES, fixtureId)) throw new TypeError('Choose a registered local fixture.');
  if (!isGeneralPlannerModel(modelId)) throw new TypeError('A registered planner model is required for a general assessment.');
  if (typeof runIdFactory !== 'function' || typeof fetchImpl !== 'function'
    || typeof catalogReader !== 'function'
    || typeof webParserCollect !== 'function' || typeof verifyAttackImpl !== 'function') {
    throw new TypeError('Invalid general runtime dependency.');
  }
  if (templateCatalog !== undefined && (typeof templateCatalog?.get !== 'function'
    || typeof templateCatalog?.list !== 'function')) throw new TypeError('Invalid template catalog.');
  for (const callback of [onModelCall, beforeProbe, afterProbe, onWebInfo, historyProvider, plannerFactory, boardFactory]) {
    if (callback !== undefined && typeof callback !== 'function') throw new TypeError('Invalid general runtime callback.');
  }
  if (typeof approvalRequired !== 'boolean' || !Number.isSafeInteger(approvalTimeoutMs)
    || approvalTimeoutMs < 1 || approvalTimeoutMs > 1_800_000) {
    throw new TypeError('Invalid general runtime approval options.');
  }
  limits = validateGeneralLoopBudget(limits);
  const config = FIXTURES[fixtureId];
  const origin = config.siteKey ? validateUniversityOrigin(targetOrigin ?? config.origin) : null;
  const instanceId = randomUUID();
  const listeners = new Set();
  const initial = () => ({ ...emptyRun(), mode: 'local-lab-general', assessmentMode: 'general',
    testProfile: 'general', fixtureId, target: origin ?? 'http://127.0.0.1/',
    coreTargetOrigin: origin, simulated: false, targetContacted: false,
    totalSteps: 1, iterations: 0, modelId,
    provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek', pendingApproval: null });
  let run = initial();
  let controller = null;
  let task = null;
  let board = null;
  let closed = false;
  let approvalController = null;
  // Session cookies stay only in this runtime process. Inventory and reports keep role labels.
  const sessionCookies = new Map();

  function getState() {
    if (ACTIVE.has(run.status)) run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    return structuredClone({ run, mode: run.mode, instanceId,
      lab: { available: true, generalSupported: true, generalAvailable: true, model: modelId,
        provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek' } });
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
    if (!config.siteKey) return;
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
    if (!config.siteKey) return [
      { role: 'alice', account: 'alice', password: null, paths: ['/api/posts'] },
      { role: 'bob', account: 'bob', password: null, paths: ['/api/posts'] },
    ];
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
    const path = config.siteKey ? '/login' : '/api/session';
    const url = new URL(path, allowedOrigin);
    const probe = { id: 'inventory-login-' + spec.role, probeId: 'inventory-login-' + spec.role,
      iteration: 1, tool: 'fixture_session', session: spec.role, method: 'POST', url: url.href };
    const reservation = await invokeHook(beforeProbe, probe);
    let response;
    try {
      const timeout = AbortSignal.timeout(5000);
      const body = config.siteKey
        ? new URLSearchParams({ username: spec.account, password: spec.password })
        : JSON.stringify({ userId: spec.account });
      response = await fetchImpl(url, { method: 'POST', redirect: 'manual',
        headers: { 'content-type': config.siteKey
          ? 'application/x-www-form-urlencoded' : 'application/json' },
        body, signal: currentSignal ? AbortSignal.any([currentSignal, timeout]) : timeout });
      run.targetContacted = true;
      const cookie = response.headers.get('set-cookie')?.split(';', 1)[0]?.trim();
      await limitedBody(response);
      const statusOkay = config.siteKey ? response.status === 302
        && response.headers.get('location') === '/mypage' : response.status === 200;
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
          entries: catalog.patterns.filter(item => {
            const application = item?.definition?.target?.application;
            return application === fixtureId || application === config.siteKey
              || (application === 'vul-web2' && Boolean(config.siteKey));
          })
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
    const references = await sourceReferences();
    evidence.push({ id: 'repository-manifest', source: 'repository/' + config.manifest,
      kind: 'dependency-reference', asset: config.manifest,
      summary: references[0].status === 'available'
        ? 'Local dependency manifest is available as historical/source context; version presence alone is not proof of an exploitable CVE.'
        : 'Local dependency manifest could not be read.' });
    const inventory = {
      fixtureId, origin: allowedOrigin, site: config.name, pages,
      authenticatedPages: authenticated.pages,
      declaredRoutes: [...config.routes],
      repositoryFiles: Object.keys(config.files),
      referenceSources: references,
      toolCapabilities: {
        http_get: 'input {path,sessionRole?}: GET on a declared or observed pathname at the selected origin; optional sessionRole uses only a prepared fixed demo session; redirects are not followed',
        web_info: 'input {path,sessionRole?}: open one declared or observed pathname at the selected origin in an isolated browser; returns up to 3 evidence items: overview (status, content type, final URL, title, redirects, technology analysis, list counts), discovered paths (same-origin first; robots/sitemap entries show in sources; same-origin paths become allowed for later probes), and page surface (forms with field names/types, frames, response headers, cookie names/attributes); once the cumulative web_info evidence budget of the run is spent, returns only a one-line overview (status, content type, list counts); response bodies and cookie values are never returned; optional sessionRole uses only a prepared fixed demo session',
        repository_read: 'input {file,offset?}: read only an allowlisted local source or reference excerpt',
        execute_attack_template: 'input {templateId,payload}: run a catalog template baseline, attack, and optional follow-up through the origin policy. Executable modes: resultCount, inheritedFilter, ownershipComparison, containsFields, statusSequence, tagAcceptance. The template pins the session role. sessionRole in the probe input is ignored.',
      },
      limitations: ['web_info opens a page in an isolated browser to observe web information, but it does not confirm whether any weakness executes; an AI verifier judges every executed probe as valid or invalid for its hypothesis and may open a read-only browser.',
        'GET and repository references do not independently confirm most weakness classes.',
        'Historical cases and source reports are context, not current-run proof.',
        'Initial public discovery is bounded to ' + MAX_INITIAL_PAGES + ' routes; other declared routes require a model probe.',
        'Authenticated observation uses only fixed demo accounts and records status and surface metadata, never response bodies.'],
    };
    return { inventory, evidence };
  }
  async function execute(allowedOrigin, currentSignal) {
    const planner = plannerFactory
      ? await plannerFactory({ modelId, env, envFile, signal: currentSignal })
      : await createAssessmentPlanner({ modelId, env, envFile });
    if (!planner || typeof planner.propose !== 'function') throw new TypeError('General planner is unavailable.');
    const localVerifier = verifierModel ?? (modelId === LOCAL_PLANNER_MODEL_ID && verifyAttackImpl === verifyAttack
      ? await createLocalJsonClient({ env, envFile }) : undefined);
    let observed = false;
    let inventory;
    const probeHypotheses = new Map();
    // A template is rendered once when policy first authorizes it. Approval,
    // the daemon policy recheck, and execution all use these exact packets.
    const templatePlans = new Map();
    const failedModelCalls = [];
    let evidenceCount = 0;
    let webInfoBytes = 0;
    const allowedPaths = new Set(config.routes.map(path => new URL(path, allowedOrigin).pathname));
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
      if (probe.tool === 'execute_attack_template') {
        const input = probe.input;
        if (!record(input) || Object.keys(input).some(key => !['templateId', 'payload', 'sessionRole'].includes(key))
          || typeof input.templateId !== 'string' || typeof input.payload !== 'string') {
          return { allowed: false, reason: 'invalid_execute_attack_template_input' };
        }
        const prior = templatePlans.get(probe.id);
        if (prior && prior.probeJson !== JSON.stringify(probe)) {
          return { allowed: false, reason: 'approved_template_changed' };
        }
        let rendered;
        try { rendered = prior?.rendered ?? renderTemplate({ templateId: input.templateId,
          payload: input.payload }, templateCatalog); }
        catch (error) {
          return { allowed: false, reason: error?.code === 'UNSUPPORTED_TEMPLATE'
            ? 'unsupported_template' : 'invalid_template' };
        }
        const template = rendered.template;
        if (Array.isArray(template.fixtures) && !template.fixtures.includes(fixtureId)) {
          return { allowed: false, reason: 'fixture_mismatch' };
        }
        const role = template.sessionRole ?? 'public';
        if (role !== 'public' && !sessionCookies.has(role)) {
          return { allowed: false, reason: 'session_unavailable' };
        }
        const steps = [rendered.baseline, rendered.packet, rendered.followUp].filter(Boolean);
        for (const item of steps) {
          if (!['GET', 'POST'].includes(item.method)) return { allowed: false, reason: 'method_out_of_scope' };
          const query = item.query ? new URLSearchParams(item.query).toString() : '';
          const url = safePath(item.path + (query ? '?' + query : ''), allowedOrigin);
          if (!url || !allowedPaths.has(url.pathname)) return { allowed: false, reason: 'path_out_of_scope' };
        }
        if (!prior) templatePlans.set(probe.id, { probeJson: JSON.stringify(probe), rendered });
        return { allowed: true, reason: 'template_authorized' };
      }
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
        const asset = url.pathname + url.search;
        const size = value => Array.isArray(value) ? value.length : 0;
        // One event per probe lets the dashboard list web-parser results and fetch each stored TargetInfo.
        const collected = fields => appendEvent({ stage: 'web_info.collected', module: 'web-parser',
          source: 'web-parser', title: '웹 정보 수집', probeId: probe.id, iteration: run.iterations, asset,
          sessionRole: sessionRole ?? null, status: observedStatus, ...fields });
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
            asset, safeText: evidenceText, safeHeaderValue };
          let evidence = evidenceFromTargetInfo(info, options);
          // The planner resends all evidence each call; past the budget only a one-line overview fits.
          if (webInfoBytes + bytes(evidence) > WEB_INFO_EVIDENCE_BUDGET_BYTES) {
            evidence = evidenceFromTargetInfo(info, { ...options, mode: 'minimal' });
          }
          webInfoBytes += bytes(evidence);
          let artifactId = null;
          try {
            // The raw TargetInfo as collected; only the model-facing evidence above is masked.
            const stored = await invokeHook(onWebInfo, { probeId: probe.id, iteration: run.iterations,
              sessionRole: sessionRole ?? null, targetInfo: info });
            if (typeof stored?.artifactId === 'string' && /^[a-f0-9]{64}$/u.test(stored.artifactId)) {
              artifactId = stored.artifactId;
            }
          } catch { /* The stored TargetInfo is optional; a failing hook must not fail the probe or the run. */ }
          collected({ type: 'info', detail: 'GET ' + asset + ' → HTTP ' + (observedStatus ?? 'no response'),
            ok: true, artifactId, counts: { technologies: size(info.technologies), paths: size(info.paths),
              forms: size(info.structure?.forms), errors: size(info.errors) },
            truncated: info.truncated === true });
          return { kind: 'web_info', result: summary, evidence };
        } catch (error) {
          if (probeSignal?.aborted || error?.fatalProbe) throw error;
          collected({ type: 'warning', detail: '웹 정보 수집 실패', ok: false, artifactId: null,
            counts: { technologies: 0, paths: 0, forms: 0, errors: 0 }, truncated: false });
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
      if (probe.tool === 'execute_attack_template') {
        const plan = templatePlans.get(probe.id);
        if (!plan || plan.probeJson !== JSON.stringify(probe)) {
          throw fault(409, 'The authorized template plan changed before execution.');
        }
        const rendered = plan.rendered;
        const sessionRole = rendered.template.sessionRole ?? 'public';
        const cookie = sessionRole === 'public' ? null : sessionCookies.get(sessionRole);
        async function templateRequest(packet, label) {
          const query = packet.query ? new URLSearchParams(packet.query).toString() : '';
          const url = safePath(packet.path + (query ? '?' + query : ''), allowedOrigin);
          const timeout = AbortSignal.timeout(5000);
          const combined = probeSignal ? AbortSignal.any([probeSignal, timeout]) : timeout;
          const headers = {
            ...(cookie ? { cookie } : {}),
            ...(packet.method === 'POST' ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
          };
          const probeRecord = { id: probe.id + '-' + label, probeId: probe.id, iteration: run.iterations,
            tool: probe.tool, session: sessionRole, method: packet.method, url: url.href };
          const reservation = await invokeHook(beforeProbe, probeRecord);
          let response;
          try {
            response = await fetchImpl(url, { method: packet.method, redirect: 'manual',
              ...(Object.keys(headers).length ? { headers } : {}),
              ...(packet.body ? { body: new URLSearchParams(packet.body).toString() } : {}),
              signal: combined });
            run.targetContacted = true;
            const body = await limitedBody(response);
            let json;
            try { json = JSON.parse(body); } catch { json = undefined; }
            return { url: url.href, method: packet.method, status: response.status,
              headers: { 'content-type': response.headers.get('content-type') ?? '' },
              json, body, truncated: Buffer.byteLength(body, 'utf8') >= MAX_BODY_BYTES };
          } finally {
            await invokeHook(afterProbe, probeRecord, { status: response?.status ?? null,
              evidenceId: evidenceId('probe', probe.id) }, reservation);
          }
        }
        try {
          const baseline = await templateRequest(rendered.baseline, 'baseline');
          const attack = await templateRequest(rendered.packet, 'attack');
          const followUp = rendered.followUp ? await templateRequest(rendered.followUp, 'followUp') : undefined;
          const verification = verifyTemplate(baseline, attack, rendered.template, followUp);
          const identity = templateIdentity(rendered.template);
          const baselineView = projectTemplateResponse(baseline);
          const attackView = projectTemplateResponse(attack);
          return {
            kind: 'execute_attack_template',
            result: { status: attack.status, verification: verification.status, ...(identity ? { identity } : {}) },
            attackRecord: {
              schemaVersion: 'attack-record/1', id: probe.id, kind: rendered.template.attackType?.name ?? 'template',
              target: { origin: allowedOrigin },
              info: { tool: 'execute_attack_template', templateId: rendered.template.templateId,
                payload: probe.input.payload, verification: verification.status, session: sessionRole },
              request: { method: attack.method, url: attack.url, headers: {}, body: null },
              response: { status: attack.status, bodyText: attackView.bodyExcerpt,
                truncated: attackView.truncated || attackView.excerptTruncated },
              control: { request: { method: baseline.method, url: baseline.url, headers: {}, body: null },
                response: { status: baseline.status, bodyText: baselineView.bodyExcerpt,
                  truncated: baselineView.truncated || baselineView.excerptTruncated } },
              ...(followUp ? { followUp: { request: { method: followUp.method, url: followUp.url, headers: {}, body: null },
                response: { status: followUp.status, bodyText: projectTemplateResponse(followUp).bodyExcerpt } } } : {}),
            },
            evidence: [{ id: evidenceId('probe', probe.id),
              source: 'attack-tool/' + fixtureId + (sessionRole === 'public' ? '' : '/role:' + sessionRole),
              kind: 'template-exchange', asset: rendered.packet.path,
              summary: utf8Prefix(safeText('template ' + rendered.template.templateId
                + ' baseline HTTP ' + baseline.status
                + (verification.baselineCount === undefined ? '' : ' count=' + (verification.baselineCount ?? 'none'))
                + '; attack HTTP ' + attack.status
                + (verification.attackCount === undefined ? '' : ' count=' + (verification.attackCount ?? 'none'))
                + (followUp ? '; followUp HTTP ' + followUp.status : '')
                + '; compare ' + verification.status), 1200) }],
          };
        } catch (error) {
          if (probeSignal?.aborted || error?.fatalProbe) throw error;
          return { kind: 'execute_attack_template', error: 'request_unavailable',
            evidence: [{ id: evidenceId('probe', probe.id), source: 'attack-tool/' + fixtureId,
              kind: 'unavailable', asset: probe.input.templateId,
              summary: 'Attack template baseline or attack request failed; the hypothesis remains unverified.' }] };
        }
      }
      return { kind: probe.tool, evidence: [] };
    } };
    // Evidence already judged per hypothesis, so each verdict covers everything known so far.
    const judgedEvidence = new Map();
    const verifier = { async verify({ hypothesis, probe, execution, evidence, signal }) {
      const id = execution.evidence[0].id;
      const templateStatus = execution.result?.verification;
      if (probe.tool === 'execute_attack_template'
        && ['confirmed', 'not_reproduced', 'inconclusive'].includes(templateStatus)) {
        const identity = execution.result?.identity;
        const verdict = templateStatus === 'inconclusive'
          ? { status: 'inconclusive', evidenceIds: [id], reason: 'template_compare_inconclusive' }
          : { status: templateStatus, completed: true, evidenceIds: [id], reason: 'template_compare_' + templateStatus };
        return identity ? { ...verdict, identity } : verdict;
      }
      const own = new Set(execution.evidence.map(item => item.id));
      const earlier = judgedEvidence.get(hypothesis.id) ?? [];
      const cited = evidence.filter(item => hypothesis.evidenceIds.includes(item.id) && !own.has(item.id));
      judgedEvidence.set(hypothesis.id, [...earlier, ...execution.evidence]);
      const sessions = Object.fromEntries([...sessionCookies].map(([role, cookie]) => [role,
        [{ name: cookie.slice(0, cookie.indexOf('=')), value: cookie.slice(cookie.indexOf('=') + 1) }]]));
      return judgeAttackRecord(recordForProbe({ probe, hypothesis, execution, origin: allowedOrigin,
        relatedEvidence: [...cited, ...earlier] }), { evidenceId: id, sessions, verify: verifyAttackImpl,
        outDir: verificationRoot ? join(verificationRoot, probe.id) : undefined, model: localVerifier,
        env, envFile, signal });
    } };
    const wrappedPlanner = { async propose(context) {
      let plan;
      try { plan = await planner.propose(context); }
      catch (error) {
        const attempts = planner instanceof generalPlanner.GeneralModelPlanner
          && Array.isArray(error?.modelAttempts) ? error.modelAttempts : [];
        for (const attempt of attempts) {
          failedModelCalls.push(attempt);
          await onModelCall?.(attempt);
        }
        if (attempts.length && error?.code === 'GENERAL_PLANNER_SCHEMA_ERROR') throw error;
        const failed = { provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek',
          requestedModel: modelId, status: 'failed', iteration: context.iteration };
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
    const availableTools = ['http_get', 'web_info', 'repository_read', 'execute_attack_template'];
    // Each vulnerability worker receives its own authenticated logical client.
    // The daemon owns the transport, while target and policy authority remain in
    // this runtime; model input cannot install an executor or change its scope.
    const attackTool = await createAttackToolBridge({ runId: run.id, targetOrigin: allowedOrigin,
      authorize: ({ probe }) => policy.authorize({ probe,
        hypothesis: probeHypotheses.get(probe.id) }),
      execute: input => executor.execute(input),
      ...(templateCatalog ? { templateCatalog } : {}),
    });
    const toolExecutor = { execute: ({ probe, signal }) => attackTool.execute({ probe,
      hypothesis: probeHypotheses.get(probe.id), signal: signal ?? currentSignal }) };
    const approval = approvalRequired ? { request: async ({ probe, hypothesis, signal: approvalSignal }) => {
      const actionForApproval = () => {
        const templatePlan = probe.tool === 'execute_attack_template' ? templatePlans.get(probe.id) : null;
        if (templatePlan && templatePlan.probeJson !== JSON.stringify(probe)) {
          throw fault(409, 'The authorized template plan changed before approval.');
        }
        const { summary: planSummary, binding } = approvalPlan(probe, allowedOrigin, templatePlan?.rendered);
        const action = { runId: run.id, target: allowedOrigin, probe,
          hypothesisId: hypothesis?.id, ...(binding ? { binding } : {}) };
        return { summary: { tool: probe.tool, target: allowedOrigin,
          hypothesis: utf8Prefix(safeText(hypothesis?.category ?? 'unknown'), 128), ...planSummary },
        digest: createHash('sha256').update(JSON.stringify(action)).digest('hex') };
      };
      const { summary, digest: actionDigest } = actionForApproval();
      const outcome = await approvalController.request({ kind: 'general-probe', probeId: probe.id,
        summary, actionDigest, signal: approvalSignal });
      if (outcome.decision === 'approved' && actionForApproval().digest !== actionDigest) {
        throw fault(409, 'Approved probe changed before execution.');
      }
      return outcome;
    } } : undefined;
    let report;
    try {
      ({ report } = await runGeneralAssessment({
        target: { fixtureId, origin: allowedOrigin }, observer, planner: wrappedPlanner,
        policy, executor: toolExecutor, verifier, approval, availableTools, limits, signal: currentSignal,
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
      templatePlans.clear();
    }
    report.runId = run.id;
    report.modelCalls.push(...failedModelCalls);
    report.fixtureId = fixtureId;
    report.targetContacted = run.targetContacted;
    report.scope = { fixtureId, origin: allowedOrigin,
      methods: ['GET'],
      sessionBootstrap: (config.siteKey ? 'POST /login' : 'POST /api/session') + ' using fixed demo accounts',
      toolIds: availableTools, allowedPaths: [...allowedPaths].sort(), ...limits };
    return report;
  }
  async function runTask() {
    try {
      const runSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      runSignal.throwIfAborted();
      if (!config.siteKey) {
        const factory = boardFactory ?? (async () => {
          const { startLocalLab } = await import('../../packages/adapters/local-lab-gateway.mjs');
          return startLocalLab({ cleanupRegistryPath });
        });
        board = await factory();
        if (!board || typeof board.origin !== 'string' || typeof board.close !== 'function'
          || !/^http:\/\/127\.0\.0\.1:\d{1,5}$/u.test(board.origin)) {
          throw new TypeError('The isolated board factory returned an invalid target.');
        }
      }
      const allowedOrigin = board?.origin ?? origin;
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
      run.pendingApproval = null;
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
    approvalController = approvalRequired ? createApprovalController({ runId: id, timeoutMs: approvalTimeoutMs,
      onPending(pending) {
        run.pendingApproval = pending;
        appendEvent({ stage: 'approval.requested', title: '공격 probe 승인 대기',
          request: { approvalId: pending.id, kind: pending.kind, probeId: pending.probeId,
            summary: pending.summary, actionDigest: pending.actionDigest }, response: { status: 'pending' } });
      },
      onResolved(outcome) {
        run.pendingApproval = null;
        appendEvent({ stage: 'approval.resolved', title: '공격 probe 승인 결정',
          request: { approvalId: outcome.id }, response: { decision: outcome.decision,
            ...(outcome.actor ? { actor: outcome.actor } : {}) } });
      },
    }) : null;
    task = Promise.resolve().then(runTask);
    publish();
    return getState();
  }
  function stop(id) {
    if (!id || id !== run.id) throw fault(404, 'General assessment not found.');
    if (ACTIVE.has(run.status)) { run.status = 'stopping'; controller.abort(); publish(); }
    return getState();
  }
  function decideApproval({ id, decision, actor } = {}) {
    if (run.status !== 'running' || !approvalController) throw fault(409, 'No active approval request.');
    return approvalController.decide({ id, decision, actor });
  }
  async function close() {
    closed = true;
    if (ACTIVE.has(run.status)) stop(run.id);
    await task;
    try { await board?.close(); } finally { listeners.clear(); board = null; }
  }
  return { getState, startLab, stop, decideApproval, close, subscribe(listener) {
    listeners.add(listener); return () => listeners.delete(listener);
  } };
}
