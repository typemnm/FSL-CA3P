import { randomUUID } from 'node:crypto';
import { normalizeExternalTarget, externalScopeRejectionReason,
  requestExternalHttp, resolvePublicAddresses } from './external-target.mjs';
import { collectWebInfo, fingerprintObservedResponse } from '../../packages/adapters/integrations/web-parser.mjs';
import { redact } from '../../packages/contracts/index.mjs';

const MAX_SESSIONS = 64;
const MAX_PAGES = 12;
const MAX_EXTERNAL_PAGES = 8;
const MAX_DISCOVERED = 60;
const LIFETIME_MS = 15 * 60_000;
const MAX_COMPONENTS = 40;
const MAX_FORMS = 20;
const MAX_FIELDS = 20;
const MAX_ERRORS = 8;
const EVIDENCE_FIELDS = new Set(['headers', 'meta', 'html', 'scriptSrc', 'scripts', 'xhr', 'url', 'js', 'dom', 'cookies', 'implies']);
const PATH_SOURCES = new Set(['redirect', 'form', 'formaction', 'link', 'area', 'script', 'iframe',
  'frame', 'embed', 'object', 'meta-refresh', 'srcset', 'sitemap', 'sitemap-index']);

const fault = (status, message, code) => Object.assign(new Error(message), { status, code });
const list = value => Array.isArray(value) ? value : [];
const bounded = (value, length = 160) => typeof value === 'string'
  ? value.replace(/[\u0000-\u001f\u007f]/gu, ' ').slice(0, length) : '';

function normalizedUrl(value) {
  return normalizeExternalTarget({ target: value, scope: { pathPrefix: '/' } }).normalizedUrl;
}

function safePath(value, base, origin) {
  if (typeof value !== 'string' && !(value instanceof URL)) return null;
  try {
    const url = new URL(value, base);
    if (url.origin !== origin || url.username || url.password || !['http:', 'https:'].includes(url.protocol)) return null;
    url.search = '';
    url.hash = '';
    return url.href;
  } catch { return null; }
}

function component(value, library = false) {
  if (!value || typeof value.name !== 'string' || !value.name.trim()) return null;
  const version = bounded(value.version, 40);
  const item = { name: bounded(value.name, 120),
    version: /^\d+(?:\.\d+){0,3}(?:[-+][a-z0-9.]{1,16})?$/iu.test(version) ? version : null };
  if (!library) {
    item.categories = list(value.categories).slice(0, 8).map(category => bounded(category, 80)).filter(Boolean);
    item.confidence = Number.isFinite(value.confidence) ? Math.max(0, Math.min(100, Math.round(value.confidence))) : null;
  }
  item.evidenceFields = [...new Set([...list(value.evidenceFields),
    ...list(value.evidence).map(evidence => evidence?.field)]
    .filter(field => EVIDENCE_FIELDS.has(field)))].slice(0, 8);
  return item;
}

function pathSource(value) {
  if (PATH_SOURCES.has(value)) return value;
  if (typeof value === 'string' && value.startsWith('request:')) return 'request';
  if (typeof value === 'string' && value.startsWith('link-rel:')) return 'link-rel';
  if (typeof value === 'string' && value.startsWith('robots:')) return 'robots';
  return 'parser:path';
}

function titleFromHtml(html) {
  if (typeof html !== 'string') return null;
  return bounded(html.slice(0, 50_000).match(/<title\b[^>]*>([\s\S]*?)<\/title>/iu)?.[1]
    ?.replace(/\s+/gu, ' ').trim(), 200) || null;
}

function errorCode(error) {
  const code = error?.code;
  if (typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/u.test(code)) return code;
  const stage = error?.stage;
  if (typeof stage === 'string' && /^[a-z][a-z0-9_-]{0,40}$/iu.test(stage)) {
    return `PARSER_${stage.toUpperCase().replace(/-/gu, '_')}`;
  }
  if (error?.name === 'TimeoutError' || error?.name === 'AbortError') return 'PARSER_TIMEOUT';
  return 'PARSER_PREVIEW_FAILED';
}

function emptyPage(url, mode, error) {
  return { url: redact(url), status: null, contentType: null, title: null,
    technologies: [], libraries: [], forms: [], paths: [],
    errors: [{ code: errorCode(error) }], truncated: false, mode };
}

function labPage(url, info, origin) {
  if (info?.target?.finalUrl) {
    let finalOrigin;
    try { finalOrigin = new URL(info.target.finalUrl).origin; } catch { /* Invalid final URL is rejected below. */ }
    if (finalOrigin !== origin) return emptyPage(url, 'browser', { code: 'REDIRECT_OUT_OF_SCOPE' });
  }
  const discovered = new Map();
  const addPath = (value, source) => {
    const path = safePath(value, url, origin);
    if (!path || (discovered.size >= MAX_DISCOVERED && !discovered.has(path))) return;
    if (!discovered.has(path)) discovered.set(path, new Set());
    discovered.get(path).add(pathSource(source));
  };
  for (const row of list(info?.paths).slice(0, MAX_DISCOVERED)) {
    for (const source of list(row?.sources).slice(0, 4)) addPath(row?.url, source);
    if (!list(row?.sources).length) addPath(row?.url, 'parser:path');
  }
  for (const link of list(info?.structure?.links).slice(0, MAX_DISCOVERED)) addPath(link?.href, 'link');
  const forms = list(info?.structure?.forms).slice(0, MAX_FORMS).map(form => ({
    action: safePath(form?.action || url, url, origin), method: bounded(form?.method, 12).toUpperCase() || 'GET',
    fields: list(form?.fields).slice(0, MAX_FIELDS).map(field => ({
      name: bounded(field?.name, 80), type: bounded(field?.type, 40),
    })).filter(field => field.name),
  })).filter(form => form.action);
  const status = Number.isInteger(info?.navigation?.status) ? info.navigation.status : null;
  const errors = list(info?.errors).slice(0, MAX_ERRORS).map(error => ({ code: errorCode(error) }));
  if (status === null && !errors.length) errors.push({ code: 'PARSER_NO_RESPONSE' });
  const page = { url: redact(url), status,
    contentType: bounded(info?.navigation?.contentType, 120) || null, title: titleFromHtml(info?.html),
    technologies: list(info?.technologies).slice(0, MAX_COMPONENTS).map(value => component(value)).filter(Boolean),
    libraries: list(info?.libraries).slice(0, MAX_COMPONENTS).map(value => component(value, true)).filter(Boolean),
    forms, paths: [...discovered].map(([path, sources]) => ({ url: path, sources: [...sources].filter(Boolean) })),
    errors,
    truncated: info?.truncated === true, mode: 'browser' };
  return page;
}

function externalPaths(body, url, origin, scope) {
  const found = new Map();
  if (typeof body !== 'string') return [];
  const markup = body.slice(0, 64 * 1024).replace(/<!--[\s\S]*?(?:-->|$)/gu, '');
  const pattern = /<(a|form)\b[^>]*?\b(?:href|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/giu;
  for (const match of markup.matchAll(pattern)) {
    if (found.size >= MAX_DISCOVERED) break;
    const candidate = match[2] ?? match[3] ?? match[4];
    let parsed;
    try { parsed = new URL(candidate, url); } catch { continue; }
    if (externalScopeRejectionReason(parsed, scope) || parsed.origin !== origin || parsed.search) continue;
    const path = safePath(parsed, url, origin);
    if (!path) continue;
    const source = match[1].toLowerCase() === 'form' ? 'html:form' : 'html:link';
    if (!found.has(path)) found.set(path, new Set());
    found.get(path).add(source);
  }
  return [...found].map(([path, sources]) => ({ url: path, sources: [...sources] }));
}

async function externalPage(url, scope, request, fingerprint) {
  const signal = AbortSignal.timeout(12_000);
  const response = await request(url, { scope, method: 'GET', signal });
  if (response?.contentEncoding && String(response.contentEncoding).toLowerCase() !== 'identity') {
    return emptyPage(url, 'http-response', { code: 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED' });
  }
  const html = /(?:text\/html|application\/xhtml\+xml)/iu.test(response?.contentType ?? '')
    ? response.body ?? '' : '';
  let observed = { technologies: [], libraries: [] };
  const errors = [];
  if (html && !response?.truncated && response?.status >= 200 && response.status < 300) {
    try { observed = await fingerprint(url, response); }
    catch { errors.push({ code: 'WEB_PARSER_UNAVAILABLE' }); }
  }
  const status = Number.isInteger(response?.status) ? response.status : null;
  if (status === null && !errors.length) errors.push({ code: 'PARSER_NO_RESPONSE' });
  return { url: redact(url), status,
    contentType: bounded(response?.contentType, 120) || null, title: titleFromHtml(html),
    technologies: list(observed.technologies).slice(0, MAX_COMPONENTS).map(value => component(value)).filter(Boolean),
    libraries: list(observed.libraries).slice(0, MAX_COMPONENTS).map(value => component(value, true)).filter(Boolean),
    forms: [], paths: externalPaths(html, url, scope.origin, scope), errors,
    truncated: response?.truncated === true, mode: 'http-response' };
}

/** A short-lived, bounded result set for review before the judgment engine starts. */
export function createTargetPreviewService({ universityOrigins = {}, labCollect = collectWebInfo,
  externalRequest = requestExternalHttp, externalFingerprint = fingerprintObservedResponse,
  publicAddresses = resolvePublicAddresses, clock = Date.now, idFactory = randomUUID } = {}) {
  if (!universityOrigins || typeof universityOrigins !== 'object' || Array.isArray(universityOrigins)
    || [labCollect, externalRequest, externalFingerprint, publicAddresses, clock, idFactory]
      .some(value => typeof value !== 'function')) throw new TypeError('Invalid parser preview dependencies.');
  const fixtures = new Map(Object.entries(universityOrigins).map(([fixtureId, origin]) => [new URL(origin).origin, fixtureId]));
  const sessions = new Map();
  const prune = () => { for (const [id, item] of sessions) if (item.expiresAtMs <= clock()) sessions.delete(id); };
  const snapshot = session => structuredClone(redact({ previewId: session.id, targetKind: session.targetKind,
    fixtureId: session.fixtureId, origin: session.origin, entryUrl: redact(session.entryUrl),
    pages: session.pages, discoveredPaths: [...new Set(session.pages.flatMap(page => page.paths.map(path => path.url)))].slice(0, MAX_DISCOVERED),
    expiresAt: new Date(session.expiresAtMs).toISOString() }));
  function getPreview(id) {
    prune();
    if (typeof id !== 'string') return null;
    const session = sessions.get(id);
    return session ? snapshot(session) : null;
  }
  async function preview({ url: input, previewId } = {}) {
    prune();
    const url = normalizedUrl(input);
    let session = previewId === undefined ? null : sessions.get(previewId);
    if (previewId !== undefined && !session) throw fault(404, 'Parser preview expired. Parse the URL again.', 'PREVIEW_NOT_FOUND');
    if (session && new URL(url).origin !== session.origin) {
      throw fault(400, 'Additional paths must use the original target origin.', 'PREVIEW_ORIGIN_MISMATCH');
    }
    if (!session) {
      if (sessions.size >= MAX_SESSIONS) throw fault(429, 'Too many parser previews. Retry shortly.', 'PREVIEW_CAPACITY');
      const origin = new URL(url).origin;
      const fixtureId = fixtures.get(origin) ?? null;
      const targetKind = fixtureId ? 'lab' : 'external';
      const scope = normalizeExternalTarget({ target: url, scope: { pathPrefix: '/' } }).scope;
      if (!fixtureId) await publicAddresses(new URL(url).hostname, { signal: AbortSignal.timeout(12_000) });
      const id = idFactory();
      if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/iu.test(id) || sessions.has(id)) {
        throw new TypeError('Invalid parser preview ID.');
      }
      session = { id, targetKind, fixtureId, origin, entryUrl: url, scope,
        pages: [], urls: new Set(), busy: false, expiresAtMs: clock() + LIFETIME_MS };
      sessions.set(id, session);
    }
    if (session.busy) throw fault(409, 'Parser preview is already collecting a URL.', 'PREVIEW_BUSY');
    if (session.urls.has(url)) return snapshot(session);
    if (session.pages.length >= (session.targetKind === 'external' ? MAX_EXTERNAL_PAGES : MAX_PAGES)) {
      throw fault(429, 'Parser preview URL limit reached.', 'PREVIEW_PAGE_LIMIT');
    }
    session.busy = true;
    try {
      let page;
      try {
        page = session.targetKind === 'lab'
          ? labPage(url, (await labCollect(url)).info, session.origin)
          : await externalPage(url, session.scope, externalRequest, externalFingerprint);
      } catch (failure) {
        if (session.targetKind === 'external' && ['EXTERNAL_ADDRESS_BLOCKED', 'EXTERNAL_DNS_REBIND',
          'EXTERNAL_SCOPE_BLOCKED', 'EXTERNAL_DNS_UNAVAILABLE'].includes(failure?.code)) throw failure;
        page = emptyPage(url, session.targetKind === 'lab' ? 'browser' : 'http-response', failure);
      }
      session.urls.add(url);
      session.pages.push(page);
      return snapshot(session);
    } catch (failure) {
      if (!session.pages.length) sessions.delete(session.id);
      throw failure;
    } finally { session.busy = false; }
  }
  return { preview, getPreview };
}
