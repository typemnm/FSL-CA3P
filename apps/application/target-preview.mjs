import { randomUUID } from 'node:crypto';
import { normalizeExternalTarget, externalScopeRejectionReason,
  requestExternalHttp, resolvePublicAddresses } from './external-target.mjs';
import { collectWebInfo, fingerprintObservedResponse } from '../../packages/adapters/integrations/web-parser.mjs';
import { redact } from '../../packages/contracts/index.mjs';

const MAX_SESSIONS = 64;
const MAX_PAGES = 48;
const MAX_EXTERNAL_PAGES = 8;
const MAX_DISCOVERED = 60;
const MAX_QUEUED = 200;
const MAX_START_URL_LENGTH = 512;
const MAX_PATH_URL_LENGTH = 512;
const MAX_LAB_CRAWL_MS = 50_000;
const MAX_EXTERNAL_CRAWL_MS = 28_000;
const LIFETIME_MS = 15 * 60_000;
const MAX_COMPONENTS = 40;
const MAX_FORMS = 20;
const MAX_FIELDS = 20;
const MAX_ERRORS = 8;
const EVIDENCE_FIELDS = new Set(['headers', 'meta', 'html', 'scriptSrc', 'stylesheetHref', 'resourceComment',
  'scripts', 'xhr', 'url', 'js', 'dom', 'cookies', 'implies']);
const PATH_SOURCES = new Set(['redirect', 'form', 'formaction', 'link', 'area', 'script', 'iframe',
  'frame', 'embed', 'object', 'meta-refresh', 'srcset', 'sitemap', 'sitemap-index']);
const AUTO_PAGE_SOURCES = new Set(['link', 'area', 'html:link', 'sitemap']);
const SAFETY_FAILURES = new Set(['EXTERNAL_ADDRESS_BLOCKED', 'EXTERNAL_DNS_REBIND',
  'EXTERNAL_SCOPE_BLOCKED', 'EXTERNAL_DNS_UNAVAILABLE']);
const STATIC_ASSET = /\.(?:css|m?js|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|pdf|zip|gz|tar|mp[34]|webm|wav|ogg|xml|txt|json|webmanifest)$/iu;
const ACTION_PATH = /^(?:logout|log-out|signout|sign-out|delete|remove|destroy|drop|clear|reset|terminate|withdraw|deactivate|unsubscribe|cancel)$/iu;

const fault = (status, message, code) => Object.assign(new Error(message), { status, code });
const list = value => Array.isArray(value) ? value : [];
const bounded = (value, length = 160) => typeof value === 'string'
  ? value.replace(/[\u0000-\u001f\u007f]/gu, ' ').slice(0, length) : '';

function normalizedUrl(value) {
  const url = normalizeExternalTarget({ target: value, scope: { pathPrefix: '/' } }).normalizedUrl;
  if (url.length > MAX_START_URL_LENGTH) {
    throw fault(400, 'Parser preview URL must be 512 characters or shorter.', 'PREVIEW_URL_TOO_LONG');
  }
  return url;
}

function safePath(value, base, origin) {
  if (typeof value !== 'string' && !(value instanceof URL)) return null;
  try {
    const url = new URL(value, base);
    if (url.origin !== origin || url.username || url.password || !['http:', 'https:'].includes(url.protocol)) return null;
    url.search = '';
    url.hash = '';
    return url.href.length <= MAX_PATH_URL_LENGTH ? url.href : null;
  } catch { return null; }
}

function longPath(value, base) {
  try { return new URL(value, base).href.length > MAX_PATH_URL_LENGTH; }
  catch { return false; }
}

function autoPageCandidate(path, session) {
  if (!path || !list(path.sources).some(source => AUTO_PAGE_SOURCES.has(source))) return null;
  const url = safePath(path.url, session.entryUrl, session.origin);
  if (!url || externalScopeRejectionReason(url, session.scope)) return null;
  const parsed = new URL(url);
  let segments;
  try { segments = decodeURIComponent(parsed.pathname).split('/').filter(Boolean); }
  catch { return null; }
  if (STATIC_ASSET.test(parsed.pathname) || segments.some(segment => ACTION_PATH.test(segment))
    || segments[0]?.toLowerCase() === 'api') return null;
  return url;
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
  if (library && value.source === 'indicator') item.source = 'indicator';
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

function labPage(url, info, session) {
  const origin = session.origin;
  if (info?.target?.finalUrl) {
    let finalOrigin;
    try { finalOrigin = new URL(info.target.finalUrl).origin; } catch { /* Invalid final URL is rejected below. */ }
    if (finalOrigin !== origin) return {
      page: emptyPage(url, 'browser', { code: 'REDIRECT_OUT_OF_SCOPE' }),
      candidates: [], discoveryTruncated: false,
    };
  }
  const discovered = new Map();
  const candidates = new Set();
  let droppedLongPath = false;
  let droppedCandidate = false;
  let droppedDisplayPath = false;
  const addPath = (value, source) => {
    const normalizedSource = pathSource(source);
    const path = safePath(value, url, origin);
    if (!path) {
      if (longPath(value, url)) {
        droppedLongPath = true;
        if (AUTO_PAGE_SOURCES.has(normalizedSource)) droppedCandidate = true;
      }
      return;
    }
    if (AUTO_PAGE_SOURCES.has(normalizedSource)) {
      const candidate = autoPageCandidate({ url: path, sources: [normalizedSource] }, session);
      if (candidate) candidates.add(candidate);
    }
    if (discovered.size >= MAX_DISCOVERED && !discovered.has(path)) {
      droppedDisplayPath = true;
      return;
    }
    if (!discovered.has(path)) discovered.set(path, new Set());
    discovered.get(path).add(normalizedSource);
  };
  // Visit candidates come from every observed anchor, even when the display cap
  // omits duplicate links or static resources from the per-page path list.
  for (const row of list(info?.paths)) {
    for (const source of list(row?.sources)) {
      if (AUTO_PAGE_SOURCES.has(source)) addPath(row?.url, source);
    }
  }
  for (const link of list(info?.structure?.links)) addPath(link?.href, 'link');
  for (const row of list(info?.paths)) {
    for (const source of list(row?.sources)) {
      if (!AUTO_PAGE_SOURCES.has(source)) addPath(row?.url, source);
    }
    if (!list(row?.sources).length) addPath(row?.url, 'parser:path');
  }
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
    truncated: info?.truncated === true || droppedLongPath || droppedDisplayPath,
    mode: 'browser' };
  return { page, candidates: [...candidates], discoveryTruncated: info?.truncated === true || droppedCandidate };
}

function externalPaths(body, url, origin, scope) {
  const found = new Map();
  if (typeof body !== 'string') return { paths: [], candidates: [],
    truncated: false, discoveryTruncated: false };
  let truncated = body.length > 64 * 1024;
  let discoveryTruncated = truncated;
  const rows = [];
  const candidates = new Set();
  const markup = body.slice(0, 64 * 1024).replace(/<!--[\s\S]*?(?:-->|$)/gu, '');
  const pattern = /<(a|form)\b[^>]*?\b(?:href|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/giu;
  for (const match of markup.matchAll(pattern)) {
    const candidate = match[2] ?? match[3] ?? match[4];
    let parsed;
    try { parsed = new URL(candidate, url); } catch { continue; }
    if (externalScopeRejectionReason(parsed, scope) || parsed.origin !== origin || parsed.search) continue;
    if (parsed.href.length > MAX_PATH_URL_LENGTH) {
      truncated = true;
      if (match[1].toLowerCase() === 'a') discoveryTruncated = true;
      continue;
    }
    const path = safePath(parsed, url, origin);
    if (!path) continue;
    const source = match[1].toLowerCase() === 'form' ? 'html:form' : 'html:link';
    rows.push({ url: path, source });
    if (source === 'html:link') {
      const next = autoPageCandidate({ url: path, sources: [source] }, { entryUrl: url, origin, scope });
      if (next) candidates.add(next);
    }
  }
  const addDisplayPath = (path, source) => {
    if (found.size >= MAX_DISCOVERED && !found.has(path)) { truncated = true; return; }
    if (!found.has(path)) found.set(path, new Set());
    found.get(path).add(source);
  };
  for (const candidate of candidates) addDisplayPath(candidate, 'html:link');
  for (const row of rows) addDisplayPath(row.url, row.source);
  return { paths: [...found].map(([path, sources]) => ({ url: path, sources: [...sources] })),
    candidates: [...candidates], truncated, discoveryTruncated };
}

async function externalPage(url, scope, request, fingerprint, timeoutMs = 12_000, callerSignal) {
  const signal = callerSignal
    ? AbortSignal.any([AbortSignal.timeout(timeoutMs), callerSignal]) : AbortSignal.timeout(timeoutMs);
  const response = await request(url, { scope, method: 'GET', signal });
  if (response?.contentEncoding && String(response.contentEncoding).toLowerCase() !== 'identity') {
    return { page: emptyPage(url, 'http-response', { code: 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED' }),
      candidates: [], discoveryTruncated: false };
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
  const discovered = externalPaths(html, url, scope.origin, scope);
  const page = { url: redact(url), status,
    contentType: bounded(response?.contentType, 120) || null, title: titleFromHtml(html),
    technologies: list(observed.technologies).slice(0, MAX_COMPONENTS).map(value => component(value)).filter(Boolean),
    libraries: list(observed.libraries).slice(0, MAX_COMPONENTS).map(value => component(value, true)).filter(Boolean),
    forms: [], paths: discovered.paths, errors,
    truncated: response?.truncated === true || discovered.truncated, mode: 'http-response' };
  return { page, candidates: discovered.candidates,
    discoveryTruncated: response?.truncated === true || discovered.discoveryTruncated };
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
    crawl: session.crawl,
    expiresAt: new Date(session.expiresAtMs).toISOString() }));
  function getPreview(id) {
    prune();
    if (typeof id !== 'string') return null;
    const session = sessions.get(id);
    return session ? snapshot(session) : null;
  }
  async function collectOne(session, url, timeoutMs, signal) {
    let page;
    let candidates = [];
    let discoveryTruncated = false;
    let safetyBlocked = false;
    try {
      const pageSignal = signal
        ? AbortSignal.any([AbortSignal.timeout(timeoutMs), signal]) : AbortSignal.timeout(timeoutMs);
      if (session.targetKind === 'lab') {
        ({ page, candidates, discoveryTruncated } = labPage(url,
          (await labCollect(url, { timeoutMs, signal: pageSignal })).info, session));
      } else {
        ({ page, candidates, discoveryTruncated } = await externalPage(url, session.scope,
          externalRequest, externalFingerprint, timeoutMs, pageSignal));
      }
    } catch (failure) {
      if (signal?.aborted) throw fault(499, 'Parser preview request was cancelled.', 'PREVIEW_ABORTED');
      safetyBlocked = session.targetKind === 'external' && SAFETY_FAILURES.has(failure?.code);
      if (safetyBlocked && !session.pages.length) throw failure;
      page = emptyPage(url, session.targetKind === 'lab' ? 'browser' : 'http-response', failure);
    }
    session.urls.add(url);
    session.pages.push(page);
    return { page, candidates, discoveryTruncated, safetyBlocked };
  }
  async function crawl(session, signal) {
    const maxPages = session.crawl.maxPages;
    const duration = session.targetKind === 'external' ? MAX_EXTERNAL_CRAWL_MS : MAX_LAB_CRAWL_MS;
    const deadline = clock() + duration;
    const queue = [session.entryUrl];
    const queued = new Set(queue);
    let dropped = 0;
    let discoveryTruncated = false;
    let stopReason = null;
    while (queue.length && session.pages.length < maxPages) {
      if (signal?.aborted) throw fault(499, 'Parser preview request was cancelled.', 'PREVIEW_ABORTED');
      const remaining = deadline - clock();
      if (remaining <= 0) { stopReason = 'time-limit'; break; }
      const url = queue.shift();
      const collected = await collectOne(session, url,
        Math.max(1, Math.min(remaining, session.targetKind === 'external' ? 12_000 : 15_000)), signal);
      const { page, candidates, safetyBlocked } = collected;
      if (collected.discoveryTruncated) discoveryTruncated = true;
      if (safetyBlocked) { stopReason = 'safety-block'; break; }
      if (!Number.isInteger(page.status) || page.status < 200 || page.status >= 400
        || !/(?:text\/html|application\/xhtml\+xml)/iu.test(page.contentType ?? '')) continue;
      for (const path of candidates) {
        const next = typeof path === 'string' ? path : autoPageCandidate(path, session);
        if (!next || queued.has(next)) continue;
        queued.add(next);
        if (queue.length >= MAX_QUEUED) { dropped += 1; continue; }
        queue.push(next);
      }
    }
    if (!stopReason && queue.length) stopReason = session.pages.length >= maxPages ? 'page-limit' : 'time-limit';
    if (!stopReason && dropped) stopReason = 'candidate-limit';
    if (!stopReason && discoveryTruncated) stopReason = 'page-content-limit';
    session.crawl = { maxPages, visited: session.pages.length, queued: queue.length + dropped,
      truncated: stopReason !== null, stopReason };
    session.expiresAtMs = clock() + LIFETIME_MS;
  }
  async function preview({ url: input, previewId, signal } = {}) {
    prune();
    if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Invalid parser preview signal.');
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
      const dnsSignal = signal
        ? AbortSignal.any([AbortSignal.timeout(12_000), signal]) : AbortSignal.timeout(12_000);
      if (!fixtureId) await publicAddresses(new URL(url).hostname, { signal: dnsSignal });
      const id = idFactory();
      if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/iu.test(id) || sessions.has(id)) {
        throw new TypeError('Invalid parser preview ID.');
      }
      session = { id, targetKind, fixtureId, origin, entryUrl: url, scope,
        pages: [], urls: new Set(), busy: false,
        crawl: { maxPages: targetKind === 'external' ? MAX_EXTERNAL_PAGES : MAX_PAGES,
          visited: 0, queued: 0, truncated: false, stopReason: null },
        expiresAtMs: clock() + LIFETIME_MS };
      sessions.set(id, session);
    }
    if (session.busy) throw fault(409, 'Parser preview is already collecting a URL.', 'PREVIEW_BUSY');
    if (session.urls.has(url)) return snapshot(session);
    if (session.pages.length >= session.crawl.maxPages) {
      throw fault(429, 'Parser preview URL limit reached.', 'PREVIEW_PAGE_LIMIT');
    }
    session.busy = true;
    try {
      if (previewId === undefined) await crawl(session, signal);
      else {
        const { safetyBlocked } = await collectOne(session, url,
          session.targetKind === 'external' ? 12_000 : 15_000, signal);
        session.crawl.visited = session.pages.length;
        if (safetyBlocked) session.crawl = { ...session.crawl, truncated: true, stopReason: 'safety-block' };
        session.expiresAtMs = clock() + LIFETIME_MS;
      }
      return snapshot(session);
    } catch (failure) {
      if (!session.pages.length || signal?.aborted || failure?.code === 'PREVIEW_ABORTED') sessions.delete(session.id);
      throw failure;
    } finally { session.busy = false; }
  }
  return { preview, getPreview };
}
