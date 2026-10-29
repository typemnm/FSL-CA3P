/**
 * Read-only bridge from this repository's web-parser to the general assessment loop.
 * web-parser opens exactly one endpoint in an isolated browser and returns the web
 * information it observes (response, headers, cookies, page structure, loaded
 * resources, Wappalyzer analysis, discovered paths). It does not judge, attack, or
 * crawl; the next endpoint is the model's choice (CONTRACT §1).
 *
 * The returned TargetInfo is an untrusted browser observation, not an API or
 * ownership assertion. Secret redaction is the core's job (redactSensitive), not
 * this module's. The raw TargetInfo stays intact; the model summary is bounded.
 */

import { collect as collectDefault } from '../../../web-parser/collect.mjs';

// Keep an abort that lands during Wappalyzer analysis bounded: the Worker match
// finishes within timeoutMs before the call rejects (CONTRACT §2), so cap at 15s.
export const DEFAULT_TIMEOUT_MS = 15000;
// Section count caps for the model summary; a truncated section carries { shown, total }.
export const MAX_SUMMARY_BYTES = 40 * 1024;
const CAPS = Object.freeze({ redirectChain: 20, headers: 50, cookies: 30, meta: 30,
  technologies: 40, forms: 20, formFields: 20, links: 50, resources: 60, paths: 80, errors: 20 });

const jsonBytes = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const partialCoverage = info => info.truncated === true
  || Array.isArray(info.errors) && info.errors.length > 0
  || Array.isArray(info.resources) && info.resources.some(resource => resource?.status == null)
  || info.navigation?.status == null;

/** Preserve whole Unicode characters and mark strings shortened only in the model-facing copy. */
function shortened(value, maxBytes) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') <= maxBytes) return value;
  const marker = '…';
  const room = Math.max(0, maxBytes - Buffer.byteLength(marker, 'utf8'));
  let prefix = '';
  let bytes = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character, 'utf8');
    if (bytes + size > room) break;
    prefix += character;
    bytes += size;
  }
  return prefix + (maxBytes >= Buffer.byteLength(marker, 'utf8') ? marker : '');
}

function shortenStrings(value, maxBytes) {
  if (typeof value === 'string') return shortened(value, maxBytes);
  if (Array.isArray(value)) return value.map(item => shortenStrings(item, maxBytes));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shortenStrings(item, maxBytes)]));
  }
  return value;
}

/** A plain array when nothing was dropped, else { shown, total, items } so truncation is visible. */
function section(list, cap, map = value => value) {
  const array = Array.isArray(list) ? list : [];
  const items = array.slice(0, cap).map(map);
  return items.length < array.length ? { shown: items.length, total: array.length, items } : items;
}

function extractTitle(html) {
  if (typeof html !== 'string') return null;
  const match = html.slice(0, 50_000).match(/<title[^>]*>([\s\S]*?)<\/title>/iu);
  return match ? match[1].replace(/\s+/gu, ' ').trim().slice(0, 300) || null : null;
}

function build(info, caps) {
  const structure = info.structure ?? {};
  return {
    requestedUrl: info.target?.requestedUrl ?? null,
    finalUrl: info.target?.finalUrl ?? null,
    origin: info.target?.origin ?? null,
    status: info.navigation?.status ?? null,
    contentType: info.navigation?.contentType ?? null,
    title: extractTitle(info.html),
    redirectChain: section(info.navigation?.redirectChain, caps.redirectChain,
      hop => ({ from: hop.from, to: hop.to, status: hop.status, kind: hop.kind })),
    headers: section(info.headers, caps.headers, header => ({ name: header.name, value: header.value })),
    cookies: section(info.cookies, caps.cookies, cookie => ({ name: cookie.name, value: cookie.value,
      domain: cookie.domain, path: cookie.path, httpOnly: cookie.httpOnly,
      secure: cookie.secure, sameSite: cookie.sameSite })),
    meta: section(info.meta, caps.meta),
    technologies: section(info.technologies, caps.technologies, tech => ({ name: tech.name,
      version: tech.version ?? null, categories: tech.categories, confidence: tech.confidence })),
    forms: section(structure.forms, caps.forms, form => ({ action: form.action, method: form.method,
      fields: section(form.fields, caps.formFields, field => ({ name: field.name, type: field.type })) })),
    links: section(structure.links, caps.links, link => link.href),
    resources: section(info.resources, caps.resources, resource => ({ kind: resource.kind,
      method: resource.method, url: resource.url, status: resource.status })),
    // robots/sitemap results surface here too: paths[].sources carries robots:* and sitemap* (CONTRACT §3).
    paths: section(info.paths, caps.paths, path => ({ url: path.url, sources: path.sources,
      methods: path.methods, sameOrigin: path.sameOrigin, params: path.params,
      ...(path.wildcard ? { wildcard: true } : {}) })),
    errors: section(info.errors, caps.errors),
    coverage: { partial: partialCoverage(info) },
    truncated: info.truncated === true,
  };
}

/**
 * Compact TargetInfo for the model. The raw observation is not modified or masked.
 * Count caps and, for unusually large individual fields, string caps keep the
 * execution envelope bounded. A capped section keeps { shown, total }; a string
 * cap is marked with an ellipsis and summaryTruncated so omissions are visible.
 */
export function summarizeTargetInfo(info, { maxBytes = MAX_SUMMARY_BYTES } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 256) throw new RangeError('maxBytes must be at least 256');
  const caps = { ...CAPS };
  // Prefer retaining intact values. Reduce only the item counts needed to fit.
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const summary = build(info, caps);
    if (jsonBytes(summary) <= maxBytes) return summary;
    let widest = null;
    for (const key of Object.keys(caps)) {
      if (caps[key] > 1 && (!widest || caps[key] > caps[widest])) widest = key;
    }
    if (!widest) break;
    caps[widest] = Math.max(1, Math.floor(caps[widest] / 2));
  }
  const summary = build(info, caps);
  for (const stringBytes of [2048, 1024, 512, 256, 128, 64, 32]) {
    const bounded = { ...shortenStrings(summary, stringBytes), summaryTruncated: true };
    if (jsonBytes(bounded) <= maxBytes) return bounded;
  }
  // The smallest summary still tells the model that detail was omitted. This also
  // bounds pathological nested fields such as a single enormous error message.
  const minimal = { requestedUrl: shortened(info.target?.requestedUrl ?? '', 80),
    finalUrl: shortened(info.target?.finalUrl ?? '', 80), status: info.navigation?.status ?? null,
    coverage: { partial: true }, truncated: true, summaryTruncated: true,
    detail: 'omitted: summary byte budget' };
  if (jsonBytes(minimal) <= maxBytes) return minimal;
  return { coverage: { partial: true }, truncated: true, summaryTruncated: true };
}

// The core ends the whole run on an evidence item whose summary exceeds 2048 UTF-8 bytes
// or whose JSON exceeds 4096 bytes, so keep a margin under both.
export const EVIDENCE_SUMMARY_BYTES = 1900;
const EVIDENCE_JSON_BYTES = 3900;
// Response headers whose value is a session or credential; only the name enters evidence.
const SECRET_HEADER = /^(?:proxy-)?authorization$|cookie|token|secret|session|api-?key/iu;

const list = value => Array.isArray(value) ? value : [];
// Drop null and empty-array fields so the model-facing items stay short.
const compact = value => Object.fromEntries(Object.entries(value)
  .filter(([, item]) => item != null && !(Array.isArray(item) && !item.length)));
const capped = (items, cap) => items.length > cap ? [...items.slice(0, cap), `+${items.length - cap} more`] : items;

/**
 * `lead; label shown/total: [item,...]`, adding whole JSON items while the summary and the
 * evidence JSON stay under the core limits. An item that does not fit is skipped, never cut,
 * so every list stays valid JSON and shown/total stays honest.
 */
function fitted(base, lead, sections) {
  const kept = sections.filter(section => section.items.length);
  const shown = kept.map(() => []);
  let boundedLead = lead;
  const render = () => [boundedLead, ...kept.map((section, index) => `${section.label} `
    + `${shown[index].length}/${section.items.length}: [${shown[index].join(',')}]`)].join('; ');
  const fits = summary => Buffer.byteLength(summary, 'utf8') <= EVIDENCE_SUMMARY_BYTES
    && Buffer.byteLength(JSON.stringify({ ...base, summary }), 'utf8') <= EVIDENCE_JSON_BYTES;
  while (!fits(render()) && Buffer.byteLength(boundedLead, 'utf8') > 3) {
    boundedLead = shortened(boundedLead, Math.floor(Buffer.byteLength(boundedLead, 'utf8') / 2));
  }
  if (!fits(render())) return { ...base, summary: 'web_info detail omitted: evidence byte budget' };
  kept.forEach((section, index) => {
    for (const item of section.items) {
      shown[index].push(item);
      if (!fits(render())) shown[index].pop();
    }
  });
  return { ...base, summary: render() };
}

/**
 * Up to `remaining` (max 3) evidence items the model reads, in priority order: overview,
 * discovered paths, page surface. The caller passes its own `safeText`/`safeHeaderValue`
 * so the masking matches its other tools; every string value is masked before serialization. Response bodies, cookie values and secret
 * header values are never included; robots/sitemap content arrives as paths[].sources.
 * `mode: 'minimal'` returns only a one-line overview (status, content type, list counts)
 * for a caller whose evidence budget is spent.
 */
export function evidenceFromTargetInfo(info, { idBase, source, asset, sessionRole, remaining = 3,
  mode = 'full', safeText = String, safeHeaderValue = String } = {}) {
  // Masking serialized JSON would let the core's `[^\s,;]+` value pattern run past a closing
  // quote; `token [redacted]` (no `=`) is also left alone when the core masks the summary again.
  const clean = value => safeText(String(value)).replaceAll('=[redacted]', ' [redacted]');
  const encode = value => JSON.stringify(value, (key, item) => typeof item === 'string' ? clean(item) : item);
  const structure = info.structure ?? {};
  const navigation = info.navigation ?? {};
  const relative = url => {
    try {
      const parsed = new URL(url);
      return parsed.origin === info.target?.origin ? parsed.pathname + parsed.search : url;
    } catch { return url; }
  };
  // The core accepts at most 512 UTF-8 bytes for evidence.asset. The full path
  // stays in the raw TargetInfo; only the evidence label is shortened.
  const evidenceAsset = shortened(clean(asset), 480);
  const subject = `web_info ${evidenceAsset}${sessionRole ? ` as fixed ${shortened(clean(sessionRole), 80)}` : ''}`;
  const base = (suffix, kind) => ({ id: suffix ? `${idBase}-${suffix}` : idBase,
    source, kind, asset: evidenceAsset });
  const frames = [...list(structure.iframes).map(frame => ({ tag: 'iframe', src: frame.src, sandbox: frame.sandbox })),
    ...list(structure.frames).map(frame => ({ tag: 'frame', src: frame.src }))].filter(frame => frame.src);
  const finalUrl = info.target?.finalUrl;
  const title = extractTitle(info.html);
  const counts = { headers: list(info.headers).length, cookies: list(info.cookies).length,
    technologies: list(info.technologies).length, forms: list(structure.forms).length,
    links: list(structure.links).length, frames: frames.length, resources: list(info.resources).length,
    paths: list(info.paths).length, errors: list(info.errors).length };
  const status = `HTTP ${navigation.status ?? 'no response'} `
    + shortened(clean(String(navigation.contentType ?? 'unknown')), 160);
  const origin = `origin=${shortened(clean(String(info.target?.origin ?? 'unknown')), 180)}`;
  const coverage = `coverage.partial=${partialCoverage(info)}`;
  if (mode === 'minimal') {
    return [{ ...base('', 'web-info'), summary: `${subject}: ${status}; counts ${JSON.stringify(counts)}`
      + `; ${origin}; ${coverage}; details withheld: evidence budget` }].slice(0, Math.max(0, remaining));
  }
  // Lead fields are capped so the lead alone always fits; lists are trimmed by whole items.
  const overview = fitted(base('', 'web-info'), `${subject}: ${status}`
    + (finalUrl && finalUrl !== info.target?.requestedUrl
      ? `; final ${shortened(clean(String(finalUrl)), 256)}` : '')
    // A control character would JSON-escape to 6 bytes; drop them so the capped lead stays small.
    + (title ? `; title ${encode(shortened(title.replace(/[\u0000-\u001f\u007f]/gu, ' '), 200))}` : '')
    + `; counts ${JSON.stringify(counts)}; ${origin}; ${coverage}`, [
    { label: 'redirects', items: list(navigation.redirectChain)
      .map(hop => encode(compact({ kind: hop.kind, status: hop.status }))) },
    { label: 'technologies', items: list(info.technologies).map(tech => encode(compact({
      name: tech.name, version: tech.version, categories: tech.categories }))) },
    { label: 'error stages', items: [...new Set(list(info.errors).map(error => error.stage))]
      .map(stage => encode(stage)) },
  ]);
  const paths = [...list(info.paths)].sort((a, b) => (b.sameOrigin === true) - (a.sameOrigin === true))
    .map(path => encode(compact({ url: relative(path.url), sources: path.sources,
      methods: path.methods, params: capped(list(path.params), 20), wildcard: path.wildcard || null })));
  const surface = [
    { label: 'forms', items: list(structure.forms).map(form => encode(compact({
      action: relative(form.action), method: form.method,
      fields: capped(list(form.fields).map(field => compact({ name: field.name, type: field.type })), 30) }))) },
    { label: 'frames', items: frames.map(frame => encode(compact({ ...frame, src: relative(frame.src) }))) },
    { label: 'headers', items: list(info.headers).map(header => encode(SECRET_HEADER.test(header.name)
      ? { name: header.name } : { name: header.name, value: safeHeaderValue(header.value ?? '') })) },
    { label: 'cookies (names and attributes only)', items: list(info.cookies).map(cookie => encode(compact({
      name: cookie.name, httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite,
      path: cookie.path, domain: cookie.domain }))) },
  ];
  return [
    overview,
    paths.length ? fitted(base('paths', 'web-info-paths'),
      `${subject} discovered paths, same-origin first and shown as path only`,
      [{ label: 'paths', items: paths }]) : null,
    surface.some(section => section.items.length) ? fitted(base('surface', 'web-info-surface'),
      `${subject} page surface; response body, cookie values and secret header values are not retained`,
      surface) : null,
  ].filter(Boolean).slice(0, Math.max(0, remaining));
}

/**
 * Open one endpoint and return its raw TargetInfo plus a model-sized summary.
 * `collectImpl` is injectable for unit tests; the default is the real web-parser.
 */
export async function collectWebInfo(url, { cookies, signal, timeoutMs = DEFAULT_TIMEOUT_MS,
  collectImpl = collectDefault } = {}) {
  const budget = Math.min(timeoutMs, DEFAULT_TIMEOUT_MS);
  // The general loop is authorized for one origin, including public observations.
  // Keep every redirect hop and browser resource inside it.
  const info = await collectImpl(url, { timeoutMs: budget, sameOriginOnly: true,
    ...(cookies ? { cookies } : {}),
    ...(signal ? { signal } : {}) });
  return { info, summary: summarizeTargetInfo(info) };
}
