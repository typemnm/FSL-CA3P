/**
 * Read-only bridge from this repository's web-parser to the general assessment loop.
 * web-parser opens exactly one endpoint in an isolated browser and returns the web
 * information it observes (response, headers, cookies, page structure, loaded
 * resources, Wappalyzer analysis, discovered paths). It does not judge, attack, or
 * crawl; the next endpoint is the model's choice (CONTRACT §1).
 *
 * The returned TargetInfo is an untrusted browser observation, not an API or
 * ownership assertion. Secret redaction is the core's job (redactSensitive), not
 * this module's, so the summary carries observed fields as-is (CONTRACT §6).
 */

import { collect as collectDefault } from '../../../web-parser/collect.mjs';

// Keep an abort that lands during Wappalyzer analysis bounded: the Worker match
// finishes within timeoutMs before the call rejects (CONTRACT §2), so cap at 15s.
export const DEFAULT_TIMEOUT_MS = 15000;
// Section count caps for the model summary; a truncated section carries { shown, total }.
export const MAX_SUMMARY_BYTES = 40 * 1024;
const CAPS = Object.freeze({ redirectChain: 20, headers: 50, cookies: 30, meta: 30,
  technologies: 40, forms: 20, formFields: 20, links: 50, resources: 60, paths: 80 });

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
    errors: info.errors ?? [],
    truncated: info.truncated === true,
  };
}

/**
 * Compact TargetInfo for the model. Fields are taken as-is (no masking); only the
 * item counts are capped, and a capped section keeps { shown, total } so the model
 * sees that it was truncated rather than silently losing entries (CONTRACT §3).
 */
export function summarizeTargetInfo(info, { maxBytes = MAX_SUMMARY_BYTES } = {}) {
  const caps = { ...CAPS };
  // A controlled lab page fits the default caps; shrink the widest sections only if an
  // unusually large page would otherwise exceed the budget. shown/total stays honest.
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const summary = build(info, caps);
    if (Buffer.byteLength(JSON.stringify(summary), 'utf8') <= maxBytes) return summary;
    let widest = null;
    for (const key of Object.keys(caps)) {
      if (caps[key] > 3 && (!widest || caps[key] > caps[widest])) widest = key;
    }
    if (!widest) return summary; // every section already at the floor
    caps[widest] = Math.max(3, Math.floor(caps[widest] / 2));
  }
  return build(info, caps);
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
  const render = () => [lead, ...kept.map((section, index) => `${section.label} `
    + `${shown[index].length}/${section.items.length}: [${shown[index].join(',')}]`)].join('; ');
  const fits = summary => Buffer.byteLength(summary, 'utf8') <= EVIDENCE_SUMMARY_BYTES
    && Buffer.byteLength(JSON.stringify({ ...base, summary }), 'utf8') <= EVIDENCE_JSON_BYTES;
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
  const subject = `web_info ${clean(asset)}${sessionRole ? ` as fixed ${sessionRole}` : ''}`;
  const base = (suffix, kind) => ({ id: suffix ? `${idBase}-${suffix}` : idBase, source, kind, asset });
  const frames = [...list(structure.iframes).map(frame => ({ tag: 'iframe', src: frame.src, sandbox: frame.sandbox })),
    ...list(structure.frames).map(frame => ({ tag: 'frame', src: frame.src }))].filter(frame => frame.src);
  const finalUrl = info.target?.finalUrl;
  const title = extractTitle(info.html);
  const counts = { headers: list(info.headers).length, cookies: list(info.cookies).length,
    technologies: list(info.technologies).length, forms: list(structure.forms).length,
    links: list(structure.links).length, frames: frames.length, resources: list(info.resources).length,
    paths: list(info.paths).length, errors: list(info.errors).length };
  const status = `HTTP ${navigation.status ?? 'no response'} `
    + clean(String(navigation.contentType ?? 'unknown').slice(0, 80));
  if (mode === 'minimal') {
    return [{ ...base('', 'web-info'), summary: `${subject}: ${status}; counts ${JSON.stringify(counts)}`
      + '; details withheld: evidence budget' }].slice(0, Math.max(0, remaining));
  }
  // Lead fields are capped so the lead alone always fits; lists are trimmed by whole items.
  const overview = fitted(base('', 'web-info'), `${subject}: ${status}`
    + (finalUrl && finalUrl !== info.target?.requestedUrl ? `; final ${clean(String(finalUrl).slice(0, 300))}` : '')
    // A control character would JSON-escape to 6 bytes; drop them so the capped lead stays small.
    + (title ? `; title ${encode(title.slice(0, 100).replace(/[\u0000-\u001f\u007f]/gu, ' '))}` : '')
    + `; counts ${JSON.stringify(counts)}`, [
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
  const info = await collectImpl(url, { timeoutMs: budget,
    ...(cookies ? { cookies } : {}), ...(signal ? { signal } : {}) });
  return { info, summary: summarizeTargetInfo(info) };
}
