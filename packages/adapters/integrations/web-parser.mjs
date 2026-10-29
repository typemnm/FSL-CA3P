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
