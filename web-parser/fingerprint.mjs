import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Worker } from 'node:worker_threads';

// Wappalyzer matching logic from wapalyzer-core (CJS entry; its ESM entry uses the removed `assert` import syntax),
// fed with the enthec/webappanalyzer dataset (downloaded by scripts/fetch-dataset.mjs) instead of the package's bundled data.
const { Wappalyzer } = createRequire(import.meta.url)('wapalyzer-core');
const DATA = new URL('./data/webappanalyzer/', import.meta.url);
// categories.json ids reported as libraries: JavaScript frameworks, Web frameworks, JavaScript graphics,
// Mobile frameworks, JavaScript libraries, UI frameworks (24 Rich text editors deliberately left out, CONTRACT §3).
export const LIBRARY_CATEGORIES = new Set([12, 18, 25, 26, 59, 66]);
// Matcher input cap for html/scripts (this module's own bound): head and tail, similar in shape to the Wappalyzer
// driver's html sampling (whose window is far larger, ~3M + 3M chars). The dataset's
// `<[^>]{1,250}` patterns cost ~250 steps per unclosed '<', so this bounds a page-controlled worst case.
export const MATCH_SAMPLE_LENGTH = 50_000;
const sample = (s) => (s.length > MATCH_SAMPLE_LENGTH ? s.slice(0, MATCH_SAMPLE_LENGTH / 2) + s.slice(-MATCH_SAMPLE_LENGTH / 2) : s);

let loaded = false;
function load() {
  if (loaded) return;
  const read = (path) => JSON.parse(readFileSync(new URL(path, DATA), 'utf8'));
  const dir = new URL('technologies/', DATA);
  const technologies = Object.assign({}, ...readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => read(`technologies/${f}`)));
  Wappalyzer.setCategories(read('categories.json'));
  Wappalyzer.setTechnologies(technologies);
  loaded = true;
}

// Every technology, including the ones wapalyzer-core holds back until their `requires`/`requiresCategory` is met.
function allTechnologies() {
  load();
  return [Wappalyzer.technologies, ...Wappalyzer.requires.map((r) => r.technologies),
    ...Wappalyzer.categoryRequires.map((r) => r.technologies)].flat();
}

// What collect() must read in the page: JS global chains (main world) and DOM selector specs (isolated world).
let probes;
export function pageProbes() {
  if (probes) return probes;
  const js = new Set();
  const dom = {};
  for (const tech of allTechnologies()) {
    for (const chain of Object.keys(tech.js)) js.add(chain);
    for (const [selector, patterns] of Object.entries(tech.dom)) {
      const probe = dom[selector] ?? { attributes: [], text: false };
      for (const p of patterns) {
        for (const a of Object.keys(p.attributes ?? {})) if (!probe.attributes.includes(a)) probe.attributes.push(a);
        probe.text ||= Boolean(p.text);
      }
      dom[selector] = probe;
    }
  }
  probes = { js: [...js], dom };
  return probes;
}

// xhr patterns are host/path patterns: a host-like string in a query parameter must not match.
function hostPath(href) {
  try {
    const u = new URL(href);
    return u.hostname + u.pathname;
  } catch {
    return href;
  }
}

// wapalyzer-core's analyze() has no js/dom relations (the extension driver did those); same detection shape here.
function detect(technology, type, key, pattern, value) {
  const matches = pattern.regex.exec(value);
  return matches && { technology, pattern: { ...pattern, type, key, value, match: matches[0] }, version: Wappalyzer.resolveVersion(pattern, value) };
}

// analyzeManyToMany doesn't report which header/cookie/meta name matched; the pattern object identifies it.
const KEYED = new Set(['headers', 'cookies', 'meta']);
function keyOf({ technology, pattern }) {
  if (pattern.key !== undefined || !KEYED.has(pattern.type)) return pattern.key;
  return Object.keys(technology[pattern.type]).find((k) => technology[pattern.type][k].some((p) => p.regex === pattern.regex));
}

function analyzePage(items, technologies) {
  const found = Wappalyzer.analyze(items, technologies);
  for (const tech of technologies) {
    for (const [chain, patterns] of Object.entries(tech.js)) {
      if (Object.hasOwn(items.js, chain)) for (const p of patterns) found.push(detect(tech, 'js', chain, p, items.js[chain]));
    }
    for (const [selector, patterns] of Object.entries(tech.dom)) {
      const node = items.dom[selector];
      if (!node) continue;
      for (const { exists, text, attributes } of patterns) {
        if (exists) found.push(detect(tech, 'dom', selector, exists, ''));
        if (text && node.text) found.push(detect(tech, 'dom', selector, text, node.text));
        for (const [name, p] of Object.entries(attributes ?? {})) {
          if (Object.hasOwn(node.attributes, name)) found.push(detect(tech, 'dom', selector, p, node.attributes[name]));
        }
      }
    }
  }
  return found.filter(Boolean);
}

// input: { url, headers:[{name,value}], cookies:[{name,value}], meta:[{name?,property?,content}], html, scriptSrc:[],
//          scripts:[], js:{chain:string}, dom:{selector:{text, attributes}}, xhr:[] } -> { technologies, libraries }
// Synchronous and page-controlled in cost: collect() runs it through fingerprintWithin().
export function fingerprint(input) {
  load();
  const multi = (pairs) => {
    const out = Object.create(null); // page-controlled names like `constructor` / `__proto__` are plain keys
    for (const [k, v] of pairs) if (k != null) (out[k.toLowerCase()] ??= []).push(v ?? '');
    return out;
  };
  const items = {
    url: input.url ?? '',
    headers: multi(input.headers.map((h) => [h.name, h.value])),
    cookies: multi(input.cookies.map((c) => [c.name, c.value])),
    meta: multi(input.meta.map((m) => [m.name ?? m.property, m.content])),
    html: sample(input.html ?? ''),
    scriptSrc: input.scriptSrc,
    scripts: sample(input.scripts.join('\n')),
    xhr: input.xhr.map(hostPath).join('\n'),
    js: input.js,
    dom: input.dom,
  };

  // Same pattern matching the same value counts once (a repeated weak signal must not reach full confidence).
  const detections = [];
  const seen = new Set();
  const add = (found) => {
    for (const d of found) {
      const id = `${d.technology.name}|${d.pattern.type}|${keyOf(d)}|${d.pattern.regex}|${d.version}`;
      if (!seen.has(id)) { seen.add(id); detections.push(d); }
    }
  };
  add(analyzePage(items, Wappalyzer.technologies));
  // `requires` / `requiresCategory` groups unlock from the resolved set (implies and excludes applied), repeated until
  // nothing new unlocks, as the Wappalyzer driver does.
  const analyzed = new Set(Wappalyzer.technologies.map((t) => t.name));
  for (;;) {
    const resolved = Wappalyzer.resolve(detections);
    const names = new Set(resolved.map((t) => t.name));
    const cats = new Set(resolved.flatMap((t) => t.categories.map((c) => c.id)));
    const gated = [...Wappalyzer.requires.filter((r) => names.has(r.name)),
      ...Wappalyzer.categoryRequires.filter((r) => cats.has(r.categoryId))]
      .flatMap((r) => r.technologies).filter((t) => !analyzed.has(t.name));
    if (!gated.length) break;
    for (const t of gated) analyzed.add(t.name);
    add(analyzePage(items, [...new Set(gated)]));
  }

  const evidence = new Map();
  for (const d of detections) {
    const { technology: { name }, pattern } = d;
    const key = keyOf(d);
    const list = evidence.get(name) ?? [];
    if (!list.some((e) => e.field === pattern.type && e.key === key && e.match === pattern.match)) {
      list.push(key === undefined ? { field: pattern.type, match: pattern.match } : { field: pattern.type, key, match: pattern.match });
    }
    evidence.set(name, list);
  }
  const resolved = Wappalyzer.resolve(detections);
  const impliedBy = new Map();
  for (const t of resolved) for (const i of Wappalyzer.getTechnology(t.name).implies) if (!impliedBy.has(i.name)) impliedBy.set(i.name, t.name);
  const technologies = resolved.map((t) => ({
    name: t.name,
    categories: t.categories.map((c) => c.name),
    version: t.version || null,
    confidence: t.confidence,
    evidence: evidence.get(t.name) ?? [{ field: 'implies', match: impliedBy.get(t.name) ?? null }],
    categoryIds: t.categories.map((c) => c.id),
  }));
  // The pinned Wappalyzer data has no Spring Boot entry. Its explicit public
  // X-Powered-By header is a useful framework hint for the Wonchang fixture.
  const springHeader = items.headers['x-powered-by']?.map((value) =>
    /^Spring Boot(?:[ /](\d+(?:\.\d+){0,3}))?$/iu.exec(value.trim())).find(Boolean);
  if (springHeader && !technologies.some((t) => t.name === 'Spring Boot')) {
    technologies.push({ name: 'Spring Boot', categories: ['Web frameworks'],
      version: springHeader[1] ?? null, confidence: 75,
      evidence: [{ field: 'headers', key: 'x-powered-by', match: 'Spring Boot' }], categoryIds: [18] });
  }
  return {
    technologies: technologies.map(({ categoryIds, ...t }) => t),
    libraries: technologies.filter((t) => t.categoryIds.some((id) => LIBRARY_CATEGORIES.has(id)))
      .map(({ name, version, evidence }) => ({ name, version, source: 'fingerprint', evidence })),
  };
}

// Runs fingerprint() in a worker so a pathological page can't freeze the caller's event loop; the worker is
// terminated at the deadline (rejects with 'timeout'). Dataset load errors reject too. One idle worker is kept warm
// (unref'd, so it never holds the process open); a concurrent call gets its own, a terminated one is replaced.
let idle = null;
export function fingerprintWithin(input, ms) {
  return new Promise((resolve, reject) => {
    let worker = idle;
    idle = null;
    if (!worker) {
      worker = new Worker(new URL('./fingerprint-worker.mjs', import.meta.url));
      worker.on('error', () => {}); // reported to the caller in flight below; an idle crash only drops the worker
      worker.once('exit', () => { if (idle === worker) idle = null; });
    }
    worker.ref();
    const onMessage = ({ result, error }) => settle(error === undefined, error === undefined ? result : new Error(error));
    const onError = (err) => settle(false, err, true);
    const onExit = (code) => settle(false, new Error(`fingerprint worker exited (${code})`), true);
    const timer = setTimeout(() => settle(false, new Error('timeout'), true), ms);
    function settle(ok, value, kill = false) {
      clearTimeout(timer);
      worker.off('message', onMessage).off('error', onError).off('exit', onExit);
      if (kill || idle) worker.terminate();
      else { worker.unref(); idle = worker; }
      (ok ? resolve : reject)(value);
    }
    worker.on('message', onMessage).on('error', onError).on('exit', onExit);
    worker.postMessage(input);
  });
}
