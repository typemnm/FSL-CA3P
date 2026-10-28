import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, errors as pwErrors } from 'playwright';
import { fingerprintWithin, pageProbes } from './fingerprint.mjs';

export const SCHEMA_VERSION = 'web-parser-1';
export const PROFILE_PREFIX = 'web-parser-';
export const MAX_RESOURCES = 500;
export const MAX_STRUCTURE_ITEMS = 500;
export const MAX_HTML_LENGTH = 5_000_000;
// Applied inside the page before anything crosses CDP, so a hostile page can't blow up the host process (CONTRACT §3).
export const MAX_TEXT_LENGTH = 10_000; // per string value in meta/structure/DOM probes
export const MAX_SNAPSHOT_TEXT = 10_000_000; // all meta/structure strings of one document together
// shortcut: JS global values are matcher input only (versions are short); raise if a pattern needs longer values.
const MAX_JS_VALUE_LENGTH = 1000;
const WAIT_UNTIL = new Set(['load', 'networkidle']);
const MAX_TIMER_MS = 2 ** 31 - 1;
// Budget split (CONTRACT §2): navigation gets 50%, core extraction ends by 70%, JS globals by 80%, DOM probes by 90%,
// the rest is for headers.
const NAV_SHARE = 0.5;
const EXTRACT_SHARE = 0.7;
const JS_SHARE = 0.8;
const PROBE_SHARE = 0.9;
const MAX_EXTRACT_ATTEMPTS = 10;
const WORLD_NAME = 'web-parser';
const HTML_TYPE = /^(text\/html|application\/xhtml\+xml)$/i;

function checkOptions(opts) {
  if (opts != null && typeof opts !== 'object') throw new Error('opts must be an object');
  if (opts != null && 'maxPages' in opts) throw new Error('maxPages: crawling removed: pass endpoints explicitly via collectEach');
  const { timeoutMs = 30000, waitUntil = 'load', userAgent, ignoreHTTPSErrors = true } = opts ?? {};
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMER_MS) throw new Error(`timeoutMs must be an integer in 1..${MAX_TIMER_MS}`);
  if (!WAIT_UNTIL.has(waitUntil)) throw new Error(`waitUntil must be one of: ${[...WAIT_UNTIL].join(', ')}`);
  if (typeof ignoreHTTPSErrors !== 'boolean') throw new Error('ignoreHTTPSErrors must be a boolean');
  if (userAgent !== undefined && typeof userAgent !== 'string') throw new Error('userAgent must be a string');
  return { timeoutMs, waitUntil, userAgent, ignoreHTTPSErrors };
}

// The Agent picks the endpoints (CONTRACT §2): one collect() per URL, in order, each in its own browser session.
export async function collectEach(targetURLs, opts) {
  if (!Array.isArray(targetURLs) || !targetURLs.length || !Array.from(targetURLs).every((u) => typeof u === 'string')) {
    throw new Error('targetURLs must be a non-empty array of URL strings');
  }
  checkOptions(opts);
  const results = [];
  for (const url of targetURLs) {
    try {
      results.push({ url, ok: true, targetInfo: await collect(url, opts) });
    } catch (err) {
      results.push({ url, ok: false, error: { message: err.message } });
    }
  }
  return results;
}

// Collector of exactly one endpoint (it never clicks, types or submits itself; page JS runs as in a normal visit):
// everything is passed through as received (CONTRACT §6, no redaction).
export async function collect(url, opts) {
  const { timeoutMs, waitUntil, userAgent, ignoreHTTPSErrors } = checkOptions(opts);
  const start = new URL(url);
  if (start.protocol !== 'http:' && start.protocol !== 'https:') throw new Error(`unsupported protocol: ${start.protocol}`);

  const info = {
    schemaVersion: SCHEMA_VERSION,
    target: { requestedUrl: start.href, finalUrl: null, origin: null },
    navigation: { status: null, contentType: null, redirectChain: [], loadTimingMs: null, securityDetails: null },
    headers: [],
    cookies: [],
    meta: [],
    html: null,
    technologies: [],
    libraries: [],
    structure: { forms: [], links: [], scripts: [], iframes: [], inputs: [] },
    resources: [],
    errors: [],
    truncated: false,
  };
  const pushResource = (kind, resUrl, status) => {
    if (info.resources.length >= MAX_RESOURCES) info.truncated = true;
    else info.resources.push({ kind, url: resUrl, status });
  };
  const fail = (stage, err) => info.errors.push({ stage, message: `${start.href}: ${err.message}` });

  // Session isolation (CONTRACT §5): own Chromium process + throwaway profile per collect(), never a shared CDP endpoint.
  const profile = await mkdtemp(join(tmpdir(), PROFILE_PREFIX));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      headless: true,
      executablePath: process.env.WEB_PARSER_BROWSER_PATH || undefined,
      userAgent,
      ignoreHTTPSErrors,
    });
    const answered = new WeakSet(); // a request aborted after its response is already recorded
    context.on('response', (r) => { answered.add(r.request()); pushResource(r.request().resourceType(), r.url(), r.status()); });
    context.on('requestfailed', (r) => { if (!answered.has(r)) pushResource(r.resourceType(), r.url(), null); });
    let probes = null; // dataset-driven matcher inputs; a dataset error only costs the fingerprint stage
    try {
      probes = pageProbes();
    } catch (err) {
      info.errors.push({ stage: 'fingerprint', message: err.message });
    }
    const seen = { js: {}, dom: {} };
    const page = context.pages()[0] ?? await context.newPage();
    const cdp = await context.newCDPSession(page);
    const docs = []; // main-frame navigation responses (3xx hops included), in arrival order
    page.on('response', (r) => {
      if (r.frame() === page.mainFrame() && r.request().isNavigationRequest()) docs.push(r);
    });
    // Document identity is the CDP loaderId (a reload of the same URL is a new document): main-frame document
    // responses in arrival order, to pair the extracted document with its response.
    const mainId = (await mainFrame(cdp)).id;
    const loaders = [];
    const navigating = new Set(); // main-frame document requests still waiting for an answer
    cdp.on('Network.requestWillBeSent', (e) => { if (e.type === 'Document' && e.frameId === mainId) navigating.add(e.requestId); });
    cdp.on('Network.loadingFailed', (e) => navigating.delete(e.requestId));
    cdp.on('Network.responseReceived', (e) => {
      navigating.delete(e.requestId);
      if (e.type === 'Document' && e.frameId === mainId) loaders.push({ loaderId: e.loaderId, url: withoutHash(e.response.url) });
    });
    await cdp.send('Network.enable');
    // Chromium holds renderer-bound commands while a main-frame navigation is in flight. A read still waiting at half its
    // slice with an unanswered main-frame document request stops that navigation (browser-side), so the committed
    // document is read; a navigation that answers in time is followed. Applies to every renderer read.
    const guard = (stage, promise, ms) => {
      const timer = setTimeout(() => {
        if (!navigating.size) return;
        fail(stage, new Error('pending navigation stopped'));
        cdp.send('Page.stopLoading').catch(() => {});
      }, ms / 2);
      return bounded(promise, ms).finally(() => clearTimeout(timer));
    };

    const began = Date.now();
    const left = (share) => Math.max(1, Math.round(began + timeoutMs * share - Date.now()));
    let gotoErr = null;
    try {
      await page.goto(start.href, { waitUntil, timeout: left(NAV_SHARE) });
    } catch (err) {
      gotoErr = err;
    }
    info.navigation.loadTimingMs = Date.now() - began;
    const gotoLoader = loaders.at(-1)?.loaderId; // the document goto waited for
    // Policy (CONTRACT §3): reject only when no main-frame response (3xx included) arrived at all.
    if (!docs.length) throw gotoErr ?? new Error('no document response');
    const loadTimedOut = gotoErr instanceof pwErrors.TimeoutError;
    if (gotoErr) fail(loadTimedOut ? 'load' : 'navigate', gotoErr);

    let snap = null;
    // A non-timeout goto failure (download, failed redirect) never committed the document, so there is no DOM to read.
    if (!gotoErr || loadTimedOut) {
      try {
        snap = await bounded(extractSettled(page, cdp, {
          waitUntil, deadline: began + timeoutMs * EXTRACT_SHARE, guard, gotoLoader, onLoadTimeout: () => fail('load', new Error('timeout')),
        }), left(EXTRACT_SHARE));
      } catch (err) {
        fail('extract', err);
      }
    }
    // target/navigation/headers describe the document extraction read; without one, the last response received.
    const finals = docs.filter((r) => !r.request().redirectedTo());
    const responseFor = (loaderId) => {
      const k = loaders.findLastIndex((l) => l.loaderId === loaderId);
      if (k === -1) return null;
      const nth = loaders.slice(0, k).filter((l) => l.url === loaders[k].url).length;
      return finals.filter((r) => withoutHash(r.url()) === loaders[k].url)[nth] ?? null;
    };
    // A document without a response (about:blank, Chromium's error page after a failed client navigation) is the
    // browser's, not target data; so is a non-HTML document's viewer DOM (its own contentType decides, sniffed if absent).
    const paired = snap && responseFor(snap.loaderId);
    if (snap && !paired) fail('extract', new Error(`extracted document has no response (${snap.url})`));
    const isHtml = paired && HTML_TYPE.test(snap.contentType);
    const final = paired || finals.at(-1) || docs.at(-1);
    const chainDocs = finals.includes(final) ? finals.slice(0, finals.indexOf(final) + 1) : [final];
    info.target.finalUrl = final.url();
    info.target.origin = new URL(final.url()).origin;
    info.navigation.status = final.status();
    info.navigation.contentType = final.headers()['content-type'] ?? null;

    if (isHtml) {
      info.meta = snap.meta;
      info.html = snap.html;
      info.structure = snap.structure;
      if (snap.truncated) info.truncated = true;
      // Fingerprint-only reads run after the core snapshot, on their own budget, against the same document.
      if (probes) {
        // Each stage has its own slice; JS globals (the cheap read that carries most versions) go first.
        const read = async (stage, fn, args, share, isolated, what) => {
          try {
            const got = await guard(stage, evaluateIn(cdp, fn, args, left(share), isolated), left(share));
            if (got?.loaderId !== snap.loaderId) throw new Error(`document changed before ${what} were read`);
            seen[stage] = got.value; // matcher input only: its value caps don't set `truncated` (no TargetInfo field is cut)
          } catch (err) {
            fail(stage, err);
          }
        };
        await read('js', readJs, [probes.js, MAX_JS_VALUE_LENGTH], JS_SHARE, false, 'JS globals');
        await read('dom', probeDom, [probes.dom, MAX_TEXT_LENGTH], PROBE_SHARE, true, 'DOM probes');
      }
    }

    try {
      [info.navigation.redirectChain, info.headers, info.navigation.securityDetails] = await bounded(
        Promise.all([documentChain(chainDocs), final.headersArray(), final.securityDetails().then((d) => (d && Object.keys(d).length ? d : null))]),
        left(1),
      );
    } catch (err) {
      fail('headers', err);
    }
    let pageCookies = [];
    try {
      // Output: the whole jar; matcher: only the cookies that apply to the analysed document.
      [info.cookies, pageCookies] = await bounded(Promise.all([context.cookies(), context.cookies(info.target.finalUrl)]), timeoutMs);
    } catch (err) {
      info.errors.push({ stage: 'cookies', message: err.message });
    }
    if (probes) {
      try {
        const { scripts } = info.structure;
        Object.assign(info, await fingerprintWithin({
          url: info.target.finalUrl,
          headers: info.headers,
          cookies: pageCookies.map(({ name, value }) => ({ name, value })),
          meta: info.meta,
          html: info.html,
          scriptSrc: scripts.filter((s) => s.src).map((s) => s.src),
          scripts: scripts.filter((s) => s.inline != null).map((s) => s.inline),
          xhr: info.resources.filter((r) => r.kind === 'xhr' || r.kind === 'fetch').map((r) => r.url),
          ...seen,
        }, timeoutMs));
      } catch (err) {
        info.errors.push({ stage: 'fingerprint', message: err.message });
      }
    }
    return info;
  } finally {
    await context?.close().catch(() => {});
    await rm(profile, { recursive: true, force: true, maxRetries: 5 }).catch(() => {});
  }
}

// Rejects with 'timeout' after ms; the losing promise is left to die with context.close().
function bounded(promise, ms) {
  promise.catch(() => {});
  let timer;
  const expiry = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

// HTTP hops of each document plus a client hop (any page-initiated navigation) between consecutive documents.
async function documentChain(docs) {
  const chain = [];
  for (const [k, res] of docs.entries()) {
    const hops = [];
    for (let req = res.request(); req.redirectedFrom(); req = req.redirectedFrom()) {
      const from = req.redirectedFrom();
      const hop = await from.response();
      hops.unshift({ from: from.url(), to: req.url(), status: hop?.status() ?? null, headers: hop ? await hop.headersArray() : null, kind: 'http' });
    }
    if (k > 0) chain.push({ from: docs[k - 1].url(), to: hops[0]?.from ?? res.url(), status: null, headers: null, kind: 'client' });
    chain.push(...hops);
  }
  return chain;
}

// Extracts from the committed document, re-extracting while a client-side redirect replaces it.
async function extractSettled(page, cdp, { waitUntil, deadline, guard, gotoLoader, onLoadTimeout }) {
  const limits = { maxHtml: MAX_HTML_LENGTH, maxItems: MAX_STRUCTURE_ITEMS, maxText: MAX_TEXT_LENGTH, budget: MAX_SNAPSHOT_TEXT };
  const remaining = () => Math.max(1, deadline - Date.now());
  let waitedFor = null;
  for (let attempt = 0; attempt < MAX_EXTRACT_ATTEMPTS; attempt++) {
    let read = null;
    try {
      read = await guard('extract', evaluateIn(cdp, extractPage, [limits], remaining(), true), remaining());
    } catch (err) {
      if (!/destroyed|Cannot find context|navigat/i.test(err.message)) throw err;
    }
    // A client redirect's landing document may be read mid-parse (body still arriving): wait for it once, as goto
    // does for the first document, then read again.
    const unloaded = read && read.loaderId !== gotoLoader && read.loaderId !== waitedFor && read.value.readyState !== 'complete';
    if (read && !unloaded) return { ...read.value, loaderId: read.loaderId };
    if (read) waitedFor = read.loaderId;
    // Half the time left, so the next attempt still reads what committed even if the new document never loads.
    await page.waitForLoadState(waitUntil, { timeout: remaining() / 2 }).catch(() => {
      if (read) onLoadTimeout(); // the landing DOM read next may be partial, as on a goto load timeout
    });
  }
  throw new Error('document kept navigating');
}

async function mainFrame(cdp) {
  return (await cdp.send('Page.getFrameTree')).frameTree.frame;
}

// Runs fn(...args) in the main frame: isolated world (page scripts can't monkey-patch the DOM APIs it uses, CONTRACT §3)
// or main world. Resolves { loaderId, value }, or null when the document changed meanwhile.
async function evaluateIn(cdp, fn, args, ms, isolated) {
  const frame = await mainFrame(cdp);
  const contextId = isolated
    ? (await cdp.send('Page.createIsolatedWorld', { frameId: frame.id, worldName: WORLD_NAME })).executionContextId
    : undefined;
  let value;
  try {
    value = await evaluate(cdp, { expression: `(${fn})(...${JSON.stringify(args)})`, contextId }, ms);
  } catch (err) {
    if (/destroyed|Cannot find context/i.test(err.message)) return null; // a navigation replaced the document
    throw err;
  }
  return (await mainFrame(cdp)).loaderId === frame.loaderId ? { loaderId: frame.loaderId, value } : null;
}

// Runtime.evaluate that really stops at the deadline: CDP's own timeout terminates a running evaluation, and
// terminateExecution covers one stuck behind page JS, so the renderer is free for the next stage.
async function evaluate(cdp, params, ms) {
  const terminated = (message) => (/Execution was terminated/.test(message) ? 'timeout' : message);
  let res;
  try {
    res = await bounded(cdp.send('Runtime.evaluate', { ...params, returnByValue: true, timeout: ms }), ms);
  } catch (err) {
    if (err.message === 'timeout') cdp.send('Runtime.terminateExecution').catch(() => {});
    throw new Error(terminated(err.message));
  }
  if (res.exceptionDetails) throw new Error(terminated(res.exceptionDetails.exception?.description ?? res.exceptionDetails.text));
  return res.result.value;
}

// Runs inside the page (main world); must stay self-contained.
function readJs(chains, maxLength) {
  const found = {};
  for (const chain of chains) {
    try {
      let value = window;
      for (const key of chain.split('.')) {
        const d = value !== null && (typeof value === 'object' || typeof value === 'function') ? Object.getOwnPropertyDescriptor(value, key) : undefined;
        value = d && 'value' in d ? d.value : undefined;
        if (value === undefined) break;
      }
      if (value === undefined) continue;
      const s = typeof value === 'string' || typeof value === 'number' ? String(value) : String(!!value);
      found[chain] = s.slice(0, maxLength);
    } catch {} // a throwing chain (e.g. a Proxy trap) is skipped
  }
  return found;
}

function withoutHash(href) {
  const u = new URL(href);
  u.hash = '';
  return u.href;
}

// Runs inside the page (isolated world); must stay self-contained. Every string and list is capped here, before the
// result crosses CDP, so the transfer is bounded whatever the page holds (CONTRACT §3).
function extractPage({ maxHtml, maxItems, maxText, budget }) {
  // Read through prototype accessors: forms and document expose named properties the content can clobber.
  const get = (proto, key) => { const g = Object.getOwnPropertyDescriptor(proto, key).get; return (o) => g.call(o); };
  const call = (proto, key) => { const f = proto[key]; return (o, ...args) => f.apply(o, args); };
  const parentOf = get(Node.prototype, 'parentElement');
  const textOf = get(Node.prototype, 'textContent');
  const idOf = get(Element.prototype, 'id');
  const tagOf = get(Element.prototype, 'localName');
  const childrenOf = get(Element.prototype, 'children');
  const elementsOf = get(HTMLFormElement.prototype, 'elements');
  const attr = call(Element.prototype, 'getAttribute');
  const root = get(Document.prototype, 'documentElement')(document);
  const base = get(Node.prototype, 'baseURI')(document);
  const docUrl = get(Document.prototype, 'URL')(document);

  let truncated = false;
  let room = budget;
  const cap = (s) => {
    if (typeof s !== 'string') return s;
    const n = Math.min(s.length, maxText, room);
    room -= n;
    if (n === s.length) return s;
    truncated = true;
    return s.slice(0, n);
  };
  const first = (list) => {
    if (list.length > maxItems) truncated = true;
    return list.slice(0, maxItems);
  };
  const all = (s) => first([...call(Document.prototype, 'querySelectorAll')(document, s)]);

  const path = (el) => {
    const parts = [];
    for (let depth = 0; el && el !== root && depth < 64; depth++, el = parentOf(el)) {
      const id = idOf(el);
      if (id) { parts.unshift(`#${CSS.escape(id)}`); break; }
      const parent = parentOf(el);
      const tag = tagOf(el);
      const sibs = parent ? [...childrenOf(parent)].filter((c) => tagOf(c) === tag) : [el];
      parts.unshift(sibs.length > 1 ? `${tag}:nth-of-type(${sibs.indexOf(el) + 1})` : tag);
    }
    return cap(parts.join(' > '));
  };
  // Resolved absolute URL, plus the attribute value as received when it differs.
  const url = (key, raw) => {
    let value = raw;
    try { if (raw != null) value = new URL(raw, base).href; } catch {}
    return value === raw ? { [key]: cap(value) } : { [key]: cap(value), raw: cap(raw) };
  };
  const html = root ? get(Element.prototype, 'outerHTML')(root) : null;
  if (html && html.length > maxHtml) truncated = true;
  return {
    url: docUrl,
    readyState: get(Document.prototype, 'readyState')(document),
    contentType: get(Document.prototype, 'contentType')(document),
    html: html && html.length > maxHtml ? html.slice(0, maxHtml) : html,
    meta: all('meta[content]').map((m) => {
      const out = {};
      for (const a of ['name', 'property', 'http-equiv', 'itemprop']) if (attr(m, a) != null) out[a] = cap(attr(m, a));
      out.content = cap(attr(m, 'content'));
      return out;
    }),
    structure: {
      forms: all('form').map((f) => {
        const raw = attr(f, 'action');
        // A missing or empty action submits to the document URL (not the <base> URL).
        const action = raw ? url('action', raw).action : cap(docUrl);
        return {
          selector: path(f),
          action,
          ...(raw === action ? {} : { raw: cap(raw) }),
          method: cap((attr(f, 'method') || 'get').toLowerCase()),
          fields: first([...elementsOf(f)].filter((e) => attr(e, 'name'))).map((e) => ({ name: cap(attr(e, 'name')), type: cap(e.type) })),
        };
      }),
      links: all('a[href]').map((a) => ({ ...url('href', attr(a, 'href')), text: cap(textOf(a).trim()) })),
      scripts: all('script').map((s) => {
        const src = attr(s, 'src') ?? attr(s, 'href'); // SVG <script> uses href
        return src != null ? { ...url('src', src), type: cap(attr(s, 'type')) } : { inline: cap(textOf(s)), type: cap(attr(s, 'type')) };
      }),
      iframes: all('iframe').map((f) => ({ ...url('src', attr(f, 'src')), sandbox: cap(attr(f, 'sandbox')) })),
      inputs: all('input, textarea, select').map((e) => ({
        selector: path(e),
        tag: tagOf(e),
        name: cap(attr(e, 'name')),
        type: cap(e.type),
        form: e.form ? path(e.form) : null,
      })),
    },
    truncated,
  };
}

// Runs inside the page (isolated world); must stay self-contained. Fingerprint DOM probes: first match per selector,
// its text when a pattern reads it, and the requested attributes (values capped like extractPage's).
function probeDom(domProbes, maxText) {
  const one = Document.prototype.querySelector;
  const textOf = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').get;
  const { getAttribute, hasAttribute } = Element.prototype;
  const found = {};
  const clip = (s) => s.slice(0, maxText);
  for (const [selector, { attributes, text }] of Object.entries(domProbes)) {
    let el = null;
    try { el = one.call(document, selector); } catch {} // the dataset holds selectors this engine may not parse
    if (!el) continue;
    const attrs = {};
    for (const a of attributes) if (hasAttribute.call(el, a)) attrs[a] = clip(getAttribute.call(el, a));
    found[selector] = { text: text ? clip(textOf.call(el).trim()) : '', attributes: attrs };
  }
  return found;
}
