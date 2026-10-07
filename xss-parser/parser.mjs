import { existsSync } from 'node:fs';
import { chromium } from 'playwright';
import { readDom } from './dom.mjs';
import { analyzeScript } from './script-hints.mjs';

const CHROME_ON_MAC = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ACTION_LINK = /(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|탈퇴|로그아웃|삭제)/i;

function checkLocalUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Provide a valid local --url.'); }
  if (!['http:', 'https:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname) ||
    url.username || url.password) {
    throw new Error('--url must be an http(s) loopback URL: localhost, 127.0.0.1, or [::1].');
  }
  return url;
}

function displayUrl(value) {
  const url = new URL(value);
  const path = url.pathname.split('/').map(part => {
    if (/^\d+$/.test(part)) return '{number}';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(part)) return '{uuid}';
    if (/^[a-z0-9_-]{24,}$/i.test(part)) return '{token}';
    return part;
  }).join('/');
  const names = [...new Set(url.searchParams.keys())];
  return url.origin + path + (names.length ? '?' + names.map(name =>
    encodeURIComponent(name) + '={value}').join('&') : '') + (url.hash ? '#{fragment}' : '');
}

function displayStaticApiUrl(value) {
  return displayUrl(value).replace(/%7B([a-zA-Z_$][\w.$]*)%7D/gi, '{$1}');
}

function rememberQueryValues(values, value) {
  try {
    for (const item of new URL(value).searchParams.values()) if (item.length >= 4) values.add(item);
  } catch { /* Ignore non-URLs. */ }
}

function redactValues(value, values) {
  if (typeof value === 'string') {
    let result = value;
    for (const secret of values) result = result.replaceAll(secret, '{query-value}');
    return result;
  }
  if (Array.isArray(value)) return value.map(item => redactValues(item, values));
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) value[key] = redactValues(item, values);
  }
  return value;
}

function validateOptions(options) {
  for (const [key, min, max] of [['maxPages', 1, 30], ['waitMs', 0, 5000], ['timeoutMs', 1000, 30000]]) {
    if (options[key] !== undefined &&
      (!Number.isInteger(options[key]) || options[key] < min || options[key] > max)) {
      throw new Error(key + ' must be an integer from ' + min + ' to ' + max + '.');
    }
  }
  if (options.readySelector !== undefined &&
    (typeof options.readySelector !== 'string' || !options.readySelector.trim() ||
      options.readySelector.length > 256)) {
    throw new Error('readySelector must be a nonempty CSS selector of at most 256 characters.');
  }
  if (options.signal !== undefined &&
    (!options.signal || typeof options.signal.aborted !== 'boolean' ||
      typeof options.signal.addEventListener !== 'function' ||
      typeof options.signal.removeEventListener !== 'function')) {
    throw new Error('signal must be an AbortSignal.');
  }
}

function abortError(signal) {
  const error = new Error('xss-parser scan aborted.', { cause: signal?.reason });
  error.name = 'AbortError';
  return error;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

function awaitWithSignal(promise, signal, onLateResolve) {
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    let settled = false;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      Promise.resolve(promise).then(value => {
        if (onLateResolve) Promise.resolve().then(() => onLateResolve(value)).catch(() => {});
      }, () => {});
      reject(abortError(signal));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    Promise.resolve(promise).then(value => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      resolve(value);
    }, error => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      reject(error);
    });
  });
}

function pageFromDom(id, pageUrl, dom, queryValues) {
  const areas = dom.areas.map((area, index) => ({
    id: id + '-area-' + (index + 1),
    name: area.name,
    kind: area.kind,
    selector: area.selector,
    parent: area.parentIndex === null ? null : id + '-area-' + (area.parentIndex + 1),
    forms: area.forms.map(form => {
      rememberQueryValues(queryValues, form.htmlAction);
      return { ...form, htmlAction: displayUrl(form.htmlAction) };
    }),
    fields: area.fields,
    buttons: area.buttons,
    links: area.links.map(link => {
      rememberQueryValues(queryValues, link.url);
      return { text: link.text, url: displayUrl(link.url), visited: false };
    }),
    outputs: area.outputs
  }));
  return { id, url: displayUrl(pageUrl), title: dom.title, areas, posts: dom.posts };
}

function compactReport(report) {
  for (const page of report.pages) {
    for (const area of page.areas) {
      for (const form of area.forms) if (!form.fields.length) delete form.fields;
      for (const key of ['forms', 'fields', 'buttons', 'links', 'outputs']) {
        if (!area[key].length) delete area[key];
      }
    }
    for (const post of page.posts || []) if (!post.buttons.length) delete post.buttons;
    for (const key of ['areas', 'posts', 'behaviors', 'renderRules', 'observedRequests']) {
      if (Array.isArray(page[key]) && !page[key].length) delete page[key];
    }
  }
}

export async function scan(inputUrl, options = {}) {
  const seed = checkLocalUrl(inputUrl);
  validateOptions(options);
  const signal = options.signal;
  throwIfAborted(signal);
  const maxPages = options.maxPages ?? 10;
  const waitMs = options.waitMs ?? 500;
  const timeoutMs = options.timeoutMs ?? 10000;
  const chromePath = options.browserPath || process.env.XSS_PARSER_BROWSER_PATH ||
    (existsSync(CHROME_ON_MAC) ? CHROME_ON_MAC : undefined);
  const browser = await awaitWithSignal(
    chromium.launch({ headless: !options.headed,
      ...(chromePath ? { executablePath: chromePath } : {}) }),
    signal,
    lateBrowser => lateBrowser.close().catch(() => {}),
  );
  const report = { schemaVersion: '3.4', startUrl: displayUrl(seed), pages: [], summary: {} };
  const queryValues = new Set();
  rememberQueryValues(queryValues, seed.href);
  const queue = [seed.href];
  const queued = new Set(queue);
  const visited = new Set();
  let elementListsTruncated = false;
  let scriptListsTruncated = false;
  let activeScriptBodies = null;
  let context;
  let closeOnAbort;
  const onAbort = () => {
    closeOnAbort ??= (async () => {
      try { await context?.close(); } catch { /* Closing can race an in-flight page request. */ }
      try { await browser.close(); } catch { /* The browser may already be closed. */ }
    })();
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    throwIfAborted(signal);
    context = await awaitWithSignal(browser.newContext({ serviceWorkers: 'block', acceptDownloads: false }), signal,
      lateContext => lateContext.close().catch(() => {}));
    context.setDefaultTimeout(timeoutMs);
    await awaitWithSignal(context.routeWebSocket('**/*', socket => socket.close()), signal);
    await awaitWithSignal(context.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== seed.origin || !READ_METHODS.has(request.method())) {
        await route.abort().catch(() => {});
        return;
      }
      try {
        const response = await route.fetch({ maxRedirects: 0, timeout: timeoutMs });
        if (activeScriptBodies && request.resourceType() === 'script') {
          if (activeScriptBodies.size >= 30 || Number(response.headers()['content-length'] || 0) > 1_000_000) {
            scriptListsTruncated = true;
          } else {
            const body = await response.body();
            if (body.length <= 1_000_000) activeScriptBodies.set(request.url(), body.toString('utf8'));
            else scriptListsTruncated = true;
          }
        }
        if (response.status() >= 300 && response.status() < 400) {
          await route.fulfill({ status: 403, body: '' });
        } else {
          await route.fulfill({ response });
        }
      } catch {
        await route.abort().catch(() => {});
      }
    }), signal);
    throwIfAborted(signal);
    while (queue.length && report.pages.length < maxPages) {
      throwIfAborted(signal);
      const next = queue.shift();
      if (visited.has(next)) continue;
      visited.add(next);
      const page = await awaitWithSignal(context.newPage(), signal,
        latePage => latePage.close().catch(() => {}));
      page.setDefaultNavigationTimeout(timeoutMs);
      const id = 'page-' + (report.pages.length + 1);
      const scriptBodies = new Map();
      const observedRequests = [];
      activeScriptBodies = scriptBodies;
      page.on('response', response => {
        const request = response.request();
        if (!['fetch', 'xhr'].includes(request.resourceType())) return;
        if (observedRequests.length >= 30) { scriptListsTruncated = true; return; }
        try {
          if (new URL(request.url()).origin !== seed.origin || !READ_METHODS.has(request.method())) return;
          rememberQueryValues(queryValues, request.url());
          observedRequests.push({ method: request.method(), url: displayUrl(request.url()),
            status: response.status() });
        } catch { /* Ignore malformed request URLs. */ }
      });
      try {
        await awaitWithSignal(page.goto(next, { waitUntil: 'domcontentloaded' }), signal);
        if (options.readySelector) {
          await awaitWithSignal(page.waitForSelector(options.readySelector, { timeout: timeoutMs }), signal);
        }
        if (waitMs) await awaitWithSignal(page.waitForTimeout(waitMs), signal);
        throwIfAborted(signal);
        if (new URL(page.url()).origin !== seed.origin) throw new Error('Navigation left the start origin.');
        const dom = await awaitWithSignal(page.evaluate(readDom, { includeBodyPreview: !options.hideBody }), signal);
        elementListsTruncated ||= dom.counts.areas > 100 || dom.counts.forms > 80 ||
          dom.counts.fields > 250 || dom.counts.buttons > 150 ||
          dom.counts.links > 250 || dom.counts.outputs > 100 || dom.counts.posts > 50;
        const reportPage = pageFromDom(id, page.url(), dom, queryValues);
        const scripts = await awaitWithSignal(page.evaluate(() => [...document.scripts].map((script, index) => ({
          url: script.src || location.href + '#inline-' + (index + 1),
          source: script.src ? null : (script.textContent || '').slice(0, 1_000_001),
          external: !!script.src,
          type: script.type
        }))), signal);
        let externalCount = 0, inlineCount = 0;
        const behaviors = [];
        for (const script of scripts) {
          if (script.type && !['module', 'text/javascript', 'application/javascript'].includes(script.type)) continue;
          if (script.external ? ++externalCount > 30 : ++inlineCount > 20) {
            scriptListsTruncated = true;
            continue;
          }
          if (new URL(script.url).origin !== seed.origin) continue;
          const source = script.external ? scriptBodies.get(script.url) : script.source;
          if (!source) { scriptListsTruncated = true; continue; }
          const result = analyzeScript(source, script.url, page.url());
          scriptListsTruncated ||= result.truncated;
          for (const behavior of result.behaviors) {
            if (behaviors.length >= 60) { scriptListsTruncated = true; break; }
            behaviors.push({ ...behavior, script: displayUrl(behavior.script),
              api: behavior.api.map(api => ({ ...api, url: displayStaticApiUrl(api.url) })) });
          }
        }
        reportPage.behaviors = behaviors;
        reportPage.observedRequests = observedRequests;
        const renderRules = [];
        const ruleIds = new Map();
        for (const behavior of behaviors) {
          const refs = [];
          for (const update of behavior.updates) {
            const key = JSON.stringify(update);
            let ruleId = ruleIds.get(key);
            if (!ruleId) {
              ruleId = id + '-render-' + (renderRules.length + 1);
              ruleIds.set(key, ruleId);
              renderRules.push({ id: ruleId, ...update, evidence: 'static-js' });
            }
            refs.push(ruleId);
          }
          delete behavior.updates;
          if (refs.length) behavior.renderRefs = refs;
        }
        reportPage.renderRules = renderRules;
        const bodyRenderRules = renderRules.filter(rule =>
          ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'textContent'].includes(rule.operation));
        for (const post of reportPage.posts) {
          if (!post.body) continue;
          const matched = bodyRenderRules.find(rule => post.body.matchSelectors.includes(rule.selector) ||
            post.body.selector === rule.selector);
          if (matched) post.body.renderRef = matched.id;
          delete post.body.matchSelectors;
        }
        report.pages.push(reportPage);
        for (const area of dom.areas) {
          for (const link of area.links) {
            let target;
            try { target = new URL(link.url); } catch { continue; }
            if (target.origin !== seed.origin || ACTION_LINK.test(target.pathname + ' ' + link.text)) continue;
            target.hash = '';
            if (!queued.has(target.href) && !visited.has(target.href)) {
              queue.push(target.href);
              queued.add(target.href);
            }
          }
        }
      } catch (error) {
        throwIfAborted(signal);
        report.pages.push({ id, url: displayUrl(next), title: null, areas: [],
          error: error.message.slice(0, 180) });
      } finally {
        activeScriptBodies = null;
        try { await page.close(); } catch { /* Aborting may already have closed the browser. */ }
      }
    }
    throwIfAborted(signal);
    const visitedUrls = new Set(report.pages.filter(page => !page.error).map(page => page.url));
    for (const page of report.pages) {
      for (const area of page.areas) {
        for (const link of area.links) {
          const withoutHash = new URL(link.url);
          withoutHash.hash = '';
          link.visited = visitedUrls.has(withoutHash.href);
        }
      }
    }
    const allAreas = report.pages.flatMap(page => page.areas);
    report.summary = {
      scope: 'visited-client-pages',
      pages: report.pages.length,
      areas: allAreas.length,
      forms: allAreas.reduce((sum, area) => sum + area.forms.length, 0),
      fields: allAreas.reduce((sum, area) => sum + area.fields.length +
        area.forms.reduce((count, form) => count + form.fields.length, 0), 0),
      buttons: allAreas.reduce((sum, area) => sum + area.buttons.length, 0),
      links: allAreas.reduce((sum, area) => sum + area.links.length, 0),
      outputs: allAreas.reduce((sum, area) => sum + area.outputs.reduce((count, output) => count + output.count, 0), 0),
      posts: report.pages.reduce((sum, page) => sum + (page.posts?.length || 0), 0),
      behaviors: report.pages.reduce((sum, page) => sum + (page.behaviors?.length || 0), 0),
      observedRequests: report.pages.reduce((sum, page) => sum + (page.observedRequests?.length || 0), 0),
      errors: report.pages.filter(page => page.error).length,
      truncated: queue.length > 0 || elementListsTruncated || scriptListsTruncated
    };
    compactReport(report);
    return redactValues(report, queryValues);
  } finally {
    signal?.removeEventListener('abort', onAbort);
    if (closeOnAbort) await closeOnAbort;
    else {
      try { await context?.close(); } finally { await browser.close(); }
    }
  }
}
