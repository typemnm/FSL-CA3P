import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { analyze } from './analyze.mjs';
import { payloads } from './payloads.mjs';

const ORIGIN = 'http://xss-fuzzer.test';
const textTypes = ['text', 'search', 'email', 'url', 'password', 'tel'];
export function validate(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Input must be a JSON object.');
  if (typeof input.html !== 'string') throw new Error('html must be a string.');
  if (!(typeof input.js === 'string' || (Array.isArray(input.js) && input.js.every(s => s && typeof s.code === 'string' && typeof s.path === 'string')))) throw new Error('js must be a string or [{path, code}].');
  if (input.profile && !['generic', 'fsl-ca3p'].includes(input.profile)) throw new Error('Unknown profile.');
  if (input.queryParams && (!Array.isArray(input.queryParams) || !input.queryParams.every(x => typeof x === 'string'))) throw new Error('queryParams must be strings.');
  if (input.actions && (!Array.isArray(input.actions) || !input.actions.every(a => ['fill', 'click', 'submit'].includes(a.type) && typeof a.selector === 'string' && (a.type !== 'fill' || typeof a.value === 'string')))) throw new Error('actions require type, selector, and fill value.');
  if (input.fixtures && (!Array.isArray(input.fixtures) || !input.fixtures.every(f => typeof f.path === 'string' && f.body !== undefined))) throw new Error('fixtures require path and body.');
  for (const [key, min, max] of [['maxCases', 1, 500], ['settleMs', 20, 5000], ['timeoutMs', 100, 30000]]) {
    if (input[key] !== undefined && (!Number.isInteger(input[key]) || input[key] < min || input[key] > max)) throw new Error(`${key} must be an integer in ${min}..${max}.`);
  }
}

// Instrumentation preserves the native setter; it only records values and stacks.
function instrument() {
  window.__xssSinks = [];
  const record = (sink, value) => {
    if (window.__xssSinks.length < 200) window.__xssSinks.push({ sink, value: String(value).slice(0, 16000), stack: new Error().stack });
  };
  for (const [proto, key] of [[Element.prototype, 'innerHTML'], [Element.prototype, 'outerHTML'], [HTMLIFrameElement.prototype, 'srcdoc']]) {
    const desc = Object.getOwnPropertyDescriptor(proto, key);
    Object.defineProperty(proto, key, { ...desc, set(value) { record(key, value); return desc.set.call(this, value); } });
  }
  for (const [proto, key, valueIndex] of [[Element.prototype, 'insertAdjacentHTML', 1], [Document.prototype, 'write', 0], [Document.prototype, 'writeln', 0]]) {
    const original = proto[key];
    proto[key] = function (...args) { record(key, args[valueIndex]); return original.apply(this, args); };
  }
  const attr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (key, value) {
    if (/^on/i.test(key)) record('event-attribute', value);
    return attr.call(this, key, value);
  };
}

function scriptsFor(input) {
  return typeof input.js === 'string' ? [{ path: '/app.js', code: input.js }] : input.js;
}
function htmlFor(input, scripts) {
  let html = input.html;
  const existing = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map(m => new URL(m[1], ORIGIN).pathname);
  const tags = scripts.filter(s => !existing.includes(new URL(s.path, ORIGIN).pathname))
    .map(s => `<script src="${new URL(s.path, ORIGIN).pathname.replaceAll('"', '&quot;')}" defer></script>`).join('');
  return /<\/head\s*>/i.test(html) ? html.replace(/<\/head\s*>/i, `${tags}</head>`) : `${html}${tags}`;
}

export async function fuzz(input, options = {}) {
  validate(input);
  const scripts = scriptsFor(input);
  const candidates = [], parseErrors = [];
  for (const s of scripts) {
    const result = analyze(s.code, s.path);
    candidates.push(...result.candidates); parseErrors.push(...result.errors);
  }
  for (const match of input.html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    if (/\bsrc\s*=/i.test(match[1])) continue;
    const type = match[1].match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1];
    if (type && !['module', 'text/javascript', 'application/javascript'].includes(type.toLowerCase())) continue;
    const codeOffset = match.index + match[0].indexOf('>') + 1;
    const prefix = input.html.slice(0, codeOffset);
    const lineOffset = prefix.split('\n').length - 1;
    const columnOffset = prefix.length - prefix.lastIndexOf('\n') - 1;
    const result = analyze(match[2], 'input.html');
    for (const candidate of result.candidates) {
      if (candidate.line === 1) candidate.column += columnOffset;
      candidate.line += lineOffset;
    }
    candidates.push(...result.candidates); parseErrors.push(...result.errors);
  }
  const report = { schemaVersion: '1.0', profile: input.profile || 'generic',
    environment: { mode: 'offline-browser', api: input.profile === 'fsl-ca3p' ? 'in-memory-fsl-ca3p-model' : 'fixtures', realServerTested: false },
    summary: {}, candidates, findings: [], cases: [], diagnostics: { parseErrors, baselineErrors: [], blockedRequests: [] },
    limitations: ['Only exercised input paths are covered.', 'Candidate sinks are not vulnerabilities until execution is observed.', 'API fixtures do not validate backend persistence, authentication, headers, or CSP.'] };
  const chrome = options.executablePath || process.env.XSS_BROWSER_PATH;
  const installedChrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : existsSync(installedChrome) ? { executablePath: installedChrome } : {}) });
  const settleMs = input.settleMs ?? 200;
  const maxCases = input.maxCases ?? 150;
  const html = htmlFor(input, scripts);
  const scriptMap = new Map(scripts.map(s => [new URL(s.path, ORIGIN).pathname, s.code]));
  const blocked = new Set();
  const allTargets = [];

  async function session(test, discover = false) {
    const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    await context.routeWebSocket('**/*', socket => {
      blocked.add(socket.url());
      socket.close();
    });
    const page = await context.newPage();
    page.setDefaultTimeout(input.timeoutMs ?? 3000);
    const errors = [], hits = [], requests = [];
    let posts = [], user = { id: 'alice', name: 'Alice' };
    const token = test?.token;
    await context.exposeBinding('__xssProbe', ({ frame }, value) => {
      if (value === token && token) hits.push({ token, frame: frame.url() });
    });
    await context.addInitScript(instrument);
    page.on('pageerror', e => { if (errors.length < 20) errors.push(e.message); });
    page.on('dialog', d => d.dismiss());
    await context.route('**/*', async route => {
      const req = route.request(), url = new URL(req.url());
      if (url.origin !== ORIGIN) { blocked.add(url.origin + url.pathname); return route.abort(); }
      if (req.isNavigationRequest() && req.frame() === page.mainFrame() && url.pathname === '/') return route.fulfill({ contentType: 'text/html', body: html });
      if (scriptMap.has(url.pathname)) return route.fulfill({ contentType: 'application/javascript', body: scriptMap.get(url.pathname) });
      if (url.pathname.startsWith('/api/')) requests.push({ method: req.method(), path: url.pathname, body: req.postData() });
      const fixture = input.fixtures?.find(f => f.path === url.pathname && (f.method || 'GET').toUpperCase() === req.method());
      if (fixture) {
        const fixturePayload = test?.source.kind === 'fixture' ? test.payload : 'baseline';
        const serialized = JSON.stringify(fixture.body).replaceAll('{{PAYLOAD}}', JSON.stringify(fixturePayload).slice(1, -1));
        return route.fulfill({ status: fixture.status || 200, contentType: 'application/json', body: serialized });
      }
      if (input.profile === 'fsl-ca3p') {
        if (url.pathname === '/api/session') return route.fulfill({ json: { user } });
        if (url.pathname === '/api/posts' && req.method() === 'POST') {
          let body;
          try { body = req.postDataJSON(); } catch { return route.fulfill({ status: 400, json: { error: 'Invalid JSON' } }); }
          if (typeof body?.title !== 'string' || typeof body?.content !== 'string' || !body.title.trim() || !body.content.trim() || body.title.trim().length > 120 || body.content.trim().length > 10000) return route.fulfill({ status: 400, json: { error: 'Invalid post' } });
          const post = { ...body, id: posts.length + 1, authorId: user.id, authorName: user.name, createdAt: '2026-01-01T00:00:00Z' };
          posts.push(post); return route.fulfill({ status: 201, json: { post } });
        }
        if (url.pathname === '/api/posts' && req.method() === 'GET') return route.fulfill({ json: { posts } });
      }
      // Unknown resources never reach a real server.
      blocked.add(url.pathname); return route.fulfill({ status: 404, body: '' });
    });
    try {
      const url = new URL(ORIGIN);
      if (test?.source.kind === 'query') url.searchParams.set(test.source.name, test.payload);
      if (test?.source.kind === 'hash') url.hash = test.payload;
      await page.goto(url.href, { waitUntil: 'load' });
      await page.waitForTimeout(settleMs);
      if (discover) {
        const fields = await page.locator('input, textarea').evaluateAll((nodes, types) => nodes.map((e, index) => ({ index, tag: e.tagName.toLowerCase(), type: e.type, name: e.name, id: e.id, disabled: e.disabled, readOnly: e.readOnly, form: !!e.form })).filter(e => !e.disabled && !e.readOnly && (e.tag === 'textarea' || types.includes(e.type))), textTypes);
        return { fields, errors };
      }
      if (test.source.kind === 'form') {
        const target = page.locator('input, textarea').nth(test.source.index);
        // Fill valid supporting fields in this form, so only one field is fuzzed per case.
        await target.evaluate((e, types) => {
          if (!e.form) return;
          for (const field of e.form.elements) {
            if (field === e || field.disabled || field.readOnly) continue;
            if (field.tagName === 'TEXTAREA' || types.includes(field.type)) {
              field.value = field.type === 'email' ? 'fuzz@example.test' : field.type === 'url' ? 'http://xss-fuzzer.test/' : 'fuzz';
              field.dispatchEvent(new Event('input', { bubbles: true }));
            }
          }
        }, textTypes);
        await target.fill(test.payload);
        await target.dispatchEvent('change');
        if (test.source.form) await target.evaluate(e => e.form.requestSubmit());
      }
      for (const action of input.actions || []) {
        const loc = page.locator(action.selector);
        if (action.type === 'fill') await loc.fill(action.value.replaceAll('{{PAYLOAD}}', test.payload));
        if (action.type === 'click') await loc.click();
        if (action.type === 'submit') await loc.evaluate(e => (e.tagName === 'FORM' ? e : e.form).requestSubmit());
      }
      await page.waitForTimeout(settleMs);
      // Verify that modeled posts also execute after a fresh read in this session.
      if (input.profile === 'fsl-ca3p' && posts.length) {
        await page.reload({ waitUntil: 'load' });
        await page.waitForTimeout(settleMs);
      }
      const sinks = await page.evaluate(() => window.__xssSinks || []);
      return { hits, errors, requests, sinks: sinks.filter(s => s.value.includes(token)), submitted: requests.some(r => r.method === 'POST') };
    } catch (e) { return { hits, errors: [...errors, e.message], requests, sinks: [], error: true }; }
    finally { await context.close(); }
  }
  try {
    const baseline = await session(null, true);
    report.diagnostics.baselineErrors = baseline.errors;
    for (const field of baseline.fields || []) allTargets.push({ kind: 'form', ...field });
    for (const name of input.queryParams || ['q', 'search', 'name', 'content']) allTargets.push({ kind: 'query', name });
    allTargets.push({ kind: 'hash', name: 'location.hash' });
    if (input.fixtures?.some(f => JSON.stringify(f.body).includes('{{PAYLOAD}}'))) allTargets.push({ kind: 'fixture', name: '{{PAYLOAD}}' });
    let planned = allTargets.length * payloads('placeholder').length;
    for (const source of allTargets) {
      for (let i = 0; i < payloads('placeholder').length; i++) {
        if (report.cases.length >= maxCases) break;
        const token = 'xss_' + randomBytes(12).toString('hex');
        const payload = payloads(token)[i];
        const result = await session({ source, token, payload: payload.value });
        const id = `case-${report.cases.length + 1}`;
        const status = result.hits.length ? 'confirmed' : result.error || result.errors.length ? 'error' : 'not_observed';
        report.cases.push({ id, source, payloadId: payload.id, payload: payload.value, token, status, errors: result.errors });
        if (result.hits.length) report.findings.push({ caseId: id, status: 'confirmed', type: input.profile === 'fsl-ca3p' && result.submitted ? 'stored-xss-client-with-modeled-api' : 'xss-client-execution', source, payloadId: payload.id, payload: payload.value,
          evidence: { executions: result.hits.length, frames: [...new Set(result.hits.map(h => h.frame))], sinks: result.sinks, apiRequests: result.requests },
          realServerVerified: false });
      }
    }
    report.summary = { plannedCases: planned, executedCases: report.cases.length, truncated: planned > report.cases.length,
      confirmedCases: report.findings.length, candidateSinks: candidates.length,
      errorCases: report.cases.filter(c => c.status === 'error').length,
      verdict: report.findings.length ? 'xss_execution_confirmed' : 'no_execution_observed' };
    report.diagnostics.blockedRequests = [...blocked].sort();
    return report;
  } finally { await browser.close(); }
}
