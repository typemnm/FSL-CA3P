import { existsSync } from 'node:fs';
import { chromium } from 'playwright';
import { readDom } from './dom.mjs';
import { findScriptHints } from './script-hints.mjs';

const CHROME_ON_MAC = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ACTION_LINK = /(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|탈퇴|로그아웃|삭제)/i;

function isLoopback(url) {
  return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
}

function checkLocalUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('A valid --url is required (for example http://127.0.0.1:3000/).'); }
  if (!['http:', 'https:'].includes(url.protocol) || !isLoopback(url) || url.username || url.password) {
    throw new Error('--url must be an http(s) loopback URL: localhost, 127.0.0.1, or [::1].');
  }
  return url;
}

function maskedPath(pathname) {
  return pathname.split('/').map(part => {
    if (/^\d+$/.test(part)) return '{number}';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(part)) return '{uuid}';
    if (/^[a-z0-9_-]{24,}$/i.test(part)) return '{token}';
    return part;
  }).join('/');
}

function displayUrl(value) {
  const url = value instanceof URL ? value : new URL(value);
  const names = [...new Set(url.searchParams.keys())];
  return url.origin + maskedPath(url.pathname) +
    (names.length ? '?' + names.map(name => encodeURIComponent(name) + '={value}').join('&') : '') +
    (url.hash ? '#{fragment}' : '');
}

function bodyKeys(request) {
  const raw = request.postData();
  if (!raw || raw.length > 100_000) return [];
  try {
    const contentType = request.headers()['content-type'] || '';
    if (contentType.includes('application/json')) {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ?
        Object.keys(parsed).slice(0, 40) : [];
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
      return [...new Set(new URLSearchParams(raw).keys())].slice(0, 40);
    }
  } catch { /* A malformed body is still recorded as an observed request. */ }
  return [];
}

function observedRequest(request) {
  const url = new URL(request.url());
  return {
    method: request.method(),
    url: displayUrl(url),
    resourceType: request.resourceType(),
    queryParameters: [...new Set(url.searchParams.keys())],
    bodyKeys: bodyKeys(request),
    status: null
  };
}

function queryInputs(pageUrl, links, requests, scriptHints, seedOrigin) {
  const found = new Map();
  const add = (value, source) => {
    let url;
    try { url = new URL(value); } catch { return; }
    if (url.origin !== seedOrigin) return;
    for (const name of new Set(url.searchParams.keys())) {
      const key = maskedPath(url.pathname) + '\u0000' + name;
      const entry = found.get(key) || { name, targetUrl: displayUrl(url), evidence: [] };
      if (!entry.evidence.includes(source)) entry.evidence.push(source);
      found.set(key, entry);
    }
  };
  add(pageUrl, 'current-url');
  for (const link of links) add(link.href, 'link');
  for (const request of requests) {
    if (['document', 'fetch', 'xhr'].includes(request.resourceType)) add(request.rawUrl, 'network-request');
  }
  for (const hint of scriptHints) add(hint.endpointUrlTemplate, 'static-js-hint');
  return [...found.values()];
}

function pathSegments(pathname) {
  return pathname.split('/').filter(Boolean).map((value, index) => ({
    index,
    shape: /^\d+$/.test(value) ? 'number' :
      /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(value) ? 'uuid' :
      /^[a-z0-9_-]{24,}$/i.test(value) ? 'token-like' : 'literal',
    possibleVariable: /^\d+$/.test(value) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(value) ||
      /^[a-z0-9_-]{24,}$/i.test(value)
  }));
}

function buildPage(id, pageUrl, responseStatus, dom, requestRecords, errors, seedOrigin, rawScriptHints, scriptErrors) {
  const url = new URL(pageUrl);
  const scriptHints = rawScriptHints.map((hint, index) => {
    const { endpointPattern, ...rest } = hint;
    return {
      id: id + '-script-hint-' + (index + 1),
      ...rest,
      endpointUrlTemplate: displayUrl(new URL(endpointPattern, seedOrigin))
    };
  });
  const forms = dom.forms.map((form, index) => ({
    id: id + '-form-' + (index + 1),
    selector: form.selector,
    htmlId: form.htmlId,
    name: form.name,
    submission: {
      htmlDefault: {
        method: form.method,
        actionUrl: displayUrl(form.actionUrl),
        enctype: form.enctype
      },
      actualSubmissionObserved: false,
      possibleScriptEndpointHints: [],
      evidence: 'HTML attributes are a fallback; JavaScript may send data elsewhere'
    },
    fields: [],
    controlIds: []
  }));
  const standaloneFields = [];
  for (const [index, raw] of dom.fields.entries()) {
    const { formIndex, ...field } = raw;
    const parent = formIndex === null ? null : forms[formIndex];
    const item = { id: id + '-field-' + (index + 1), ...field, formId: parent?.id || null, evidence: 'rendered DOM' };
    if (parent) parent.fields.push(item);
    else standaloneFields.push(item);
  }
  for (const form of forms) {
    const fieldNames = new Set(form.fields.map(field => field.name).filter(Boolean));
    form.submission.possibleScriptEndpointHints = scriptHints.flatMap(hint => {
      const matchedFieldNames = hint.bodyKeys.filter(name => fieldNames.has(name));
      return matchedFieldNames.length ?
        [{ hintId: hint.id, matchedFieldNames, evidence: 'field-name overlap only; not a confirmed form binding' }] : [];
    });
  }
  const controls = dom.controls.map((raw, index) => {
    const { formIndex, ...control } = raw;
    const parent = formIndex === null ? null : forms[formIndex];
    const item = { id: id + '-control-' + (index + 1), ...control, formId: parent?.id || null };
    if (parent) parent.controlIds.push(item.id);
    return item;
  });
  const links = dom.links.flatMap(link => {
    let target;
    try { target = new URL(link.href); } catch { return []; }
    if (target.origin !== seedOrigin) return [];
    const actionLike = ACTION_LINK.test(target.pathname + ' ' + link.text);
    return [{
      url: displayUrl(target),
      text: link.text,
      crawlEligible: !actionLike,
      ...(actionLike ? { skipReason: 'action-like link' } : {})
    }];
  });
  const requestOutput = requestRecords.map(({ rawUrl, ...record }) => record);
  const queryParameters = queryInputs(pageUrl, dom.links, requestRecords, scriptHints, seedOrigin);
  const fragmentSources = [];
  if (url.hash) fragmentSources.push('current-url');
  if (dom.links.some(link => {
    try { const target = new URL(link.href); return target.origin === seedOrigin && !!target.hash; }
    catch { return false; }
  })) fragmentSources.push('link');
  return {
    id,
    url: displayUrl(url),
    title: dom.title,
    status: responseStatus,
    path: { pathname: maskedPath(url.pathname), segments: pathSegments(url.pathname) },
    forms,
    standaloneFields,
    controls,
    urlInputs: {
      queryParameters,
      fragment: { observed: fragmentSources.length > 0, evidence: fragmentSources }
    },
    links,
    observedRequests: requestOutput,
    scriptEndpointHints: scriptHints,
    scriptAnalysisErrors: scriptErrors,
    counts: {
      ...dom.counts,
      truncated: {
        forms: dom.counts.forms > dom.forms.length,
        fields: dom.counts.fields > dom.fields.length,
        controls: dom.counts.controls > dom.controls.length,
        links: dom.counts.links > dom.links.length
      }
    },
    errors
  };
}

function collectInputPoints(pages) {
  const points = [];
  for (const [pageIndex, page] of pages.entries()) {
    for (const [formIndex, form] of page.forms.entries()) {
      for (const [fieldIndex, field] of form.fields.entries()) {
        points.push({
          id: field.id,
          kind: 'dom-field',
          pageId: page.id,
          ref: '/pages/' + pageIndex + '/forms/' + formIndex + '/fields/' + fieldIndex,
          name: field.name,
          label: field.label,
          type: field.type,
          selector: field.selector,
          userEditable: field.userEditable,
          submission: form.submission,
          evidence: 'rendered DOM'
        });
      }
    }
    for (const [fieldIndex, field] of page.standaloneFields.entries()) {
      points.push({
        id: field.id,
        kind: 'dom-field',
        pageId: page.id,
        ref: '/pages/' + pageIndex + '/standaloneFields/' + fieldIndex,
        name: field.name,
        label: field.label,
        type: field.type,
        selector: field.selector,
        userEditable: field.userEditable,
        submission: null,
        evidence: 'rendered DOM'
      });
    }
    for (const [queryIndex, param] of page.urlInputs.queryParameters.entries()) {
      points.push({
        id: page.id + '-query-' + (queryIndex + 1),
        kind: 'url-query',
        pageId: page.id,
        ref: '/pages/' + pageIndex + '/urlInputs/queryParameters/' + queryIndex,
        name: param.name,
        targetUrl: param.targetUrl,
        evidence: param.evidence
      });
    }
    for (const [segmentIndex, segment] of page.path.segments.entries()) {
      if (!segment.possibleVariable) continue;
      points.push({
        id: page.id + '-path-' + (segmentIndex + 1),
        kind: 'url-path-segment',
        pageId: page.id,
        ref: '/pages/' + pageIndex + '/path/segments/' + segmentIndex,
        name: 'path[' + segment.index + ']',
        shape: segment.shape,
        targetUrl: page.url,
        evidence: 'visited URL shape heuristic'
      });
    }
    if (page.urlInputs.fragment.observed) {
      points.push({
        id: page.id + '-fragment',
        kind: 'url-fragment',
        pageId: page.id,
        ref: '/pages/' + pageIndex + '/urlInputs/fragment',
        name: 'location.hash',
        evidence: page.urlInputs.fragment.evidence
      });
    }
  }
  return points;
}

function validateOptions(options) {
  for (const [name, min, max] of [['maxPages', 1, 30], ['waitMs', 0, 5000], ['timeoutMs', 1000, 30000]]) {
    if (options[name] !== undefined &&
      (!Number.isInteger(options[name]) || options[name] < min || options[name] > max)) {
      throw new Error(name + ' must be an integer from ' + min + ' to ' + max + '.');
    }
  }
}

export async function scan(inputUrl, options = {}) {
  const seed = checkLocalUrl(inputUrl);
  validateOptions(options);
  const maxPages = options.maxPages ?? 10;
  const waitMs = options.waitMs ?? 500;
  const timeoutMs = options.timeoutMs ?? 10000;
  const chromePath = options.browserPath || process.env.XSS_PARSER_BROWSER_PATH ||
    (existsSync(CHROME_ON_MAC) ? CHROME_ON_MAC : undefined);
  const browser = await chromium.launch({
    headless: !options.headed,
    ...(chromePath ? { executablePath: chromePath } : {})
  });
  const report = {
    schemaVersion: '1.0',
    tool: 'xss-parser',
    target: {
      startUrl: displayUrl(seed),
      origin: seed.origin,
      scope: 'same-origin links; loopback-only browser requests'
    },
    scan: {
      mode: 'passive',
      maxPages,
      waitMs,
      timeoutMs,
      writeMethodsBlocked: true,
      formSubmissionPerformed: false,
      clickedControls: false,
      headed: !!options.headed
    },
    summary: {},
    pages: [],
    inputPoints: [],
    blockedRequests: [],
    limitations: [
      'Input points are observed surfaces, not proven vulnerabilities.',
      'No form submission, button clicks, authentication, or write-method requests are performed.',
      'JavaScript may override HTML form action and method. Static endpoint hints and field-name matches are unconfirmed.',
      'Unvisited routes, authenticated content, shadow DOM, and delayed UI may be missed.'
    ]
  };
  const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
  context.setDefaultTimeout(timeoutMs);
  await context.routeWebSocket('**/*', socket => {
    report.blockedRequests.push({ method: 'WS', url: displayUrl(socket.url()), reason: 'websocket' });
    socket.close();
  });
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const reason = !isLoopback(url) ? 'non-loopback' : !SAFE_METHODS.has(method) ? 'write-method' : null;
    if (reason) {
      report.blockedRequests.push({ method, url: displayUrl(url), reason });
      await route.abort();
    } else {
      await route.continue();
    }
  });
  const queue = [seed.href];
  const queued = new Set([new URL(seed.href).origin + seed.pathname + seed.search]);
  const visited = new Set();
  try {
    while (queue.length && report.pages.length < maxPages) {
      const next = queue.shift();
      const keyUrl = new URL(next);
      keyUrl.hash = '';
      const key = keyUrl.href;
      if (visited.has(key)) continue;
      visited.add(key);
      const page = await context.newPage();
      page.setDefaultNavigationTimeout(timeoutMs);
      const requestRecords = [];
      const requestMap = new WeakMap();
      const scriptTasks = [];
      const errors = [];
      page.on('request', request => {
        const record = { ...observedRequest(request), rawUrl: request.url() };
        requestRecords.push(record);
        requestMap.set(request, record);
      });
      page.on('response', response => {
        const record = requestMap.get(response.request());
        if (record) record.status = response.status();
        if (response.request().resourceType() === 'script' && scriptTasks.length < 30) {
          scriptTasks.push(response.text().then(source => ({
            source,
            scriptUrl: displayUrl(response.url())
          })).catch(error => ({ error: error.message.slice(0, 150), scriptUrl: displayUrl(response.url()) })));
        }
      });
      page.on('pageerror', error => {
        if (errors.length < 20) errors.push('Page script error: ' + error.message.slice(0, 250));
      });
      let status = null;
      try {
        const response = await page.goto(next, { waitUntil: 'domcontentloaded' });
        status = response?.status() ?? null;
        if (waitMs) await page.waitForTimeout(waitMs);
        const dom = await page.evaluate(readDom);
        const scriptResponses = await Promise.all(scriptTasks);
        const rawScriptHints = [];
        const scriptErrors = [];
        for (const script of [
          ...scriptResponses,
          ...dom.inlineScripts.map((source, index) => ({
            source,
            scriptUrl: displayUrl(page.url()) + ' [inline ' + (index + 1) + ']'
          }))
        ]) {
          if (script.error) {
            scriptErrors.push({ scriptUrl: script.scriptUrl, message: script.error });
            continue;
          }
          const result = findScriptHints(script.source, script.scriptUrl);
          rawScriptHints.push(...result.hints);
          if (result.error) scriptErrors.push({ scriptUrl: script.scriptUrl, message: result.error });
        }
        const pageId = 'page-' + (report.pages.length + 1);
        const built = buildPage(
          pageId, page.url(), status, dom, requestRecords, errors, seed.origin, rawScriptHints, scriptErrors
        );
        report.pages.push(built);
        for (const link of dom.links) {
          let target;
          try { target = new URL(link.href); } catch { continue; }
          if (target.origin !== seed.origin || ACTION_LINK.test(target.pathname + ' ' + link.text)) continue;
          target.hash = '';
          const targetKey = target.href;
          if (!queued.has(targetKey) && !visited.has(targetKey)) {
            queue.push(targetKey);
            queued.add(targetKey);
          }
        }
      } catch (error) {
        report.pages.push({
          id: 'page-' + (report.pages.length + 1),
          url: displayUrl(next),
          title: null,
          status,
          path: { pathname: maskedPath(keyUrl.pathname), segments: pathSegments(keyUrl.pathname) },
          forms: [],
          standaloneFields: [],
          controls: [],
          urlInputs: { queryParameters: [], fragment: { observed: false, evidence: [] } },
          links: [],
          observedRequests: requestRecords.map(({ rawUrl, ...record }) => record),
          scriptEndpointHints: [],
          scriptAnalysisErrors: [],
          counts: { forms: 0, fields: 0, controls: 0, links: 0, truncated: {} },
          errors: [error.message.slice(0, 300), ...errors]
        });
      } finally {
        await page.close();
      }
    }
    report.inputPoints = collectInputPoints(report.pages);
    report.summary = {
      pagesVisited: report.pages.length,
      formsFound: report.pages.reduce((sum, page) => sum + page.forms.length, 0),
      fieldsFound: report.inputPoints.filter(point => point.kind === 'dom-field').length,
      editableFields: report.inputPoints.filter(point => point.kind === 'dom-field' && point.userEditable).length,
      urlQueryParameters: report.inputPoints.filter(point => point.kind === 'url-query').length,
      urlQueryParametersObserved: report.inputPoints.filter(point =>
        point.kind === 'url-query' && point.evidence.some(source => source !== 'static-js-hint')).length,
      urlQueryParametersStaticOnly: report.inputPoints.filter(point =>
        point.kind === 'url-query' && point.evidence.every(source => source === 'static-js-hint')).length,
      urlPathSegments: report.inputPoints.filter(point => point.kind === 'url-path-segment').length,
      urlFragments: report.inputPoints.filter(point => point.kind === 'url-fragment').length,
      controlsFound: report.pages.reduce((sum, page) => sum + page.controls.length, 0),
      observedRequests: report.pages.reduce((sum, page) => sum + page.observedRequests.length, 0),
      scriptEndpointHints: report.pages.reduce((sum, page) => sum + page.scriptEndpointHints.length, 0),
      blockedRequests: report.blockedRequests.length,
      errors: report.pages.reduce((sum, page) => sum + page.errors.length, 0),
      truncated: queue.length > 0 || report.pages.some(page =>
        Object.values(page.counts.truncated).some(Boolean))
    };
    return report;
  } finally {
    await context.close();
    await browser.close();
  }
}
