/**
 * Read-only bridge from this repository's xss-parser to the local agent loop.
 * The returned page data is an untrusted browser observation, not an API or
 * ownership assertion. In particular, `author` is only a displayed name.
 */

import { createRequire } from 'node:module';
import canary from '../../agent/src/xss-canary.js';

const { createStoredXssCanary, storedXssCanaryContent } = canary;
export { createStoredXssCanary, storedXssCanaryContent };

const VERIFY_TIMEOUT_MS = 10_000;
const BINDING_WAIT_MS = 1_500;
const MAX_OBSERVATION_ERRORS = 8;
const requireParserDependency = createRequire(new URL('../../xss-parser/package.json', import.meta.url));

function localOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError('xss-parser requires a valid local target origin.'); }
  if (!['http:', 'https:'].includes(url.protocol)
    || !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('xss-parser accepts only an HTTP(S) loopback origin.');
  }
  return url.origin;
}

function parserFailure(message, cause) {
  const error = new Error(message, { cause });
  error.code = 'XSS_PARSER_FAILED';
  return error;
}

async function loadScan() {
  try {
    const { scan } = await import('../../xss-parser/parser.mjs');
    if (typeof scan !== 'function') throw new TypeError('scan export is missing');
    return scan;
  } catch (cause) {
    const error = new Error(
      'xss-parser is unavailable. Install its dependencies in xss-parser with npm install, '
      + 'then install Playwright Chromium with npx playwright install chromium.',
      { cause },
    );
    error.code = 'XSS_PARSER_UNAVAILABLE';
    throw error;
  }
}

function normalizeReport(report, origin) {
  if (!report || report.schemaVersion !== '3.4' || !Array.isArray(report.pages)
    || report.summary?.scope !== 'visited-client-pages'
    || typeof report.summary.truncated !== 'boolean') {
    throw parserFailure('xss-parser returned an unsupported report schema.');
  }
  let reportOrigin;
  try { reportOrigin = new URL(report.startUrl).origin; }
  catch { throw parserFailure('xss-parser returned an invalid start URL.'); }
  if (reportOrigin !== origin) throw parserFailure('xss-parser report changed target origin.');

  const observedPosts = [];
  const errors = [];
  for (const page of report.pages) {
    if (!page || typeof page.url !== 'string') {
      throw parserFailure('xss-parser returned a page without a URL.');
    }
    let pageOrigin;
    try { pageOrigin = new URL(page.url).origin; }
    catch { throw parserFailure('xss-parser returned an invalid page URL.'); }
    if (pageOrigin !== origin) throw parserFailure('xss-parser report contains a page from another origin.');
    if (page.error) {
      errors.push({ url: page.url, message: String(page.error) });
      continue;
    }
    if (page.posts !== undefined && !Array.isArray(page.posts)) {
      throw parserFailure('xss-parser returned invalid post observations.');
    }
    for (const post of page.posts ?? []) {
      if (!post || (post.id !== null && typeof post.id !== 'string')
        || (post.title !== null && typeof post.title !== 'string')
        || (post.author !== null && typeof post.author !== 'string')) {
        throw parserFailure('xss-parser returned an invalid visible post.');
      }
      observedPosts.push({
        id: post.id,
        idSource: post.idSource ?? null,
        title: post.title,
        author: post.author,
        pageUrl: page.url,
      });
    }
  }
  return {
    report,
    observedPosts,
    errors,
    truncated: report.summary.truncated,
  };
}

/**
 * Scan one page of the isolated local target. `scanImpl` is injectable for
 * protocol tests; the default is the real Playwright-backed xss-parser.
 */
export async function parseLocalSite(originInput, { scanImpl, signal } = {}) {
  const origin = localOrigin(originInput);
  const scan = scanImpl ?? await loadScan();
  if (typeof scan !== 'function') throw new TypeError('scanImpl must be a function.');
  let report;
  try {
    report = await scan(`${origin}/`, {
      maxPages: 1,
      hideBody: true,
      waitMs: 0,
      // The local board renders its posts after the initial API read.
      readySelector: '#post-list[aria-busy="false"]',
      signal,
    });
  } catch (cause) {
    if (signal?.aborted) throw cause;
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw parserFailure(
      `xss-parser could not scan the local target: ${detail}. `
      + 'Ensure Chrome/Chromium is installed (npx playwright install chromium).',
      cause,
    );
  }
  return normalizeReport(report, origin);
}

function abortError(signal) {
  const error = new Error('Stored-XSS browser observation was aborted.', { cause: signal?.reason });
  error.name = 'AbortError';
  return error;
}

function validateObservation(postId, marker, signal) {
  if (!Number.isSafeInteger(postId) || postId < 1) {
    throw new TypeError('Stored-XSS observation requires a positive integer postId.');
  }
  // The canonical helper also validates the marker before producing any HTML.
  storedXssCanaryContent(marker);
  if (signal !== undefined && (!signal || typeof signal.aborted !== 'boolean'
    || typeof signal.addEventListener !== 'function'
    || typeof signal.removeEventListener !== 'function')) {
    throw new TypeError('signal must be an AbortSignal.');
  }
  if (signal?.aborted) throw abortError(signal);
}

function loadChromium() {
  try {
    const { chromium } = requireParserDependency('playwright');
    if (!chromium?.launch) throw new TypeError('Playwright Chromium is missing.');
    return chromium;
  } catch (cause) {
    const error = new Error(
      'Playwright is unavailable. Install xss-parser dependencies and Chromium with '
      + 'npm install and npx playwright install chromium in xss-parser.',
      { cause },
    );
    error.code = 'XSS_PARSER_UNAVAILABLE';
    throw error;
  }
}

function waitForBinding(bindingPromise, milliseconds, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve();
    };
    const onAbort = () => finish(abortError(signal));
    const timer = setTimeout(() => finish(), milliseconds);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
    bindingPromise.then(() => finish(), error => finish(error));
  });
}

/**
 * Reopen the private loopback board in a fresh browser and look for execution
 * of the exact canary previously posted by this run. No browser writes, remote
 * requests, or WebSocket connections are allowed during the observation.
 * A matching HTML fragment alone never confirms execution.
 */
export async function observeStoredXssExecution(originInput, { postId, marker, signal } = {}) {
  const origin = localOrigin(originInput);
  validateObservation(postId, marker, signal);
  const content = storedXssCanaryContent(marker);
  const chromium = loadChromium();
  const deadline = Date.now() + VERIFY_TIMEOUT_MS;
  const remaining = () => {
    const milliseconds = deadline - Date.now();
    if (milliseconds <= 0) throw parserFailure('Stored-XSS browser observation timed out.');
    return milliseconds;
  };
  const errors = [];
  const addError = message => {
    if (errors.length < MAX_OBSERVATION_ERRORS) errors.push(message);
  };
  let browser;
  let context;
  let page;
  let bindingCalled = false;
  let resolveBinding;
  let timedOut = false;
  const bindingPromise = new Promise(resolve => { resolveBinding = resolve; });
  const closeBrowser = () => { void browser?.close().catch(() => {}); };
  const onAbort = () => closeBrowser();
  const deadlineTimer = setTimeout(() => { timedOut = true; closeBrowser(); }, VERIFY_TIMEOUT_MS);

  try {
    const executablePath = process.env.XSS_PARSER_BROWSER_PATH;
    browser = await chromium.launch({
      headless: true,
      timeout: remaining(),
      ...(executablePath ? { executablePath } : {}),
    });
    if (signal?.aborted) throw abortError(signal);
    signal?.addEventListener('abort', onAbort, { once: true });
    context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    await context.route('**/*', async route => {
      const request = route.request();
      let sameOrigin = false;
      try { sameOrigin = new URL(request.url()).origin === origin; }
      catch { /* Unparseable browser requests are blocked. */ }
      if (!sameOrigin || !['GET', 'HEAD'].includes(request.method())) {
        addError(`Blocked browser request: ${request.method()} ${sameOrigin ? 'local write' : 'outside target origin'}.`);
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
    await context.routeWebSocket('**/*', webSocket => webSocket.close());
    page = await context.newPage();
    page.setDefaultTimeout(remaining());
    page.on('popup', popup => { void popup.close().catch(() => {}); });
    page.on('pageerror', error => addError(`Browser script error: ${String(error.message).slice(0, 240)}`));
    await page.exposeBinding('__ca3pXssProbe', (source, observedMarker) => {
      if (source.page !== page || source.frame !== page.mainFrame() || observedMarker !== marker) return;
      bindingCalled = true;
      resolveBinding();
    });

    const response = await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded', timeout: remaining() });
    if (!response || response.status() >= 400) {
      throw parserFailure(`The local board returned HTTP ${response?.status() ?? 'no response'}.`);
    }
    await page.waitForSelector('#post-list[aria-busy="false"]', { timeout: remaining() });
    if (new URL(page.url()).origin !== origin) {
      throw parserFailure('The browser left the local target origin.');
    }
    const dom = await page.evaluate(({ expectedPostId, expectedMarker, expectedContent }) => {
      const cards = Array.from(document.querySelectorAll('#post-list .post-card'));
      const matchingCards = cards.filter(card =>
        card.querySelector('.post-number')?.textContent?.trim() === `NO. ${expectedPostId}`);
      const marked = Array.from(document.querySelectorAll('[data-ca3p-xss-marker]'))
        .filter(element => element.getAttribute('data-ca3p-xss-marker') === expectedMarker);
      const template = document.createElement('template');
      template.innerHTML = expectedContent;
      const expectedElement = template.content.firstElementChild;
      const postVisible = matchingCards.length === 1;
      const payloadPresent = postVisible && marked.length === 1
        && matchingCards[0].querySelector('.post-content')?.contains(marked[0]) === true
        && marked[0].outerHTML === expectedElement?.outerHTML;
      return { postVisible, payloadPresent };
    }, { expectedPostId: postId, expectedMarker: marker, expectedContent: content });
    if (dom.payloadPresent && !bindingCalled) {
      await waitForBinding(bindingPromise, Math.min(BINDING_WAIT_MS, remaining()), signal);
    }
    if (signal?.aborted) throw abortError(signal);
    return {
      executed: dom.postVisible && dom.payloadPresent && bindingCalled,
      marker,
      postId,
      pageUrl: page.url(),
      postVisible: dom.postVisible,
      payloadPresent: dom.payloadPresent,
      bindingCalled,
      errors,
    };
  } catch (cause) {
    if (signal?.aborted) throw abortError(signal);
    if (timedOut) throw parserFailure('Stored-XSS browser observation timed out.', cause);
    if (cause?.code === 'XSS_PARSER_FAILED') throw cause;
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw parserFailure(`Stored-XSS browser observation failed: ${detail}`, cause);
  } finally {
    clearTimeout(deadlineTimer);
    signal?.removeEventListener('abort', onAbort);
    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
  }
}
