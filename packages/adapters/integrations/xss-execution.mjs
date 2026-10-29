/**
 * Read-only stored-XSS execution check that drives web-parser's Playwright.
 * The returned page data is an untrusted browser observation, not an API or
 * ownership assertion.
 */

import { createRequire } from 'node:module';
import canary from '../../../agent/src/xss-canary.js';

const { createStoredXssCanary, storedXssCanaryContent } = canary;
export { createStoredXssCanary, storedXssCanaryContent };

const VERIFY_TIMEOUT_MS = 10_000;
const BINDING_WAIT_MS = 1_500;
const MAX_OBSERVATION_ERRORS = 8;
const requireBrowserDependency = createRequire(new URL('../../../web-parser/package.json', import.meta.url));

function localOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError('Stored-XSS observation requires a valid local target origin.'); }
  if (!['http:', 'https:'].includes(url.protocol)
    || !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('Stored-XSS observation accepts only an HTTP(S) loopback origin.');
  }
  return url.origin;
}

function parserFailure(message, cause) {
  const error = new Error(message, { cause });
  error.code = 'XSS_PARSER_FAILED';
  return error;
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
    const { chromium } = requireBrowserDependency('playwright');
    if (!chromium?.launch) throw new TypeError('Playwright Chromium is missing.');
    return chromium;
  } catch (cause) {
    const error = new Error(
      'web-parser Playwright is unavailable. Install web-parser dependencies and Chromium with '
      + 'npm install and npx playwright install chromium in web-parser.',
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
    // XSS_PARSER_BROWSER_PATH is the old name, kept as an alias.
    const executablePath = process.env.WEB_PARSER_BROWSER_PATH || process.env.XSS_PARSER_BROWSER_PATH;
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
