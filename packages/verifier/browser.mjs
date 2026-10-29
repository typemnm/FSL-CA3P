/**
 * Sandboxed browser session for verifier checks. Same isolation as
 * observeStoredXssExecution (xss-parser) and openSandbox (report capture):
 * a fresh browser per call, same-origin GET/HEAD only, no WebSocket, no
 * service workers, no downloads, popups closed, dialogs dismissed.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from 'playwright';

const MAX_BLOCKED = 32;
const POLL_MS = 25;

function sessionError(code, message, options) {
  const error = new Error(message, options);
  error.code = code;
  return error;
}

function abortError() {
  const error = new Error('Verifier browser was aborted.');
  error.name = 'AbortError';
  return error;
}

function originOf(value) {
  try { return new URL(value).origin; }
  catch { return null; }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Whole code points only, so the cut never splits a UTF-8 sequence.
function clipBytes(value, maxBytes) {
  let out = '';
  let bytes = 0;
  for (const char of value) {
    bytes += Buffer.byteLength(char);
    if (bytes > maxBytes) break;
    out += char;
  }
  return out;
}

function pushCapped(list, item, max) {
  if (list.length < max) list.push(item);
}

export async function openVerifierBrowser(origin, { cookies = [], timeoutMs = 10000, signal, bindingName = '__ca3pXssProbe' } = {}) {
  if (signal?.aborted) throw abortError();
  const allowedOrigin = originOf(origin);
  const deadline = Date.now() + timeoutMs;
  const remaining = () => Math.max(deadline - Date.now(), 1);
  const blocked = [];
  const bindingCalls = [];
  const dialogs = [];
  const consoleMessages = [];
  const pageErrorMessages = [];
  let pageErrorCount = 0;
  let browser;
  let closing;

  // Pending calls race this promise so the one session deadline and abort fail them.
  let rejectPending;
  const interrupted = new Promise((_, reject) => { rejectPending = reject; });
  interrupted.catch(() => {});
  const guard = promise => Promise.race([promise, interrupted]);

  const close = () => {
    closing ??= (async () => {
      clearTimeout(deadlineTimer);
      signal?.removeEventListener('abort', onAbort);
      await browser?.close().catch(() => {});
    })();
    return closing;
  };
  const interrupt = error => {
    rejectPending(error);
    void close();
  };
  const deadlineTimer = setTimeout(() => interrupt(sessionError('TIMEOUT', 'Verifier browser deadline passed.')), timeoutMs);
  const onAbort = () => interrupt(abortError());
  signal?.addEventListener('abort', onAbort, { once: true });

  const block = (method, url, reason) => {
    if (blocked.length < MAX_BLOCKED) blocked.push({ method, url: String(url).slice(0, 240), reason });
  };

  const launchBrowser = async () => {
    const launched = await chromium.launch({ headless: true }).catch(cause => {
      throw sessionError('BROWSER_UNAVAILABLE', 'Chromium could not start. Run npx playwright install chromium in packages/verifier.', { cause });
    });
    if (closing) await launched.close().catch(() => {});
    else browser = launched;
  };

  const hasBinding = value => bindingCalls.some(call => call.mainFrame && call.value === String(value));
  const waitForBinding = async (value, ms) => {
    const until = Date.now() + ms;
    while (!hasBinding(value)) {
      if (Date.now() >= until) return false;
      await guard(sleep(POLL_MS));
    }
    return true;
  };

  try {
    await guard(launchBrowser());
    const context = await guard(browser.newContext({ serviceWorkers: 'block', acceptDownloads: false }));
    await guard(context.route('**/*', async route => {
      const request = route.request();
      const method = request.method();
      const reason = originOf(request.url()) !== allowedOrigin ? 'outside target origin'
        : ['GET', 'HEAD'].includes(method) ? null : 'write blocked';
      if (reason) {
        block(method, request.url(), reason);
        return route.abort('blockedbyclient');
      }
      return route.continue();
    }));
    await guard(context.routeWebSocket('**/*', socket => {
      block('WEBSOCKET', socket.url(), 'websocket');
      socket.close();
    }));
    await guard(context.addCookies(cookies.map(({ name, value }) => ({ name, value, url: allowedOrigin }))));

    const page = await guard(context.newPage());
    page.setDefaultTimeout(timeoutMs);
    page.on('popup', popup => { void popup.close().catch(() => {}); });
    page.on('dialog', dialog => {
      pushCapped(dialogs, { type: dialog.type(), message: String(dialog.message()).slice(0, 200) }, 10);
      void dialog.dismiss().catch(() => {});
    });
    page.on('console', message => {
      pushCapped(consoleMessages, { type: message.type(), text: message.text().slice(0, 200) }, 20);
    });
    page.on('pageerror', error => {
      pageErrorCount += 1;
      pushCapped(pageErrorMessages, String(error.message).slice(0, 200), 10);
    });
    await guard(page.exposeBinding(bindingName, (source, value) => {
      bindingCalls.push({ value: String(value).slice(0, 128), mainFrame: source.frame === page.mainFrame() });
    }));

    const goto = async (path, { readySelector } = {}) => {
      const response = await guard(page.goto(new URL(path, origin).href, { waitUntil: 'domcontentloaded', timeout: remaining() }).catch(() => null));
      const finalUrl = page.url();
      let ready = originOf(finalUrl) === allowedOrigin;
      if (ready && readySelector) {
        ready = await page.waitForSelector(readySelector, { timeout: remaining() }).then(() => true, () => false);
      }
      return { status: response?.status() ?? null, finalUrl, ready };
    };

    const selfCheck = async () => {
      const control = randomBytes(8).toString('hex');
      await guard(page.evaluate(([name, value]) => window[name](value), [bindingName, control]).catch(() => {}));
      return waitForBinding(control, 1000);
    };

    const screenshot = async (outDir, label, { selector, fullPage } = {}) => {
      const file = `images/${label}-${randomBytes(4).toString('hex')}.png`;
      const png = await guard(selector ? page.locator(selector).first().screenshot() : page.screenshot({ fullPage }));
      await guard(mkdir(join(outDir, 'images'), { recursive: true }));
      await guard(writeFile(join(outDir, file), png));
      return { label, file, sha256: `sha256:${createHash('sha256').update(png).digest('hex')}`, bytes: png.length };
    };

    const observe = async () => {
      const title = await guard(page.title().catch(() => ''));
      const text = await guard(page.evaluate(() => document.body?.innerText ?? '').catch(() => ''));
      return {
        finalUrl: page.url(),
        title: String(title).slice(0, 200),
        text: clipBytes(String(text), 4096),
        dialogs: dialogs.slice(),
        console: consoleMessages.slice(),
        pageErrors: pageErrorMessages.slice(),
        bindingCalls: bindingCalls.map(call => ({ ...call })),
        blocked: blocked.map(entry => ({ ...entry })),
      };
    };

    return {
      page,
      goto,
      bindingCalls,
      waitForBinding: (value, ms) => guard(waitForBinding(value, ms)),
      selfCheck: () => guard(selfCheck()),
      screenshot: (outDir, label, options) => guard(screenshot(outDir, label, options)),
      observe: () => guard(observe()),
      blocked,
      pageErrors: () => pageErrorCount,
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
