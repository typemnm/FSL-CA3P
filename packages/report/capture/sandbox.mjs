/**
 * Hardened Playwright context for one loopback origin (PLAN §2.5). Mirrors the
 * verify-stage sandbox in packages/adapters/integrations/xss-parser.mjs
 * (observeStoredXssExecution): same-origin GET/HEAD only, no WebSocket, no
 * service workers, no downloads, popups closed, dialogs dismissed, deadline.
 * The single exception is one session-switch request that exactly matches an
 * allow-list entry handed in by the collector; an empty list permits none.
 */

import { chromium } from 'playwright';

export const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_BLOCKED = 32;

export class CaptureError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.code = code;
  }
}

/** Body as the browser sends it: strings verbatim, anything else as JSON. */
export function bodyText(body) {
  if (body === undefined || body === null) return '';
  return typeof body === 'string' ? body : JSON.stringify(body);
}

function normalizeSwitch(entry) {
  if (!entry || typeof entry.method !== 'string' || typeof entry.path !== 'string'
    || !entry.path.startsWith('/') || entry.path.startsWith('//')) {
    throw new CaptureError('INVALID_SESSION_SWITCH', 'A session switch needs {method, path, body} with an absolute path.');
  }
  return { method: entry.method.toUpperCase(), path: entry.path, body: bodyText(entry.body) };
}

export function normalizeSwitches(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new CaptureError('INVALID_SESSION_SWITCH', 'The session-switch allow-list must be an array.');
  return list.map(normalizeSwitch);
}

/**
 * Open a headless browser restricted to `origin`. The caller must validate the
 * origin first and always call `close()`. `blocked` records every refusal.
 */
export async function openSandbox(origin, { allowSessionSwitches, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const allowed = normalizeSwitches(allowSessionSwitches);
  const blocked = [];
  const sessionSwitches = [];
  const block = (method, url, reason) => {
    if (blocked.length < MAX_BLOCKED) blocked.push({ method, url: String(url).slice(0, 240), reason });
  };
  const deadline = Date.now() + timeoutMs;
  const remaining = () => {
    const milliseconds = deadline - Date.now();
    if (milliseconds <= 0) throw new CaptureError('TIMEOUT', 'Capture timed out.');
    return milliseconds;
  };

  let browser;
  const state = { timedOut: false };
  const deadlineTimer = setTimeout(() => {
    state.timedOut = true;
    void browser?.close().catch(() => {});
  }, timeoutMs);
  const close = async () => {
    clearTimeout(deadlineTimer);
    await browser?.close().catch(() => {});
  };

  try {
    try {
      browser = await chromium.launch({ headless: true, timeout: remaining() });
    } catch (cause) {
      throw new CaptureError('BROWSER_UNAVAILABLE',
        'Chromium could not start. Run npx playwright install chromium in packages/report/capture.', { cause });
    }
    const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    await context.route('**/*', async route => {
      const request = route.request();
      const method = request.method();
      let url = null;
      try { url = new URL(request.url()); }
      catch { /* Unparseable browser requests are blocked. */ }
      if (!url || url.origin !== origin) {
        block(method, request.url(), 'outside target origin');
        await route.abort('blockedbyclient');
        return;
      }
      if (method === 'GET' || method === 'HEAD') {
        await route.continue();
        return;
      }
      const path = url.pathname + url.search;
      const body = request.postData() ?? '';
      const match = allowed.find(entry => entry.method === method && entry.path === path && entry.body === body);
      if (match && sessionSwitches.length === 0) {
        sessionSwitches.push({ method, path, body });
        await route.continue();
        return;
      }
      block(method, request.url(), match ? 'session switch already used' : 'write not in session-switch allow-list');
      await route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*', webSocket => {
      block('WEBSOCKET', webSocket.url(), 'websocket');
      webSocket.close();
    });
    const page = await context.newPage();
    page.setDefaultTimeout(remaining());
    page.on('popup', popup => { void popup.close().catch(() => {}); });
    page.on('dialog', dialog => { void dialog.dismiss().catch(() => {}); });
    return { browser, context, page, blocked, sessionSwitches, remaining, state, close };
  } catch (error) {
    await close();
    if (state.timedOut) throw new CaptureError('TIMEOUT', 'Capture timed out.', { cause: error });
    throw error;
  }
}
