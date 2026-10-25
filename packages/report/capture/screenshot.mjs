/**
 * capture_screenshot implementation (PLAN §2.5). Opens the bundle's loopback
 * target in the sandbox, optionally performs the one allow-listed session
 * switch, and writes PNGs to outDir. The only write the target can see is
 * that session switch; the sandbox blocks everything else.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { CaptureError, bodyText, openSandbox } from './sandbox.mjs';

export { CaptureError } from './sandbox.mjs';

/** Accept exactly `http://127.0.0.1:<port>`; no path, credentials or default port. */
export function loopbackOrigin(value, name = 'origin') {
  const match = typeof value === 'string' && /^http:\/\/127\.0\.0\.1:(\d{1,5})$/.exec(value);
  const port = match ? Number(match[1]) : 0;
  if (!match || port < 1 || port > 65535 || new URL(value).origin !== value) {
    throw new CaptureError('INVALID_ORIGIN', `${name} must be http://127.0.0.1:<port>.`);
  }
  return value;
}

function sameOrigin(page, origin) {
  if (new URL(page.url()).origin !== origin) {
    throw new CaptureError('LEFT_ORIGIN', 'The browser left the target origin.');
  }
}

async function load(page, url, remaining) {
  const response = await page.goto(url, { waitUntil: 'networkidle', timeout: remaining() });
  if (!response || response.status() >= 400) {
    throw new CaptureError('TARGET_HTTP_ERROR', `The target returned HTTP ${response?.status() ?? 'no response'}.`);
  }
}

/**
 * Returns one metadata record per PNG: the element shot (selector), the full
 * page (fullPage), or the viewport when neither is asked for.
 */
export async function capture(origin, {
  selector, fullPage = false, sessionSwitch, allowSessionSwitches, outDir, expectedOrigin, timeoutMs,
} = {}) {
  loopbackOrigin(origin);
  if (expectedOrigin === undefined) {
    throw new CaptureError('ORIGIN_MISMATCH', 'expectedOrigin is required (the bundle target.origin).');
  }
  if (origin !== loopbackOrigin(expectedOrigin, 'expectedOrigin')) {
    throw new CaptureError('ORIGIN_MISMATCH', 'origin does not equal the bundle target origin.');
  }
  if (typeof outDir !== 'string' || !outDir) throw new CaptureError('INVALID_OUT_DIR', 'outDir is required.');
  if (selector !== undefined && (typeof selector !== 'string' || !selector.trim())) {
    throw new CaptureError('INVALID_SELECTOR', 'selector must be a non-empty string.');
  }

  const sandbox = await openSandbox(origin, { allowSessionSwitches, timeoutMs });
  const { page, remaining, blocked, sessionSwitches } = sandbox;
  try {
    const url = `${origin}/`;
    await load(page, url, remaining);
    sameOrigin(page, origin);

    if (sessionSwitch) {
      const { method, path, body } = sessionSwitch;
      const text = bodyText(body);
      const status = await page.evaluate(async request => {
        try {
          const response = await fetch(request.path, {
            method: request.method,
            credentials: 'same-origin',
            ...(request.text ? { body: request.text, headers: { 'content-type': 'application/json' } } : {}),
          });
          return response.status;
        } catch { return null; }
      }, { method: String(method).toUpperCase(), path, text });
      if (sessionSwitches.length === 0 || status === null) {
        throw new CaptureError('SESSION_SWITCH_BLOCKED', 'The session switch does not match the allow-list.');
      }
      if (status >= 400) throw new CaptureError('SESSION_SWITCH_FAILED', `The session switch returned HTTP ${status}.`);
      await load(page, url, remaining);
      sameOrigin(page, origin);
    }

    const dir = resolve(outDir);
    await mkdir(dir, { recursive: true });
    const shots = [];
    if (selector) shots.push(['element', path => page.locator(selector).first().screenshot({ path, timeout: remaining() })]);
    if (fullPage) shots.push(['fullPage', path => page.screenshot({ path, fullPage: true, timeout: remaining() })]);
    if (!shots.length) shots.push(['viewport', path => page.screenshot({ path, timeout: remaining() })]);

    const records = [];
    for (const [kind, take] of shots) {
      const path = join(dir, `${kind}-${Date.now()}-${randomBytes(4).toString('hex')}.png`);
      let buffer;
      try { buffer = await take(path); }
      catch (cause) {
        if (kind === 'element' && !sandbox.state.timedOut) {
          throw new CaptureError('SELECTOR_NOT_FOUND', `No visible element for selector ${selector}.`, { cause });
        }
        throw cause;
      }
      records.push({
        kind,
        url,
        selector: kind === 'element' ? selector : null,
        // null = the target's default session (vul-web-1: alice).
        viewer: sessionSwitch ? (sessionSwitch.body?.userId ?? bodyText(sessionSwitch.body)) : null,
        capturedAt: new Date().toISOString(),
        pageUrl: page.url(),
        path,
        sizeBytes: buffer.length,
        sha256: `sha256:${createHash('sha256').update(buffer).digest('hex')}`,
        mime: 'image/png',
      });
    }
    const observations = { blocked: [...blocked], sessionSwitch: sessionSwitches[0] ?? null };
    return records.map(record => ({ ...record, observations }));
  } catch (cause) {
    if (sandbox.state.timedOut) throw new CaptureError('TIMEOUT', 'Capture timed out.', { cause });
    if (cause instanceof CaptureError) throw cause;
    throw new CaptureError('CAPTURE_FAILED', `Capture failed: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
  } finally {
    await sandbox.close();
  }
}
