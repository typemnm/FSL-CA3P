'use strict';

const { spawn } = require('node:child_process');

const MAX_BODY_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const CURL_MAX_SECONDS = 10;
const PROCESS_TIMEOUT_MS = 12_000;

function failure(error, status = null, bodyJson = {}, setCookie = null) {
  return { success: false, status, bodyJson, setCookie, error };
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isJsonValue(value, depth = 0) {
  if (depth > 24) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((item) => isJsonValue(item, depth + 1));
  if (!isPlainObject(value)) return false;

  return Object.getOwnPropertyNames(value).every((key) => {
    const property = Object.getOwnPropertyDescriptor(value, key);
    return property.enumerable && Object.hasOwn(property, 'value') && isJsonValue(property.value, depth + 1);
  });
}

function parseAllowedOrigin(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  let origin;
  try {
    origin = new URL(value);
  } catch {
    return null;
  }
  if (origin.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(origin.hostname)) return null;
  if (origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) return null;
  if (origin.origin !== value) return null;
  return origin;
}

function parseCommand(command, allowedOrigin) {
  if (!isPlainObject(command)) return { error: 'invalid_command' };
  const keys = Object.keys(command);
  if (keys.some((key) => !['method', 'url', 'body'].includes(key)) ||
      !Object.hasOwn(command, 'method') || !Object.hasOwn(command, 'url')) {
    return { error: 'invalid_command' };
  }

  const method = command.method;
  if (!['GET', 'POST', 'DELETE'].includes(method)) return { error: 'unsupported_method' };

  const rawUrl = command.url;
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 8192 ||
      rawUrl.trim() !== rawUrl || /[\u0000-\u001f\u007f\\#]/u.test(rawUrl)) {
    return { error: 'invalid_url' };
  }
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { error: 'invalid_url' };
  }
  if (url.protocol !== 'http:' || url.username || url.password || url.hash ||
      url.origin !== allowedOrigin.origin) {
    return { error: 'origin_not_allowed' };
  }

  const hasBody = Object.hasOwn(command, 'body');
  if (hasBody && method !== 'POST') return { error: 'body_not_allowed' };
  let serializedBody = null;
  if (hasBody) {
    if (!isPlainObject(command.body) || !isJsonValue(command.body)) return { error: 'invalid_body' };
    serializedBody = JSON.stringify(command.body);
    if (Buffer.byteLength(serializedBody, 'utf8') > MAX_BODY_BYTES) return { error: 'body_too_large' };
  }

  return { method, url: url.href, serializedBody };
}

function findHeaderEnd(buffer, start) {
  const crlf = buffer.indexOf('\r\n\r\n', start);
  const lf = buffer.indexOf('\n\n', start);
  if (crlf < 0 && lf < 0) return null;
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) return { index: crlf, length: 4 };
  return { index: lf, length: 2 };
}

function parseResponse(output) {
  let cursor = 0;
  for (let interim = 0; interim < 5; interim += 1) {
    const end = findHeaderEnd(output, cursor);
    if (!end) return null;
    const headerText = output.subarray(cursor, end.index).toString('latin1');
    const [statusLine, ...headerLines] = headerText.split(/\r?\n/u);
    const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/u.exec(statusLine);
    if (!match) return null;
    const status = Number(match[1]);
    cursor = end.index + end.length;
    if (status >= 100 && status < 200 && status !== 101) continue;

    let setCookie = null;
    for (const line of headerLines) {
      if (!/^set-cookie\s*:/iu.test(line)) continue;
      setCookie = line.slice(line.indexOf(':') + 1).trim() || null;
      break;
    }

    const body = output.subarray(cursor).toString('utf8');
    let bodyJson = {};
    let jsonValid = body.length === 0;
    if (body.length > 0) {
      try {
        const parsed = JSON.parse(body);
        if (isPlainObject(parsed)) {
          bodyJson = parsed;
          jsonValid = true;
        }
      } catch {
        // A failed or non-JSON HTTP response is still returned with its status.
      }
    }
    return { status, bodyJson, setCookie, jsonValid };
  }
  return null;
}

function childEnv() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(?:http|https|all|no)_proxy$/iu.test(key)) continue;
    env[key] = value;
  }
  return env;
}

/**
 * Execute one narrowly scoped curl request. The command is data, never a shell
 * command or a list of user-controlled curl flags. The caller owns session
 * cookies and must keep the returned Set-Cookie value outside agent events.
 */
async function executeCurl(command, { allowedOrigin, cookie = null, signal } = {}) {
  const origin = parseAllowedOrigin(allowedOrigin);
  if (!origin) return failure('invalid_allowed_origin');

  const parsed = parseCommand(command, origin);
  if (parsed.error) return failure(parsed.error);
  if (signal?.aborted) return failure('aborted');
  if (cookie !== null && (typeof cookie !== 'string' || cookie.length === 0 ||
      cookie.length > 4096 || !cookie.includes('=') || /[\u0000-\u001f\u007f]/u.test(cookie))) {
    return failure('invalid_cookie');
  }

  const args = [
    '--disable',
    '--silent',
    '--show-error',
    '--include',
    '--globoff',
    '--noproxy', '*',
    '--proto', '=http',
    '--max-redirs', '0',
    '--connect-timeout', '3',
    '--max-time', String(CURL_MAX_SECONDS),
    '--request', parsed.method,
    '--url', parsed.url,
    '--header', 'Accept: application/json',
  ];
  if (cookie !== null) args.push('--cookie', cookie);
  if (parsed.serializedBody !== null) {
    args.push('--header', 'Content-Type: application/json');
    args.push('--data-binary', parsed.serializedBody);
  }

  const executable = process.platform === 'win32' ? 'curl.exe' : 'curl';
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(executable, args, {
        shell: false,
        windowsHide: true,
        env: childEnv(),
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch {
      resolve(failure('curl_unavailable'));
      return;
    }

    const output = [];
    let outputBytes = 0;
    let stderrBytes = 0;
    let tooLarge = false;
    let aborted = false;
    let timedOut = false;
    let settled = false;
    const onAbort = () => {
      aborted = true;
      child.kill();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, PROCESS_TIMEOUT_MS);
    signal?.addEventListener('abort', onAbort, { once: true });

    function finish(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolve(result);
    }

    child.stdout.on('data', (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_RESPONSE_BYTES) {
        tooLarge = true;
        child.kill();
        return;
      }
      output.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_STDERR_BYTES) child.stderr.pause();
    });
    child.on('error', () => finish(failure('curl_unavailable')));
    child.on('close', (code) => {
      if (tooLarge) return finish(failure('response_too_large'));
      if (aborted || signal?.aborted) return finish(failure('aborted'));
      if (timedOut || code === 28) return finish(failure('timeout'));
      if (code !== 0) return finish(failure(`curl_exit_${code ?? 'unknown'}`));

      const response = parseResponse(Buffer.concat(output));
      if (!response) return finish(failure('invalid_http_response'));
      const { status, bodyJson, setCookie, jsonValid } = response;
      if (status < 200 || status >= 300) {
        return finish(failure(`http_${status}`, status, bodyJson, setCookie));
      }
      if (!jsonValid) return finish(failure('invalid_json_response', status, bodyJson, setCookie));
      finish({ success: true, status, bodyJson, setCookie, error: null });
    });
  });
}

module.exports = { executeCurl };
