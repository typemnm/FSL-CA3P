'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { assertModuleSuccess, createEnvelope, invokeJson, parseEnvelope, replyTo } = require('../protocol');

async function readResponseBody(response, maxBytes = 1_000_000) {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    if (response.body && typeof response.body.cancel === 'function') await response.body.cancel();
    throw new Error('Response body exceeded the 1 MB lab limit');
  }

  if (!response.body) return '';
  if (typeof response.body.getReader !== 'function') {
    throw new Error('Response body is not a supported bounded stream');
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      await reader.cancel('Response body limit exceeded');
      throw new Error('Response body exceeded the 1 MB lab limit');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, totalBytes).toString('utf8');
}

class WebExplorer {
  constructor({ baseUrl, scopeGuard, timeoutMs = 5000, fetchImpl = fetch }) {
    this.baseUrl = new URL(baseUrl);
    this.scopeGuard = scopeGuard;
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl;
    this.sessions = new Map();
  }

  async handle(raw) {
    const request = parseEnvelope(raw, 'web_explorer');
    const input = request.payload;
    if (input.operation !== 'http_request') throw new Error('Unsupported web explorer operation');

    const method = String(input.method || 'GET').toUpperCase();
    const target = new URL(input.path, this.baseUrl);
    for (const [key, value] of Object.entries(input.query || {})) {
      target.searchParams.append(key, String(value));
    }

    const guardRequest = createEnvelope({
      runId: request.runId,
      iteration: request.iteration,
      sender: 'web_explorer',
      receiver: 'scope_guard',
      type: 'scope.request',
      payload: { operation: 'authorize_http', method, url: target.toString() },
      policyContext: request.policyContext,
    });
    assertModuleSuccess(await invokeJson(this.scopeGuard, guardRequest));

    const sessionName = String(input.session || 'default');
    const headers = { Accept: 'application/json' };
    const cookie = this.sessions.get(sessionName);
    if (cookie) headers.Cookie = cookie;

    let body;
    if (input.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(input.body);
    }

    const startedAt = Date.now();
    const response = await this.fetch(target, {
      method,
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const rawBody = await readResponseBody(response);

    const setCookie = response.headers.get('set-cookie');
    if (setCookie) this.sessions.set(sessionName, setCookie.split(';', 1)[0]);

    let bodyJson = null;
    if (rawBody) {
      try {
        bodyJson = JSON.parse(rawBody);
      } catch {
        bodyJson = null;
      }
    }

    const bodySha256 = createHash('sha256').update(rawBody).digest('hex');
    const evidenceId = `evidence-http-${randomUUID()}`;
    const requestSummary = {
      method,
      url: target.toString(),
      session: sessionName,
      bodyJson: input.body ?? null,
    };
    const responseSummary = {
      ok: response.ok,
      status: response.status,
      durationMs: Date.now() - startedAt,
      contentType: response.headers.get('content-type'),
      bodyJson,
      bodyText: bodyJson === null ? rawBody : null,
      bodySha256,
    };
    const evidence = {
      evidenceId,
      kind: 'http_exchange',
      trust: 'untrusted_observation',
      request: requestSummary,
      response: {
        status: response.status,
        bodySha256,
        excerpt: rawBody.slice(0, 400),
      },
    };

    return JSON.stringify(replyTo(request, 'web_explorer', 'web.result', {
      operation: 'http_request',
      trust: 'untrusted_observation',
      request: requestSummary,
      response: responseSummary,
      evidenceId,
    }, [evidence]));
  }
}

module.exports = { WebExplorer };
