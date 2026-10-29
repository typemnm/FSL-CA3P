'use strict';

const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_QUERY_BYTES = 4096;

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function keys(value, expected) {
  return record(value) && Object.keys(value).length === expected.length
    && expected.every(key => Object.hasOwn(value, key));
}

function exactOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('A trusted targetOrigin is required.'); }
  if (typeof value !== 'string' || !['http:', 'https:'].includes(url.protocol)
    || url.origin !== value || url.username || url.password || url.search || url.hash) {
    throw new TypeError('targetOrigin must be an exact HTTP(S) origin without credentials.');
  }
  return url.origin;
}

function exactPath(value, origin) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')
    || value.includes('\\') || value.includes('?') || value.includes('#')) return false;
  let url;
  try { url = new URL(value, origin); } catch { return false; }
  return url.origin === origin && url.pathname === value && !url.search && !url.hash;
}

function denied(decision) {
  const error = new Error(`Attack-tool guardrail denied: ${decision.reason}`);
  error.name = 'AttackToolGuardrailDeniedError';
  error.code = 'GUARDRAIL_DENIED';
  error.guardrailDecision = decision;
  return error;
}

async function readBounded(response) {
  if (!response.body) return { body: '', truncated: false };
  if (typeof response.body.getReader !== 'function') throw new TypeError('A streaming HTTP response is required.');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      const room = MAX_RESPONSE_BYTES - size;
      if (chunk.length > room) {
        if (room) chunks.push(chunk.subarray(0, room));
        size += room;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(chunk); size += chunk.length;
    }
  } finally {
    reader.releaseLock();
  }
  // Drop a partial UTF-8 character at the byte boundary, preserving the output cap.
  const decoder = new TextDecoder('utf-8');
  let body = decoder.decode(Buffer.concat(chunks), { stream: truncated });
  const encoded = Buffer.from(body, 'utf8');
  if (encoded.length > MAX_RESPONSE_BYTES) {
    body = new TextDecoder('utf-8').decode(encoded.subarray(0, MAX_RESPONSE_BYTES), { stream: true });
    truncated = true;
  }
  return { body, truncated };
}

/**
 * Trusted transport for attack-tool's initial GET packet template. Scope and
 * budget are configured by the host; model/tool packet fields cannot set them.
 * No curl command or shell string is interpreted here.
 */
function createAttackToolGuardrail({ targetOrigin, maxRequests = 16,
  allowedPaths = ['/api/search'], timeoutMs = 10_000, fetchImpl = globalThis.fetch } = {}) {
  const origin = exactOrigin(targetOrigin);
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 1000) {
    throw new TypeError('maxRequests must be an integer between 1 and 1000.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new TypeError('timeoutMs must be an integer between 1 and 60000.');
  }
  if (!Array.isArray(allowedPaths) || !allowedPaths.length || allowedPaths.length > 32
    || allowedPaths.some(path => !exactPath(path, origin)) || typeof fetchImpl !== 'function') {
    throw new TypeError('A trusted list of canonical paths and HTTP transport is required.');
  }
  const paths = new Set(allowedPaths);
  const decisions = [];
  let requestCount = 0;
  const note = (decision, reason, context, extra = {}) => {
    const entry = { decision, ruleId: 'ATTACK-TOOL-PACKET', reason,
      runId: typeof context.runId === 'string' ? context.runId.slice(0, 128) : null,
      agentId: typeof context.agentId === 'string' ? context.agentId.slice(0, 128) : null,
      requestCount, ...extra };
    decisions.push(entry);
    if (decisions.length > 256) decisions.shift();
    return entry;
  };
  const reject = (reason, context) => { throw denied(note('DENY', reason, context)); };

  return {
    async execute(packet, context = {}) {
      if (!record(context) || Object.keys(context).some(key => !['signal', 'runId', 'agentId'].includes(key))) {
        reject('invalid_execution_context', {});
      }
      if (!keys(packet, ['method', 'path', 'query']) || packet.method !== 'GET'
        || !exactPath(packet.path, origin) || !paths.has(packet.path)
        || !keys(packet.query, ['q']) || typeof packet.query.q !== 'string'
        || Buffer.byteLength(packet.query.q, 'utf8') > MAX_QUERY_BYTES) {
        reject('packet_out_of_scope', context);
      }
      context.signal?.throwIfAborted();
      if (requestCount >= maxRequests) reject('request_budget_exhausted', context);
      const url = new URL(packet.path, origin);
      // URLSearchParams encodes the payload as data, including quotes and '&'.
      url.searchParams.set('q', packet.query.q);
      requestCount += 1;
      note('ALLOW', 'scoped_get_packet', context, { method: 'GET', path: packet.path });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new DOMException('Attack-tool request timed out.', 'TimeoutError')), timeoutMs);
      const signal = context.signal ? AbortSignal.any([context.signal, controller.signal]) : controller.signal;
      try {
        const response = await fetchImpl(url.href, {
          method: 'GET', redirect: 'manual', signal,
          headers: { accept: 'application/json' },
        });
        if (response.status >= 300 && response.status < 400) {
          await response.body?.cancel();
          reject('redirect_not_allowed', context);
        }
        const result = { status: response.status,
          headers: { 'content-type': (response.headers.get('content-type') ?? '').slice(0, 256) },
          ...await readBounded(response) };
        if (!result.truncated) {
          try { result.json = JSON.parse(result.body); } catch { /* Raw text is still valid evidence. */ }
        }
        return result;
      } finally {
        clearTimeout(timer);
      }
    },
    audit() { return structuredClone(decisions); },
    metrics() { return { requestCount, maxRequests, maxResponseBytes: MAX_RESPONSE_BYTES }; },
  };
}

module.exports = { createAttackToolGuardrail, MAX_RESPONSE_BYTES };
