'use strict';

const { randomUUID } = require('node:crypto');

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const KINDS = new Set(['general-probe', 'rule-idor']);
const DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;

function fault(code, status = 409) {
  return Object.assign(new Error(code), { code, status });
}

function abortError() {
  return Object.assign(new Error('Approval wait aborted.'), { name: 'AbortError' });
}

/** One pending human decision per run. The caller publishes only a bounded safe summary. */
function createApprovalController({ runId, onPending, onResolved,
  timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof runId !== 'string' || !ID.test(runId)) throw new TypeError('Valid runId is required.');
  if (typeof onPending !== 'function' || typeof onResolved !== 'function') {
    throw new TypeError('Synchronous approval lifecycle callbacks are required.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DEFAULT_TIMEOUT_MS) {
    throw new TypeError('Approval timeout must be 1..1800000 milliseconds.');
  }
  let active = null;

  function finish(entry, decision, actor) {
    if (active !== entry) throw fault('APPROVAL_NOT_PENDING');
    active = null;
    clearTimeout(entry.timer);
    entry.signal?.removeEventListener('abort', entry.onAbort);
    const outcome = { id: entry.pending.id, decision,
      ...(actor ? { actor } : {}), decidedAt: new Date().toISOString() };
    try {
      const result = onResolved(structuredClone(outcome));
      if (result && typeof result.then === 'function') throw new TypeError('onResolved must be synchronous.');
    } catch (error) {
      entry.reject(error);
      throw error;
    }
    if (decision === 'cancelled' || entry.signal?.aborted) entry.reject(abortError());
    else entry.resolve(outcome);
    return outcome;
  }

  function request({ kind, probeId, summary, actionDigest, signal } = {}) {
    if (active) throw fault('APPROVAL_ALREADY_PENDING');
    if (!KINDS.has(kind) || probeId !== undefined && (typeof probeId !== 'string' || !ID.test(probeId))
      || typeof actionDigest !== 'string' || !DIGEST.test(actionDigest)) {
      throw new TypeError('Invalid approval request.');
    }
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) {
      throw new TypeError('A safe approval summary is required.');
    }
    let safeSummary;
    try {
      safeSummary = JSON.parse(JSON.stringify(summary));
      if (!safeSummary || typeof safeSummary !== 'object' || Array.isArray(safeSummary)
        || Buffer.byteLength(JSON.stringify(safeSummary), 'utf8') > 4096) throw new Error();
    } catch { throw new TypeError('Approval summary must be bounded JSON.'); }
    if (signal?.aborted) return Promise.reject(abortError());
    if (signal !== undefined && typeof signal?.addEventListener !== 'function') {
      throw new TypeError('signal must be an AbortSignal.');
    }
    const requested = Date.now();
    const pending = { id: randomUUID(), runId, kind,
      ...(probeId ? { probeId } : {}), summary: safeSummary, actionDigest,
      requestedAt: new Date(requested).toISOString(),
      expiresAt: new Date(requested + timeoutMs).toISOString() };
    return new Promise((resolve, reject) => {
      const entry = { pending, signal, resolve, reject, timer: null, onAbort: null };
      active = entry;
      entry.onAbort = () => { try { finish(entry, 'cancelled'); } catch { /* Promise is rejected by finish. */ } };
      signal?.addEventListener('abort', entry.onAbort, { once: true });
      entry.timer = setTimeout(() => { try { finish(entry, 'timed_out'); } catch { /* Promise is rejected by finish. */ } }, timeoutMs);
      try {
        const result = onPending(structuredClone(pending));
        if (result && typeof result.then === 'function') throw new TypeError('onPending must be synchronous.');
      } catch (error) {
        if (active === entry) {
          active = null;
          clearTimeout(entry.timer);
          signal?.removeEventListener('abort', entry.onAbort);
          reject(error);
        }
      }
    });
  }

  function decide({ id, decision, actor } = {}) {
    if (typeof id !== 'string' || !ID.test(id) || !['approve', 'reject'].includes(decision)
      || typeof actor !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/u.test(actor)) {
      throw Object.assign(new TypeError('Invalid approval decision.'), { status: 400, code: 'INVALID_APPROVAL_DECISION' });
    }
    if (!active || active.pending.id !== id) throw fault('APPROVAL_NOT_PENDING');
    if (Date.now() >= Date.parse(active.pending.expiresAt)) {
      finish(active, 'timed_out');
      throw fault('APPROVAL_EXPIRED');
    }
    return finish(active, decision === 'approve' ? 'approved' : 'rejected', actor);
  }

  return { request, decide, current: () => active ? structuredClone(active.pending) : null };
}

module.exports = { createApprovalController, DEFAULT_TIMEOUT_MS };
