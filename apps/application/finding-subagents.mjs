import { createHash } from 'node:crypto';

const PRIORITY = Object.freeze({ inconclusive: 0, not_tested: 1, confirmed: 2 });
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value);
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

export const PARENT_EXECUTION_LIMITS = Object.freeze({
  maxTargetRequests: 224,
  maxModelRequests: 160,
  maxModelTokens: 1_000_000,
  deadlineMs: 30 * 60 * 1000,
});

function limitError(code) {
  return Object.assign(new Error(code), { code, fatalProbe: true });
}

/** Reservations happen synchronously, before concurrent children can send work. */
export function createSharedExecutionBudget(limits = PARENT_EXECUTION_LIMITS) {
  for (const key of ['maxTargetRequests', 'maxModelRequests', 'maxModelTokens']) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1) throw new TypeError('Invalid parent execution limit.');
  }
  if (!Number.isSafeInteger(limits.deadlineMs) || limits.deadlineMs < 1) {
    throw new TypeError('Invalid parent execution deadline.');
  }
  let targetRequests = 0;
  let pendingTargetRequests = 0;
  let modelRequests = 0;
  let modelTokens = 0;
  return {
    reserveTargetRequest(count = 1) {
      if (!Number.isSafeInteger(count) || count < 1) throw new TypeError('Invalid target request count.');
      if (targetRequests + pendingTargetRequests + count > limits.maxTargetRequests) {
        throw limitError('PARENT_TARGET_REQUEST_BUDGET_EXCEEDED');
      }
      targetRequests += count;
    },
    // Chromium follows at most 20 redirects for one routed request. Playwright
    // only routes the first URL, so reserve the full chain before dispatch.
    reserveBrowserRequest() {
      const maximum = 21;
      if (targetRequests + pendingTargetRequests + maximum > limits.maxTargetRequests) {
        throw limitError('PARENT_TARGET_REQUEST_BUDGET_EXCEEDED');
      }
      pendingTargetRequests += maximum;
      let settled = false;
      return (actualRequests, complete = true) => {
        if (settled) return;
        settled = true;
        const observed = Number.isSafeInteger(actualRequests) && actualRequests >= 0
          && actualRequests <= maximum ? actualRequests : 0;
        targetRequests += observed;
        pendingTargetRequests -= complete ? maximum : observed;
      };
    },
    reserveModelRequest(tokenEstimate) {
      if (!Number.isSafeInteger(tokenEstimate) || tokenEstimate < 1) throw new TypeError('Invalid model token estimate.');
      if (modelRequests >= limits.maxModelRequests) throw limitError('PARENT_MODEL_REQUEST_BUDGET_EXCEEDED');
      if (modelTokens + tokenEstimate > limits.maxModelTokens) throw limitError('PARENT_MODEL_TOKEN_BUDGET_EXCEEDED');
      modelRequests += 1;
      modelTokens += tokenEstimate;
      let settled = false;
      return actualTokens => {
        if (settled) return;
        settled = true;
        if (Number.isSafeInteger(actualTokens) && actualTokens >= 0) {
          modelTokens += actualTokens - tokenEstimate;
        }
      };
    },
    snapshot() { return { targetRequests, pendingTargetRequests, modelRequests, modelTokens, ...limits }; },
  };
}

/** Read requests may overlap; state-changing requests exclude all target reads and writes. */
export function createTargetRequestGate() {
  let readers = 0;
  let writer = false;
  const queue = [];
  const drain = () => {
    if (writer || !queue.length || (readers && queue[0].write)) return;
    if (queue[0].write) {
      writer = true;
      queue.shift().resolve(() => { writer = false; drain(); });
    } else {
      while (queue.length && !queue[0].write) {
        readers += 1;
        queue.shift().resolve(() => { readers -= 1; drain(); });
      }
    }
  };
  return {
    acquire(method = 'GET', signal) {
      signal?.throwIfAborted();
      const write = !['GET', 'HEAD', 'OPTIONS'].includes(String(method).toUpperCase());
      return new Promise((resolve, reject) => {
        const entry = { write, resolve: release => {
          signal?.removeEventListener('abort', abort);
          let used = false;
          resolve(() => { if (!used) { used = true; release(); } });
        } };
        const abort = () => {
          const index = queue.indexOf(entry);
          if (index >= 0) queue.splice(index, 1);
          reject(signal.reason ?? Object.assign(new Error('Aborted'), { name: 'AbortError' }));
          drain();
        };
        signal?.addEventListener('abort', abort, { once: true });
        queue.push(entry);
        drain();
      });
    },
  };
}

/** Select only findings whose original hypothesis and cited observations still exist. */
export function selectFindingSubtasks(report, { runId, maxTasks, probeBudget, eligible } = {}) {
  if (!id(runId) || !Number.isSafeInteger(maxTasks) || maxTasks < 1 || maxTasks > 4
    || !Number.isSafeInteger(probeBudget) || probeBudget < 0
    || (eligible !== undefined && typeof eligible !== 'function')) throw new TypeError('Invalid finding subtask options.');
  const hypotheses = new Map((report?.hypotheses ?? []).map(row => [row?.id, row]));
  const evidence = new Map((report?.evidence ?? []).map(row => [row?.id, row]));
  const seen = new Set();
  const candidates = (report?.findings ?? []).flatMap((finding, index) => {
    if (!finding || !id(finding.id) || seen.has(finding.id) || !Object.hasOwn(PRIORITY, finding.status)) return [];
    seen.add(finding.id);
    // A refused or policy-blocked probe must not be retried through a child.
    // The core uses no_probe when a hypothesis received no probe at all.
    if (finding.status === 'not_tested' && finding.reason !== undefined && finding.reason !== 'no_probe') return [];
    // The first child implementation has only read-only tools, not template execution.
    if (finding.templateId !== undefined || (eligible && !eligible(finding))) return [];
    const hypothesis = hypotheses.get(finding.hypothesisId);
    if (!hypothesis || !id(hypothesis.id) || !Array.isArray(hypothesis.evidenceIds)
      || !hypothesis.evidenceIds.length || hypothesis.evidenceIds.some(ref => !evidence.has(ref))) return [];
    const evidenceIds = [...new Set([...hypothesis.evidenceIds,
      ...(Array.isArray(finding.evidenceIds) ? finding.evidenceIds : [])])];
    if (evidenceIds.some(ref => !evidence.has(ref))) return [];
    const sourceEvidence = evidenceIds.map(ref => evidence.get(ref));
    const sourceFindingDigest = hash({ finding, hypothesis, sourceEvidence });
    const subtaskId = `sub-${hash({ runId, findingId: finding.id, sourceFindingDigest }).slice(0, 24)}`;
    return [{ id: subtaskId, agentId: subtaskId, sourceFindingId: finding.id, sourceFindingDigest,
      finding, hypothesis, evidence: sourceEvidence, index }];
  }).sort((a, b) => PRIORITY[a.finding.status] - PRIORITY[b.finding.status] || a.index - b.index);
  const selected = candidates.slice(0, Math.min(maxTasks, Math.ceil(probeBudget / 2)));
  return selected.map((task, index) => ({ ...task, maxProbes: Math.min(2, probeBudget - index * 2) }));
}

/** Bound concurrent child loops. Every task settles before the parent becomes terminal. */
export async function runFindingSubtasks(tasks, concurrency, execute, signal) {
  if (!Array.isArray(tasks) || !Number.isSafeInteger(concurrency) || concurrency < 1
    || typeof execute !== 'function') throw new TypeError('Invalid subtask pool.');
  let next = 0;
  const results = new Array(tasks.length);
  const worker = async () => {
    while (next < tasks.length) {
      if (signal?.aborted) return;
      const index = next++;
      results[index] = await execute(tasks[index], index);
    }
  };
  const settled = await Promise.allSettled(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  const failure = settled.find(item => item.status === 'rejected');
  if (failure) throw failure.reason;
  return results;
}
