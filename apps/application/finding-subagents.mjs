import { createHash } from 'node:crypto';

const PRIORITY = Object.freeze({ inconclusive: 0, not_tested: 1, confirmed: 2 });
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value);
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

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
