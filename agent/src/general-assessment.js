'use strict';

const { randomUUID } = require('node:crypto');

const SCHEMA_VERSION = 'general-assessment/1';
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const VERDICTS = new Set(['confirmed', 'not_reproduced', 'inconclusive']);
const REJECTED_PROBE_REASONS = new Set(['unknown_hypothesis_id', 'unavailable_tool',
  'unsafe_probe_input', 'invalid_probe_schema', 'proposal_limit']);
const SENSITIVE_KEY = /^(?:(?:x[-_])?(?:api[-_]?key|auth[-_]?(?:key|token)|access[-_]?token|refresh[-_]?token|csrf[-_]?token|client[-_]?secret)|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|secret|token|session(?:[-_]?id)?|credentials?|private[-_]?key)$/iu;
const FORBIDDEN_TOOL_KEY = /^(?:(?:x[-_])?(?:api[-_]?key|auth[-_]?(?:key|token)|access[-_]?token|refresh[-_]?token|csrf[-_]?token|client[-_]?secret)|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|secret|token|session(?:[-_]?id)?|credentials?|private[-_]?key|command|shell|argv)$/iu;
const LIMIT_DEFAULTS = Object.freeze({ maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 });
const LIMIT_CAPS = Object.freeze({ maxIterations: 32, maxProbes: 128, maxEvidenceItems: 256 });

function fault(code) { return Object.assign(new Error(code), { code }); }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function redactText(value) {
  return value.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/giu, '$1 [redacted]')
    .replace(/\b(password|passwd|api[_-]?key|secret|token|session|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      '$1=[redacted]');
}
function redactSensitive(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (record(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) =>
    [key, SENSITIVE_KEY.test(key) ? '[redacted]' : redactSensitive(item)]));
  return value;
}
function assertSafeToolInput(value) {
  if (Array.isArray(value)) return value.forEach(assertSafeToolInput);
  if (!record(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (FORBIDDEN_TOOL_KEY.test(key)) throw fault('FORBIDDEN_PROBE_INPUT');
    assertSafeToolInput(item);
  }
}
function boundedString(value, label, maxBytes = 512) {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value, 'utf8') > maxBytes) {
    throw fault(`INVALID_${label.toUpperCase()}`);
  }
  return redactText(value);
}
function identifier(value, label) {
  if (typeof value !== 'string' || !ID.test(value)) throw fault(`INVALID_${label.toUpperCase()}`);
  return value;
}
function eventAsset(value) {
  const withoutQuery = value.split(/[?#]/u, 1)[0];
  try {
    const url = new URL(value);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.pathname;
  } catch { /* Relative assets use the path before any query or fragment. */ }
  return withoutQuery;
}

/** Keep untrusted observations and model tool arguments JSON-only and bounded. */
function jsonValue(value, label, maxBytes) {
  const seen = new WeakSet();
  function copy(item, depth) {
    if (depth > 12) throw fault(`INVALID_${label.toUpperCase()}`);
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return item;
    if (typeof item === 'number' && Number.isFinite(item)) return item;
    if (Array.isArray(item)) {
      if (item.length > 256 || seen.has(item)) throw fault(`INVALID_${label.toUpperCase()}`);
      seen.add(item);
      return item.map(child => copy(child, depth + 1));
    }
    if (!record(item) || ![Object.prototype, null].includes(Object.getPrototypeOf(item)) || seen.has(item)) {
      throw fault(`INVALID_${label.toUpperCase()}`);
    }
    seen.add(item);
    const keys = Object.keys(item);
    if (keys.length > 128 || keys.some(key => ['__proto__', 'prototype', 'constructor'].includes(key))) {
      throw fault(`INVALID_${label.toUpperCase()}`);
    }
    return Object.fromEntries(keys.map(key => [key, copy(item[key], depth + 1)]));
  }
  const result = copy(value, 0);
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxBytes) throw fault(`${label.toUpperCase()}_TOO_LARGE`);
  return result;
}

function limitsFor(value) {
  if (value !== undefined && !record(value)) throw fault('INVALID_LIMITS');
  const result = {};
  for (const name of Object.keys(LIMIT_DEFAULTS)) {
    const number = value?.[name] ?? LIMIT_DEFAULTS[name];
    if (!Number.isSafeInteger(number) || number < 1 || number > LIMIT_CAPS[name]) throw fault('INVALID_LIMITS');
    result[name] = number;
  }
  if (value && Object.keys(value).some(key => !Object.hasOwn(LIMIT_DEFAULTS, key))) throw fault('INVALID_LIMITS');
  return result;
}

function assertPort(port, method, name) {
  if (!port || typeof port[method] !== 'function') throw new TypeError(`${name}.${method} is required`);
}

function normalizeEvidence(items, known, maxNew, label) {
  if (!Array.isArray(items) || items.length > maxNew) throw fault('INVALID_EVIDENCE');
  const local = new Set();
  return items.map(item => {
    if (!record(item)) throw fault('INVALID_EVIDENCE');
    const id = identifier(item.id, 'evidence_id');
    if (known.has(id) || local.has(id)) throw fault('DUPLICATE_EVIDENCE_ID');
    local.add(id);
    const evidence = {
      id,
      source: boundedString(item.source, 'evidence_source', 128),
      kind: boundedString(item.kind, 'evidence_kind', 128),
      summary: boundedString(item.summary, 'evidence_summary', 2048),
    };
    if (item.asset !== undefined) evidence.asset = boundedString(item.asset, 'evidence_asset', 512);
    if (item.observedAt !== undefined) evidence.observedAt = boundedString(item.observedAt, 'observed_at', 64);
    // Deliberately do not persist opaque payloads or raw HTTP bodies in the core report.
    jsonValue(evidence, label, 4096);
    return evidence;
  });
}

function evidenceRefs(value, known, label, { required = false } = {}) {
  if (!Array.isArray(value) || value.length > 32 || (required && value.length === 0)) throw fault(`INVALID_${label.toUpperCase()}`);
  const refs = value.map(id => identifier(id, label));
  if (new Set(refs).size !== refs.length || refs.some(id => !known.has(id))) throw fault(`UNKNOWN_${label.toUpperCase()}`);
  return refs;
}

function normalizeHypotheses(items, knownHypotheses, knownEvidence) {
  if (!Array.isArray(items) || items.length > 32) throw fault('INVALID_HYPOTHESES');
  const ids = new Set();
  return items.map(item => {
    if (!record(item)) throw fault('INVALID_HYPOTHESIS');
    const id = identifier(item.id, 'hypothesis_id');
    if (knownHypotheses.has(id) || ids.has(id)) throw fault('DUPLICATE_HYPOTHESIS_ID');
    ids.add(id);
    return {
      id,
      category: boundedString(item.category, 'category', 128),
      asset: boundedString(item.asset, 'asset', 512),
      rationale: boundedString(item.rationale, 'rationale', 2048),
      evidenceIds: evidenceRefs(item.evidenceIds ?? [], knownEvidence, 'hypothesis_evidence', { required: true }),
      status: 'not_tested',
    };
  });
}

function normalizeProbes(items, knownProbes, knownHypotheses, availableTools, remaining) {
  if (!Array.isArray(items) || items.length > remaining) throw fault('PROBE_BUDGET_EXCEEDED');
  const ids = new Set();
  return items.map(item => {
    if (!record(item)) throw fault('INVALID_PROBE');
    const id = identifier(item.id, 'probe_id');
    if (knownProbes.has(id) || ids.has(id)) throw fault('DUPLICATE_PROBE_ID');
    ids.add(id);
    const hypothesisId = identifier(item.hypothesisId, 'hypothesis_id');
    if (!knownHypotheses.has(hypothesisId)) throw fault('UNKNOWN_HYPOTHESIS_ID');
    const tool = identifier(item.tool, 'tool');
    if (!availableTools.includes(tool)) throw fault('UNAVAILABLE_TOOL');
    const input = jsonValue(item.input ?? {}, 'probe_input', 8192);
    if (!record(input)) throw fault('INVALID_PROBE_INPUT');
    assertSafeToolInput(input);
    return { id, hypothesisId, tool, input };
  });
}

function normalizeRejectedProbes(items, iteration) {
  if (!Array.isArray(items) || items.length > 32) throw fault('INVALID_REJECTED_PROBES');
  const seen = new Set();
  return items.map(item => {
    if (!record(item) || Object.keys(item).length !== 2
      || !Number.isSafeInteger(item.index) || item.index < 0 || item.index > 31
      || seen.has(item.index) || !REJECTED_PROBE_REASONS.has(item.reason)) {
      throw fault('INVALID_REJECTED_PROBES');
    }
    seen.add(item.index);
    return { iteration, index: item.index, reason: item.reason };
  });
}

function modelMetadata(value, iteration) {
  if (!record(value)) return null;
  const metadata = { iteration };
  for (const key of ['provider', 'model', 'requestedModel', 'reportedModel', 'status', 'finishReason']) {
    if (typeof value[key] === 'string' && Buffer.byteLength(value[key], 'utf8') <= 128) metadata[key] = value[key];
  }
  if (Number.isFinite(value.latencyMs) && value.latencyMs >= 0) metadata.latencyMs = value.latencyMs;
  if (typeof value.promptDigest === 'string' && /^[a-f0-9]{64}$/u.test(value.promptDigest)) metadata.promptDigest = value.promptDigest;
  for (const key of ['evidenceCount', 'contextRedactions']) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) metadata[key] = value[key];
  }
  if (record(value.usage)) {
    metadata.usage = {};
    for (const key of ['prompt_tokens', 'completion_tokens', 'total_tokens']) {
      if (Number.isSafeInteger(value.usage[key]) && value.usage[key] >= 0) metadata.usage[key] = value.usage[key];
    }
  }
  return metadata;
}

function buildFindings(report, verdicts) {
  report.findings = report.hypotheses.map(hypothesis => {
    const rows = verdicts.get(hypothesis.id) ?? [];
    const hasConfirmed = rows.some(row => row.status === 'confirmed');
    const hasNegative = rows.some(row => row.status === 'not_reproduced');
    const status = hasConfirmed && hasNegative ? 'inconclusive'
      : hasConfirmed ? 'confirmed'
        : rows.some(row => row.status === 'inconclusive') ? 'inconclusive'
          : hasNegative ? 'not_reproduced' : 'not_tested';
    const evidenceIds = [...new Set([...hypothesis.evidenceIds, ...rows.flatMap(row => row.evidenceIds)])];
    const reason = hasConfirmed && hasNegative ? 'conflicting_results'
      : status === 'not_tested' ? (report.probes.find(probe => probe.hypothesisId === hypothesis.id)?.reason ?? 'no_probe')
        : rows.find(row => row.reason)?.reason;
    hypothesis.status = status;
    return { id: `finding:${hypothesis.id}`, hypothesisId: hypothesis.id,
      category: hypothesis.category, asset: hypothesis.asset, status, evidenceIds,
      rationale: hypothesis.rationale, ...(reason ? { reason } : {}) };
  });
  const statuses = report.findings.map(item => item.status);
  report.coverage = { totalHypotheses: statuses.length,
    confirmed: statuses.filter(value => value === 'confirmed').length,
    notReproduced: statuses.filter(value => value === 'not_reproduced').length,
    inconclusive: statuses.filter(value => value === 'inconclusive').length,
    notTested: statuses.filter(value => value === 'not_tested').length };
}

function aborted(signal) { if (signal?.aborted) throw Object.assign(new Error('Aborted'), { name: 'AbortError' }); }

/** General assessment core. All network and target actions enter through mandatory ports. */
async function runGeneralAssessment({ target, observer, planner, policy, executor, verifier,
  availableTools, limits, signal, onEvent } = {}) {
  assertPort(observer, 'observe', 'observer');
  assertPort(planner, 'propose', 'planner');
  assertPort(policy, 'authorize', 'policy');
  assertPort(executor, 'execute', 'executor');
  assertPort(verifier, 'verify', 'verifier');
  if (onEvent !== undefined && typeof onEvent !== 'function') throw new TypeError('onEvent must be a function');
  if (!Array.isArray(availableTools) || !availableTools.length || availableTools.length > 32
    || availableTools.some(tool => typeof tool !== 'string' || !ID.test(tool))
    || new Set(availableTools).size !== availableTools.length) throw fault('INVALID_AVAILABLE_TOOLS');
  const safeTarget = redactSensitive(jsonValue(target, 'target', 4096));
  if (!record(safeTarget)) throw fault('INVALID_TARGET');
  const budgetLimits = limitsFor(limits);
  const report = { schemaVersion: SCHEMA_VERSION, assessmentMode: 'general', runId: `general-${randomUUID()}`,
    status: 'running', target: redactSensitive(safeTarget), inventory: {}, evidence: [], hypotheses: [], probes: [],
    rejectedProposals: [], partial: false,
    findings: [], coverage: { totalHypotheses: 0, confirmed: 0, notReproduced: 0, inconclusive: 0, notTested: 0 },
    modelCalls: [], iterations: 0, budget: { ...budgetLimits, usedProbes: 0 }, stopReason: null };
  const evidenceById = new Map();
  const hypothesisById = new Map();
  const probeIds = new Set();
  const verdicts = new Map();
  let usedProbes = 0;
  let retriedInvalidOnlyPlan = false;
  const emit = async event => {
    if (!onEvent) return;
    const statuses = report.probes.map(probe => probe.status);
    // Progress counts describe probes, not final findings. No response bodies or
    // model text enter this event contract.
    const progress = {
      hypothesisCount: report.hypotheses.length,
      probeCount: report.probes.length,
      evidenceCount: report.evidence.length,
      confirmedProbeCount: statuses.filter(status => status === 'confirmed').length,
      notReproducedProbeCount: statuses.filter(status => status === 'not_reproduced').length,
      inconclusiveProbeCount: statuses.filter(status => status === 'inconclusive').length,
      blockedProbeCount: statuses.filter(status => status === 'blocked').length,
      remainingProbeBudget: budgetLimits.maxProbes - usedProbes,
    };
    await onEvent({ runId: report.runId, iteration: report.iterations, ...event, progress });
  };

  try {
    for (let iteration = 1; iteration <= budgetLimits.maxIterations; iteration += 1) {
      aborted(signal);
      if (usedProbes >= budgetLimits.maxProbes) { report.stopReason = 'probe_budget'; break; }
      report.iterations = iteration;
      const observed = await observer.observe({ target: safeTarget, iteration,
        evidence: [...report.evidence], signal });
      aborted(signal);
      if (!record(observed)) throw fault('INVALID_OBSERVATION');
      if (observed.inventory !== undefined) report.inventory = redactSensitive(jsonValue(observed.inventory, 'inventory', 64 * 1024));
      const observationEvidence = normalizeEvidence(observed.evidence ?? [], evidenceById,
        budgetLimits.maxEvidenceItems - report.evidence.length, 'observation_evidence');
      for (const item of observationEvidence) { evidenceById.set(item.id, item); report.evidence.push(item); }
      await emit({ stage: 'observe', iteration, evidenceIds: observationEvidence.map(item => item.id),
        evidenceSummaries: observationEvidence.map(item => ({ id: item.id, kind: item.kind,
          ...(item.asset ? { asset: eventAsset(item.asset) } : {}) })) });

      const budget = { maxIterations: budgetLimits.maxIterations, maxProbes: budgetLimits.maxProbes,
        remainingProbes: budgetLimits.maxProbes - usedProbes, usedProbes };
      let plan;
      try {
        plan = await planner.propose({ inventory: report.inventory, evidence: [...report.evidence],
          hypotheses: [...report.hypotheses], usedProbeIds: [...probeIds], iteration, budget,
          availableTools: [...availableTools], signal });
      } catch (error) {
        if (error?.code === 'GENERAL_PLANNER_SCHEMA_ERROR'
          && report.findings.some(item => item.status === 'confirmed' || item.status === 'not_reproduced')) {
          report.rejectedProposals.push({ iteration, reason: 'invalid_model_plan' });
          report.stopReason = 'invalid_model_plan';
          report.partial = true;
          await emit({ stage: 'plan_rejected', iteration, status: 'invalid_model_plan' });
          break;
        }
        throw error;
      }
      aborted(signal);
      if (!record(plan) || (plan.done !== undefined && typeof plan.done !== 'boolean')) throw fault('INVALID_PLAN');
      const attempts = plan.modelAttempts === undefined ? [plan.modelMetadata]
        : Array.isArray(plan.modelAttempts) && plan.modelAttempts.length >= 1
          && plan.modelAttempts.length <= 2 ? plan.modelAttempts : null;
      if (!attempts) throw fault('INVALID_PLAN');
      for (const item of attempts) {
        const metadata = modelMetadata(item, iteration);
        if (metadata) report.modelCalls.push(metadata);
      }
      const newHypotheses = normalizeHypotheses(plan.hypotheses ?? [], hypothesisById, evidenceById);
      if (report.hypotheses.length + newHypotheses.length > 128) throw fault('HYPOTHESIS_BUDGET_EXCEEDED');
      for (const item of newHypotheses) { hypothesisById.set(item.id, item); report.hypotheses.push(item); }
      const probes = normalizeProbes(plan.probes ?? [], probeIds, hypothesisById,
        availableTools, budgetLimits.maxProbes - usedProbes);
      const rejectedProbes = normalizeRejectedProbes(plan.rejectedProbes ?? [], iteration);
      report.rejectedProposals.push(...rejectedProbes);
      if (rejectedProbes.length) report.partial = true;
      await emit({ stage: 'plan', iteration, hypothesisIds: newHypotheses.map(item => item.id),
        hypothesisSummaries: newHypotheses.map(item => ({ id: item.id,
          category: item.category, asset: eventAsset(item.asset) })),
        probeIds: probes.map(item => item.id),
        probeLinks: probes.map(item => ({ probeId: item.id, hypothesisId: item.hypothesisId,
          tool: item.tool })), done: plan.done === true });
      if (rejectedProbes.length) await emit({ stage: 'plan_rejected', iteration,
        status: 'invalid_model_proposal', rejectedCount: rejectedProbes.length });
      if (plan.done === true && probes.length) throw fault('INVALID_PLAN');
      if (plan.done === true) { report.stopReason = 'planner_done'; break; }
      if (rejectedProbes.length && !probes.length) {
        // A new hypothesis can be retried once with its exact ID in the next
        // model context. Rejected probes never enter policy or execution.
        if (newHypotheses.length && !retriedInvalidOnlyPlan && iteration < budgetLimits.maxIterations) {
          retriedInvalidOnlyPlan = true;
          buildFindings(report, verdicts);
          continue;
        }
        report.stopReason = 'invalid_model_proposal'; report.partial = true; break;
      }
      if (!newHypotheses.length && !probes.length && !observationEvidence.length) {
        report.stopReason = 'no_progress'; break;
      }
      for (const probe of probes) {
        aborted(signal);
        probeIds.add(probe.id);
        usedProbes += 1;
        report.budget.usedProbes = usedProbes;
        const row = { id: probe.id, hypothesisId: probe.hypothesisId, tool: probe.tool,
          status: 'pending', evidenceIds: [] };
        report.probes.push(row);
        const hypothesis = hypothesisById.get(probe.hypothesisId);
        const decision = await policy.authorize({ probe,
          hypothesis: { id: hypothesis.id, category: hypothesis.category, asset: hypothesis.asset,
            status: hypothesis.status }, target: safeTarget, inventory: report.inventory,
          budget: { ...budget, remainingProbes: budgetLimits.maxProbes - usedProbes, usedProbes }, signal });
        aborted(signal);
        if (!record(decision) || typeof decision.allowed !== 'boolean') throw fault('INVALID_POLICY_DECISION');
        if (!decision.allowed) {
          row.status = 'blocked'; row.reason = typeof decision.reason === 'string' && ID.test(decision.reason)
            ? decision.reason : 'policy_denied';
          await emit({ stage: 'policy', iteration, hypothesisId: probe.hypothesisId,
            probeId: probe.id, tool: probe.tool, status: 'blocked', reason: row.reason });
          continue;
        }
        await emit({ stage: 'policy', iteration, hypothesisId: probe.hypothesisId,
          probeId: probe.id, tool: probe.tool, status: 'allowed' });
        const execution = await executor.execute({ probe, target: safeTarget, signal });
        aborted(signal);
        if (!record(execution)) throw fault('INVALID_EXECUTION');
        jsonValue(execution, 'execution', 64 * 1024);
        const newEvidence = normalizeEvidence(execution.evidence ?? [], evidenceById,
          budgetLimits.maxEvidenceItems - report.evidence.length, 'probe_evidence');
        for (const item of newEvidence) { evidenceById.set(item.id, item); report.evidence.push(item); }
        row.evidenceIds = newEvidence.map(item => item.id);
        await emit({ stage: 'execute', iteration, hypothesisId: probe.hypothesisId,
          probeId: probe.id, tool: probe.tool, status: 'completed',
          evidenceIds: [...row.evidenceIds],
          evidenceSummaries: newEvidence.map(item => ({ id: item.id, kind: item.kind,
            ...(item.asset ? { asset: eventAsset(item.asset) } : {}) })) });
        if (!newEvidence.length) {
          row.status = 'inconclusive'; row.reason = 'no_evidence';
          verdicts.set(probe.hypothesisId, [...(verdicts.get(probe.hypothesisId) ?? []),
            { status: 'inconclusive', evidenceIds: [], reason: 'no_evidence' }]);
          await emit({ stage: 'verify', iteration, hypothesisId: probe.hypothesisId,
            probeId: probe.id, tool: probe.tool, status: 'inconclusive',
            reason: 'no_evidence', evidenceIds: [] });
          continue;
        }
        const result = await verifier.verify({ hypothesis: hypothesisById.get(probe.hypothesisId),
          probe, execution, evidence: [...report.evidence], signal });
        aborted(signal);
        if (!record(result) || !VERDICTS.has(result.status)) throw fault('INVALID_VERDICT');
        const refs = evidenceRefs(result.evidenceIds ?? [], evidenceById, 'verdict_evidence');
        if (result.status !== 'inconclusive'
          && (result.completed !== true || !refs.some(id => row.evidenceIds.includes(id)))) {
          throw fault('UNSUPPORTED_VERDICT');
        }
        row.status = result.status;
        const verdict = { status: result.status, evidenceIds: refs };
        if (result.reason !== undefined) verdict.reason = boundedString(result.reason, 'verdict_reason', 512);
        verdicts.set(probe.hypothesisId, [...(verdicts.get(probe.hypothesisId) ?? []), verdict]);
        await emit({ stage: 'verify', iteration, hypothesisId: probe.hypothesisId,
          probeId: probe.id, tool: probe.tool, status: result.status,
          ...(verdict.reason ? { reason: verdict.reason } : {}), evidenceIds: refs });
      }
      // The next model step needs the preceding verification state, not only
      // the original hypothesis text and newly collected evidence.
      buildFindings(report, verdicts);
      if (iteration === budgetLimits.maxIterations) report.stopReason = 'iteration_budget';
    }
    if (!report.stopReason) report.stopReason = 'iteration_budget';
    report.status = 'completed';
  } catch (error) {
    report.status = signal?.aborted || error?.name === 'AbortError' ? 'cancelled' : 'failed';
    report.stopReason = report.status === 'cancelled' ? 'cancelled' : 'failure';
    if (report.status === 'failed') report.error = { code: typeof error?.code === 'string' && ID.test(error.code)
      ? error.code : 'GENERAL_ASSESSMENT_FAILED' };
  }
  buildFindings(report, verdicts);
  try {
    await emit({ stage: 'complete', status: report.status, stopReason: report.stopReason,
      coverage: { ...report.coverage } });
  } catch {
    report.status = 'failed'; report.stopReason = 'failure'; report.error = { code: 'EVENT_SINK_FAILED' };
  }
  return { report };
}

module.exports = { SCHEMA_VERSION, runGeneralAssessment };
