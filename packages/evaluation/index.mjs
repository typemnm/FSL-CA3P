import { digest } from '../contracts/index.mjs';

export const NORMALIZATION_VERSION = '1.0';
export const CONTRACT_DEPENDENCIES = Object.freeze({ agent: ['xss-parser', 'attack-module', 'guardrail', 'casper-db', 'pentest-db'],
  'casper-db': ['xss-parser'], 'attack-module': ['guardrail'] });
export function affectedModules(changed) {
  const affected = new Set(changed); let expanded = true;
  while (expanded) {
    expanded = false;
    for (const [consumer, producers] of Object.entries(CONTRACT_DEPENDENCIES)) {
      if (!affected.has(consumer) && producers.some(name => affected.has(name))) { affected.add(consumer); expanded = true; }
    }
  }
  return [...affected].sort();
}
const VOLATILE_FIELDS = new Set(['timestamp', 'time', 'startedAt', 'completedAt', 'createdAt', 'recordedAt',
  'storedAt', 'observedAt', 'elapsedMs', 'latency', 'latencyMs', 'messageId', 'correlationId', 'evidenceId',
  'runId', 'coreRunId', 'findingId', 'sequence', 'artifactRef']);

/** Used only for diff. Original origins, marker binding and evidence are untouched. */
export function normalizeForComparison(value, { markers = [] } = {}) {
  if (Array.isArray(value)) return value.map(item => normalizeForComparison(item, { markers }));
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .filter(key => !VOLATILE_FIELDS.has(key))
    .map(key => [key, normalizeForComparison(value[key], { markers })]));
  if (typeof value !== 'string') return value;
  let result = value.replace(/https?:\/\/127\.0\.0\.1:\d+/gu, 'http://127.0.0.1:<port>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/giu, '<uuid>');
  for (const marker of markers.filter(item => typeof item === 'string' && item)) result = result.split(marker).join('<marker>');
  return result;
}

function changes(a, b, path = '', result = []) {
  if (JSON.stringify(a) === JSON.stringify(b)) return result;
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) changes(a[key], b[key], `${path}/${key}`, result);
  } else result.push({ path: path || '/', before: a ?? null, after: b ?? null });
  return result;
}
function metrics(run) {
  const calls = run.modelCalls ?? [];
  const validCalls = calls.filter(call => call.status === 'completed' || call.status === 'success');
  return { elapsedMs: run.elapsedMs ?? null, events: run.events?.length ?? 0,
    finding: run.report?.finding?.status ?? null, modelCalls: calls.length,
    promptTokens: calls.reduce((sum, item) => sum + (item.usage?.prompt_tokens ?? 0), 0),
    completionTokens: calls.reduce((sum, item) => sum + (item.usage?.completion_tokens ?? 0), 0),
    tokenUsageAvailable: calls.length > 0 && calls.every(item => item.usage != null),
    successfulModelCalls: validCalls.length, estimatedCost: null };
}
export function compareRunRecords(base, candidate, { kind = 'code' } = {}) {
  if (!base || !candidate) throw Object.assign(new Error('Both runs must exist.'), { status: 404 });
  if (!['code', 'model', 'prompt', 'environment'].includes(kind)) throw Object.assign(new Error('Invalid comparison kind.'), { status: 400 });
  const conditions = [];
  const inspect = (name, a, b) => conditions.push({ name, before: a ?? null, after: b ?? null,
    equal: a !== null && a !== undefined && b !== null && b !== undefined && JSON.stringify(a) === JSON.stringify(b),
    available: a !== null && a !== undefined && b !== null && b !== undefined });
  inspect('mode', base.mode, candidate.mode);
  inspect('logicalInput', base.manifest?.data?.logicalInputDigest, candidate.manifest?.data?.logicalInputDigest);
  inspect('dataset', base.manifest?.data?.datasetDigest, candidate.manifest?.data?.datasetDigest);
  inspect('catalog', base.manifest?.data?.catalogDigest, candidate.manifest?.data?.catalogDigest);
  inspect('caseSnapshot', base.manifest?.data?.caseSnapshotDigest, candidate.manifest?.data?.caseSnapshotDigest);
  inspect('initialState', base.manifest?.target?.initialStateDigest, candidate.manifest?.target?.initialStateDigest);
  inspect('policy', base.manifest?.policy?.rulesetDigest, candidate.manifest?.policy?.rulesetDigest);
  inspect('contracts', base.manifest?.shared?.contractDigest, candidate.manifest?.shared?.contractDigest);
  if (kind !== 'environment') {
    for (const name of ['nodeVersion', 'pythonVersion', 'browserVersion', 'playwrightVersion']) {
      inspect(name, base.manifest?.environment?.[name], candidate.manifest?.environment?.[name]);
    }
  }
  if (kind !== 'model') inspect('model', base.manifest?.model?.id, candidate.manifest?.model?.id);
  if (kind !== 'model') inspect('modelSettings', base.manifest?.model?.settings, candidate.manifest?.model?.settings);
  if (kind !== 'model' && ((base.modelCalls?.length ?? 0) > 0 || (candidate.modelCalls?.length ?? 0) > 0)) {
    inspect('actualRequestSettings', (base.modelCalls ?? []).map(call => call.requestSettings), (candidate.modelCalls ?? []).map(call => call.requestSettings));
    inspect('reportedModel', base.modelCalls?.[0]?.reportedModel, candidate.modelCalls?.[0]?.reportedModel);
  }
  if (kind !== 'code') {
    inspect('source', base.manifest?.source?.commitSha, candidate.manifest?.source?.commitSha);
    inspect('moduleContent', base.manifest?.modules, candidate.manifest?.modules);
    inspect('sharedLock', base.manifest?.shared?.lockDigest, candidate.manifest?.shared?.lockDigest);
  }
  if (kind !== 'prompt') inspect('promptTemplate', base.manifest?.model?.promptTemplateDigest, candidate.manifest?.model?.promptTemplateDigest);
  const changedModules = [];
  for (const name of new Set([...Object.keys(base.manifest?.modules ?? {}), ...Object.keys(candidate.manifest?.modules ?? {})])) {
    if (base.manifest?.modules?.[name]?.contentDigest !== candidate.manifest?.modules?.[name]?.contentDigest) changedModules.push(name);
  }
  const markers = [];
  function collectMarkers(value) {
    if (!value || typeof value !== 'object') return;
    for (const [key, item] of Object.entries(value)) {
      if (key === 'marker' && typeof item === 'string' && /^[a-f0-9]{32}$/u.test(item)) markers.push(item);
      else collectMarkers(item);
    }
  }
  collectMarkers(base); collectMarkers(candidate);
  const before = normalizeForComparison(base.report, { markers });
  const after = normalizeForComparison(candidate.report, { markers });
  const moduleNames = new Set([...(base.events ?? []).map(event => event.module), ...(candidate.events ?? []).map(event => event.module)]);
  const moduleDiffs = [...moduleNames].map(module => {
    const pick = run => normalizeForComparison((run.events ?? []).filter(event => event.module === module)
      .map(event => ({ stage: event.stage, request: event.request, response: event.response })), { markers });
    return { module, changes: changes(pick(base), pick(candidate)) };
  });
  return { id: digest({ baseline: base.id, candidate: candidate.id, kind, normalization: NORMALIZATION_VERSION }),
    baselineRunId: base.id, candidateRunId: candidate.id, kind, normalizationVersion: NORMALIZATION_VERSION,
    comparable: conditions.every(item => item.equal) && !base.provenanceIncomplete && !candidate.provenanceIncomplete,
    conditions, changedModules,
    affectedModules: affectedModules(changedModules),
    promptDigests: { before: (base.modelCalls ?? []).map(item => item.promptDigest), after: (candidate.modelCalls ?? []).map(item => item.promptDigest) },
    rawEvidencePreserved: true, causalAttribution: 'not-established',
    metrics: { baseline: metrics(base), candidate: metrics(candidate) },
    findingTransition: { before: base.report?.finding?.status ?? 'unavailable', after: candidate.report?.finding?.status ?? 'unavailable' },
    changes: changes(before, after), moduleDiffs };
}

export function evaluateCases(cases) {
  let truePositives = 0, falsePositives = 0, falseNegatives = 0, inconclusive = 0, positives = 0, decidable = 0;
  for (const item of cases) {
    if (item.vulnerable) positives += 1;
    if (!['confirmed', 'not_reproduced'].includes(item.result)) { inconclusive += 1; continue; }
    decidable += 1;
    if (item.result === 'confirmed') { if (item.vulnerable) truePositives += 1; else falsePositives += 1; }
    else if (item.vulnerable) falseNegatives += 1;
  }
  return { cases: cases.length, truePositives, falsePositives, falseNegatives, inconclusive,
    precision: truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : null,
    endToEndRecall: positives ? truePositives / positives : null,
    conditionalRecall: truePositives + falseNegatives ? truePositives / (truePositives + falseNegatives) : null,
    coverage: cases.length ? decidable / cases.length : null, inconclusiveRate: cases.length ? inconclusive / cases.length : null };
}
