import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import attackModule from '../../attack-module/index.js';
import guardrailPackage from '../../guardrail/src/index.js';

const { executeCurl } = attackModule;
const { GuardrailEvaluator } = guardrailPackage;

const PROFILE_ID = 'payload_fuzz_intruder';
const DEFAULT_ORIGIN = 'http://127.0.0.1:4101';
const DEFAULT_CATALOG = fileURLToPath(new URL('../../pentest-db/cases.multi.draft.json', import.meta.url));

function exactLoopbackOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError('An exact loopback HTTP origin is required.'); }
  if (typeof value !== 'string' || value !== url.origin || url.protocol !== 'http:'
    || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('An exact 127.0.0.1 HTTP origin with a port is required.');
  }
  return value;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function selectResponse(catalog, vulnType) {
  if (Array.isArray(catalog.responses)) return catalog.responses.find(item => item && item.vulnType === vulnType) ?? null;
  if (catalog.response && catalog.response.vulnType === vulnType) return catalog.response;
  return null;
}

function buildPath(request) {
  if (!request || typeof request.method !== 'string' || typeof request.path !== 'string') {
    throw new Error('intruder case request is missing method or path.');
  }
  const query = (request.query && typeof request.query === 'object') ? request.query : {};
  const keys = Object.keys(query);
  const path = keys.length
    ? `${request.path}?${keys.map(key => `${encodeURIComponent(key)}=${encodeURIComponent(query[key])}`).join('&')}`
    : request.path;
  return { method: request.method, path };
}

export function loadIntruderPlan(catalogPath = DEFAULT_CATALOG, vulnType = 'sql_injection') {
  const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
  const response = selectResponse(catalog, vulnType);
  const fuzzable = (response?.payloads ?? []).filter(item =>
    item?.successCheck?.expect?.observe === 'httpResponse' && item.successCheck.expect.attack);
  const first = fuzzable[0];
  const baselineSpec = first?.successCheck?.expect?.baseline;
  if (!response || fuzzable.length === 0 || !baselineSpec || !baselineSpec.request) {
    throw new Error(`catalog has no fuzzable (httpResponse) payloads for vulnType "${vulnType}".`);
  }
  const baselineRequest = buildPath(baselineSpec.request);
  const stages = { baseline: { method: baselineRequest.method, path: baselineRequest.path } };
  const shots = fuzzable.map((item, index) => {
    const attack = item.successCheck.expect.attack;
    const request = buildPath(attack.request);
    const stage = `shot_${index}`;
    stages[stage] = { method: request.method, path: request.path };
    return {
      stage,
      payloadId: item.payloadId,
      value: item.value,
      resultField: item.successCheck.resultField ?? 'results',
      expectStatus: Number.isInteger(attack.status) ? attack.status : null,
      resultCountMin: Number.isInteger(attack.resultCountMin) ? attack.resultCountMin : null,
      containsFields: Array.isArray(attack.containsFields) ? attack.containsFields : null,
    };
  });
  return {
    vulnType,
    cwe: response.cwe ?? null,
    application: response.target?.application ?? 'target',
    parameter: first.injectionPoint?.parameter ?? null,
    baseline: {
      resultField: first.successCheck.resultField ?? 'results',
      resultCount: Number.isInteger(baselineSpec.resultCount) ? baselineSpec.resultCount : 0,
    },
    shots,
    stages,
  };
}

export function createRuleset({ origin, plan }) {
  const allowedOrigin = exactLoopbackOrigin(origin);
  const seen = new Set();
  const endpointCatalog = [];
  let mutations = 0;
  for (const spec of Object.values(plan.stages)) {
    if (['POST', 'DELETE'].includes(spec.method)) mutations += 1;
    const base = spec.path.split('?')[0];
    const pattern = `^${escapeRegex(base)}(\\?.*)?$`;
    const key = `${spec.method} ${pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpointCatalog.push({ id: `EP_${endpointCatalog.length}`, method: spec.method, pathPattern: pattern, queryKeys: [], bodyKeys: [] });
  }
  const totalRequests = Object.keys(plan.stages).length;
  return {
    schemaVersion: '1.0.0',
    rulesetId: `intruder-${plan.application}-${plan.vulnType}`,
    targetApplication: plan.application,
    engine: { defaultDecision: 'DENY', failureMode: 'closed' },
    inputContract: {
      required: ['stage', 'action', 'trustedContext'],
      actionSchemas: { http_request: {
        required: ['operation', 'session', 'method', 'path'],
        allowedFields: ['operation', 'session', 'method', 'path'],
      } },
      trustedContext: {
        required: ['targetMode', 'targetOrigin', 'testProfile', 'runId', 'iteration', 'networkPolicy', 'budget'],
      },
    },
    endpointCatalog,
    hardDenyRules: [
      { id: 'SCOPE-ORIGIN', reason: 'The run origin changed.',
        when: { field: 'trustedContext.targetOrigin', operator: 'not_equals', value: allowedOrigin } },
      { id: 'SCOPE-MODE', reason: 'Only the isolated lab mode is allowed.',
        when: { field: 'trustedContext.targetMode', operator: 'not_equals', value: 'isolated_local_lab' } },
      { id: 'SCOPE-NETWORK', reason: 'External requests are forbidden.',
        when: { field: 'trustedContext.networkPolicy.externalRequests', operator: 'not_equals', value: 'DENY' } },
      { id: 'REQUEST-BUDGET', reason: 'The request budget is exhausted.',
        when: { operator: 'budget_exceeded' } },
    ],
    profiles: { [PROFILE_ID]: {
      trustedContextRequirements: {
        externalRequests: 'DENY',
        maximumHttpRequests: totalRequests,
        maximumMutations: mutations,
        maximumIterations: 1,
      },
      stageRules: Object.entries(plan.stages).map(([stage, spec]) => ({
        stage, decision: 'ALLOW', exactAction: {
          operation: 'http_request', session: 'attacker', method: spec.method, path: spec.path,
        },
      })),
    } },
  };
}

export class IntruderDeniedError extends Error {
  constructor(ruleId) {
    super(`intruder denied by ${ruleId}.`);
    this.name = 'IntruderDeniedError';
    this.code = 'GUARDRAIL_DENIED';
    this.ruleId = ruleId;
  }
}

export function createGuardedRequest({ origin, runId, plan, curlImpl = executeCurl }) {
  const allowedOrigin = exactLoopbackOrigin(origin);
  if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(runId)) {
    throw new TypeError('A safe runId is required.');
  }
  if (typeof curlImpl !== 'function') throw new TypeError('curlImpl must be a function.');
  const evaluator = new GuardrailEvaluator(createRuleset({ origin: allowedOrigin, plan }));
  const usedStages = new Set();
  const budget = { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 };

  return async function guardedRequest(stage, { signal } = {}) {
    const spec = plan.stages[stage];
    if (!spec || usedStages.has(stage)) throw new IntruderDeniedError('STAGE-UNAVAILABLE');
    const action = { operation: 'http_request', session: 'attacker', method: spec.method, path: spec.path };
    const decision = evaluator.evaluate({
      stage, action,
      trustedContext: {
        targetMode: 'isolated_local_lab', targetOrigin: allowedOrigin,
        testProfile: PROFILE_ID, runId, iteration: 1,
        networkPolicy: { externalRequests: 'DENY' }, budget: { ...budget },
      },
    });
    if (decision.decision !== 'ALLOW') throw new IntruderDeniedError(decision.ruleId);
    usedStages.add(stage);
    budget.requestCount += 1;
    if (['POST', 'DELETE'].includes(spec.method)) {
      budget.mutationCount += 1;
      if (spec.method === 'DELETE') budget.deleteCount += 1;
    }
    return curlImpl({ method: spec.method, url: `${allowedOrigin}${spec.path}` }, { allowedOrigin, signal });
  };
}

function countField(response, field) {
  const value = response?.bodyJson?.[field];
  return Array.isArray(value) ? value.length : null;
}

export async function run({ origin, catalogPath = DEFAULT_CATALOG, vulnType = 'sql_injection', curlImpl = executeCurl, signal } = {}) {
  const allowedOrigin = exactLoopbackOrigin(origin ?? DEFAULT_ORIGIN);
  const plan = loadIntruderPlan(catalogPath, vulnType);
  const runId = `intruder-${vulnType}-${randomUUID()}`;
  const startedAt = new Date().toISOString();
  const request = createGuardedRequest({ origin: allowedOrigin, runId, plan, curlImpl });

  const baselineResponse = await request('baseline', { signal });
  const baselineCount = countField(baselineResponse, plan.baseline.resultField);
  const baselineOk = baselineCount !== null && baselineCount <= plan.baseline.resultCount;
  const evidence = [{ check: 'baseline', resultCount: baselineCount }];

  const attempts = [];
  for (const shot of plan.shots) {
    const response = await request(shot.stage, { signal });
    const status = Number.isInteger(response?.status) ? response.status : null;
    const resultCount = countField(response, shot.resultField);
    const body = response?.bodyJson;
    let statusHit;
    if (shot.containsFields) {
      statusHit = !!body && typeof body === 'object' && !Array.isArray(body)
        && shot.containsFields.every(field => body[field] !== undefined);
    } else if (shot.resultCountMin !== null) {
      statusHit = resultCount !== null && resultCount >= shot.resultCountMin;
    } else {
      statusHit = shot.expectStatus !== null && status === shot.expectStatus;
    }
    const hit = baselineOk && statusHit;
    attempts.push({ payloadId: shot.payloadId, value: shot.value, status, resultCount, hit });
    evidence.push({ check: shot.payloadId, status, resultCount, hit });
  }

  const hits = attempts.filter(item => item.hit).map(item => item.payloadId);
  let status = 'inconclusive';
  if (baselineOk) status = hits.length > 0 ? 'confirmed' : 'not_confirmed';

  return {
    schemaVersion: '1.0', runId, vulnType, fixtureId: plan.application,
    testProfile: PROFILE_ID, startedAt, completedAt: new Date().toISOString(),
    targetContacted: true, simulated: false,
    finding: { category: plan.cwe, status, parameter: plan.parameter, hits },
    evidence,
    provenance: {
      tool: 'intruder', guardrail: 'guardrail/GuardrailEvaluator', attack: 'attack-module/executeCurl',
      catalog: 'pentest-db/cases.multi.draft.json',
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const vulnType = process.argv[2] ?? 'sql_injection';
    const origin = process.env.INTRUDER_ORIGIN ?? process.env.VULWEB2_ORIGIN;
    if (!origin) throw new Error('INTRUDER_ORIGIN_REQUIRED');
    const report = await run({ origin, vulnType });
    console.log(JSON.stringify(report, null, 2));
    if (report.finding.status !== 'confirmed') process.exitCode = 1;
  } catch (error) {
    const reason = error instanceof IntruderDeniedError ? error.ruleId : (error.message || 'NETWORK_OR_RUNTIME_ERROR');
    console.error(JSON.stringify({ error: 'INTRUDER_FAILED', reason }));
    process.exitCode = 1;
  }
}
