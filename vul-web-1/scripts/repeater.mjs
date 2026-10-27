import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import attackModule from '../../attack-module/index.js';
import guardrailPackage from '../../guardrail/src/index.js';

const { executeCurl } = attackModule;
const { GuardrailEvaluator } = guardrailPackage;

const PROFILE_ID = 'request_tamper_repeater';
const DEFAULT_ORIGIN = 'http://127.0.0.1:3000';
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

function normalizeRequest(request) {
  if (!request || typeof request.method !== 'string' || typeof request.path !== 'string') {
    throw new Error('repeater case request is missing method or path.');
  }
  const query = (request.query && typeof request.query === 'object') ? request.query : {};
  const keys = Object.keys(query);
  const path = keys.length ? `${request.path}?${keys.map(key => `${key}=${query[key]}`).join('&')}` : request.path;
  return { method: request.method, path, query };
}

export function loadPlan(catalogPath = DEFAULT_CATALOG, vulnType = 'idor') {
  const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
  const response = selectResponse(catalog, vulnType);
  const payload = response?.payloads?.find(item => item?.successCheck?.expect?.observe === 'httpResponse');
  const expect = payload?.successCheck?.expect;
  if (!response || !payload || !expect || !expect.baseline || !expect.attack) {
    throw new Error(`catalog has no request-tampering (httpResponse) case for vulnType "${vulnType}".`);
  }
  const control = normalizeRequest(expect.baseline.request);
  const tamper = normalizeRequest(expect.attack.request);
  const parameter = payload.injectionPoint?.parameter;
  const stages = {
    control: { method: control.method, path: control.path, expectStatus: expect.baseline.status, actor: control.query[parameter] ?? null },
    tamper: { method: tamper.method, path: tamper.path, expectStatus: expect.attack.status, actor: tamper.query[parameter] ?? null },
  };
  let resourceRemoved = null;
  let verifyStatus = null;
  if (expect.resourceRemoved && typeof expect.resourceRemoved.check === 'string') {
    const [method, path] = expect.resourceRemoved.check.trim().split(/\s+/u);
    if (!method || !path) throw new Error('resourceRemoved.check must be "METHOD /path".');
    stages.verify = { method, path };
    resourceRemoved = { postId: expect.resourceRemoved.postId };
  } else if (expect.verify && expect.verify.request && Number.isInteger(expect.verify.status)) {
    const verifyRequest = normalizeRequest(expect.verify.request);
    stages.verify = { method: verifyRequest.method, path: verifyRequest.path };
    verifyStatus = expect.verify.status;
  }
  return {
    vulnType, cwe: response.cwe ?? null, application: response.target?.application ?? 'target',
    parameter, resourceRemoved, verifyStatus, stages,
  };
}

export function createRuleset({ origin, plan }) {
  const allowedOrigin = exactLoopbackOrigin(origin);
  const seen = new Set();
  const endpointCatalog = [];
  for (const [stage, spec] of Object.entries(plan.stages)) {
    const base = spec.path.split('?')[0];
    const pattern = `^${escapeRegex(base)}(\\?.*)?$`;
    const key = `${spec.method} ${pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpointCatalog.push({ id: stage.toUpperCase(), method: spec.method, pathPattern: pattern, queryKeys: [], bodyKeys: [] });
  }
  return {
    schemaVersion: '1.0.0',
    rulesetId: `repeater-${plan.application}-${plan.vulnType}`,
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
        externalRequests: 'DENY', maximumHttpRequests: 3,
        maximumMutations: 2, maximumIterations: 1,
      },
      stageRules: Object.entries(plan.stages).map(([stage, spec]) => ({
        stage, decision: 'ALLOW', exactAction: {
          operation: 'http_request', session: 'attacker', method: spec.method, path: spec.path,
        },
      })),
    } },
  };
}

export class RepeaterDeniedError extends Error {
  constructor(ruleId) {
    super(`repeater denied by ${ruleId}.`);
    this.name = 'RepeaterDeniedError';
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
    if (!spec || usedStages.has(stage)) throw new RepeaterDeniedError('STAGE-UNAVAILABLE');
    const action = { operation: 'http_request', session: 'attacker', method: spec.method, path: spec.path };
    const decision = evaluator.evaluate({
      stage, action,
      trustedContext: {
        targetMode: 'isolated_local_lab', targetOrigin: allowedOrigin,
        testProfile: PROFILE_ID, runId, iteration: 1,
        networkPolicy: { externalRequests: 'DENY' }, budget: { ...budget },
      },
    });
    if (decision.decision !== 'ALLOW') throw new RepeaterDeniedError(decision.ruleId);
    usedStages.add(stage);
    budget.requestCount += 1;
    if (['POST', 'DELETE'].includes(spec.method)) {
      budget.mutationCount += 1;
      if (spec.method === 'DELETE') budget.deleteCount += 1;
    }
    return curlImpl({ method: spec.method, url: `${allowedOrigin}${spec.path}` }, { allowedOrigin, signal });
  };
}

function statusOf(response) {
  return Number.isInteger(response?.status) ? response.status : null;
}

function findingStatus(plan, evidence) {
  const { control, tamper, verify } = evidence;
  if (control.status !== plan.stages.control.expectStatus) return 'inconclusive';
  if (plan.verifyStatus !== null && plan.verifyStatus !== undefined) {
    if (verify?.status === plan.verifyStatus) return 'confirmed';
    if (Number.isInteger(verify?.status)) return 'not_confirmed';
    return 'inconclusive';
  }
  if (tamper.status === plan.stages.tamper.expectStatus) {
    if (!plan.resourceRemoved) return 'confirmed';
    return verify?.removed === true ? 'confirmed' : 'inconclusive';
  }
  if ([403, 404].includes(tamper.status)) return 'not_confirmed';
  return 'inconclusive';
}

export async function run({ origin, catalogPath = DEFAULT_CATALOG, vulnType = 'idor', curlImpl = executeCurl, signal } = {}) {
  const allowedOrigin = exactLoopbackOrigin(origin ?? DEFAULT_ORIGIN);
  const plan = loadPlan(catalogPath, vulnType);
  const runId = `repeater-${vulnType}-${randomUUID()}`;
  const startedAt = new Date().toISOString();
  const request = createGuardedRequest({ origin: allowedOrigin, runId, plan, curlImpl });

  const controlResponse = await request('control', { signal });
  const tamperResponse = await request('tamper', { signal });
  const evidence = {
    control: { check: 'control', [plan.parameter]: plan.stages.control.actor, status: statusOf(controlResponse) },
    tamper: { check: 'tamper', [plan.parameter]: plan.stages.tamper.actor, status: statusOf(tamperResponse) },
  };
  if (plan.stages.verify) {
    const verifyResponse = await request('verify', { signal });
    if (plan.resourceRemoved) {
      const posts = Array.isArray(verifyResponse?.bodyJson?.posts) ? verifyResponse.bodyJson.posts : null;
      const removed = posts ? !posts.some(item => item && item.id === plan.resourceRemoved.postId) : null;
      evidence.verify = { check: 'verify', targetId: plan.resourceRemoved.postId, removed };
    } else {
      evidence.verify = { check: 'verify', status: statusOf(verifyResponse), expectedStatus: plan.verifyStatus };
    }
  }

  return {
    schemaVersion: '1.0', runId, vulnType, fixtureId: plan.application,
    testProfile: PROFILE_ID, startedAt, completedAt: new Date().toISOString(),
    targetContacted: true, simulated: false,
    finding: { category: plan.cwe, status: findingStatus(plan, evidence) },
    evidence: Object.values(evidence),
    provenance: {
      tool: 'repeater', guardrail: 'guardrail/GuardrailEvaluator', attack: 'attack-module/executeCurl',
      catalog: 'pentest-db/cases.multi.draft.json',
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const vulnType = process.argv[2] ?? 'idor';
    const origin = process.env.REPEATER_ORIGIN ?? process.env.VULWEB1_ORIGIN;
    if (!origin) throw new Error('REPEATER_ORIGIN_REQUIRED');
    const report = await run({ origin, vulnType });
    console.log(JSON.stringify(report, null, 2));
    if (report.finding.status !== 'confirmed') process.exitCode = 1;
  } catch (error) {
    const reason = error instanceof RepeaterDeniedError ? error.ruleId : (error.message || 'NETWORK_OR_RUNTIME_ERROR');
    console.error(JSON.stringify({ error: 'REPEATER_FAILED', reason }));
    process.exitCode = 1;
  }
}
