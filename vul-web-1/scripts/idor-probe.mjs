import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import attackModule from '../../attack-module/index.js';
import { lookupAttackInfoSync } from '../../casper-db/client.mjs';
import guardrailPackage from '../../guardrail/src/index.js';

const { executeCurl } = attackModule;
const { GuardrailEvaluator } = guardrailPackage;

const PROFILE_ID = 'client_controlled_delete_idor';
const DEFAULT_ORIGIN = 'http://127.0.0.1:3000';

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

function selectIdorResponse(catalog) {
  if (catalog && Array.isArray(catalog.responses)) {
    return catalog.responses.find(item => item && item.vulnType === 'idor') ?? null;
  }
  if (catalog && catalog.response && catalog.response.vulnType === 'idor') return catalog.response;
  return null;
}

function normalizeRequest(request) {
  if (!request || typeof request.method !== 'string' || typeof request.path !== 'string') {
    throw new Error('IDOR case request is missing method or path.');
  }
  const query = (request.query && typeof request.query === 'object') ? request.query : {};
  const keys = Object.keys(query);
  const path = keys.length ? `${request.path}?${keys.map(key => `${key}=${query[key]}`).join('&')}` : request.path;
  return { method: request.method, path, query };
}

export function loadIdorPlan(catalogPath) {
  // Explicit JSON input is retained for old fixture callers; live defaults use the unified DB.
  const response = catalogPath === undefined
    ? lookupAttackInfoSync({ vulnType: 'idor', target: { application: 'vul-web-1',
      endpoint: 'DELETE /api/posts/:id', parameter: 'authorId' } })
    : selectIdorResponse(JSON.parse(readFileSync(catalogPath, 'utf8')));
  const payload = response?.payloads?.[0];
  const expect = payload?.successCheck?.expect;
  if (!response || !payload || !expect || expect.observe !== 'httpResponse'
    || !expect.baseline || !expect.attack || !expect.resourceRemoved) {
    throw new Error('Catalog has no usable httpResponse IDOR case.');
  }
  const control = normalizeRequest(expect.baseline.request);
  const tamper = normalizeRequest(expect.attack.request);
  const parameter = payload.injectionPoint?.parameter;
  const [verifyMethod, verifyPath] = String(expect.resourceRemoved.check).trim().split(/\s+/u);
  if (!verifyMethod || !verifyPath) throw new Error('resourceRemoved.check must be "METHOD /path".');
  return {
    patternId: response.patternId ?? null,
    patternRevision: response.patternRevision ?? null,
    cwe: response.cwe ?? 'CWE-639',
    parameter,
    targetPostId: expect.resourceRemoved.postId,
    stages: {
      control: { method: control.method, path: control.path, expectStatus: expect.baseline.status, actor: control.query[parameter] ?? null },
      tamper: { method: tamper.method, path: tamper.path, expectStatus: expect.attack.status, actor: tamper.query[parameter] ?? null },
      verify: { method: verifyMethod, path: verifyPath },
    },
  };
}

export function createIdorRuleset({ origin, plan }) {
  const allowedOrigin = exactLoopbackOrigin(origin);
  return {
    schemaVersion: '1.0.0',
    rulesetId: 'vul-web-1-client-controlled-delete-idor',
    targetApplication: 'vul-web-1',
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
    endpointCatalog: [
      { id: 'DELETE_TARGET_POST', method: 'DELETE', pathPattern: '^/api/posts/1(\\?authorId=[A-Za-z0-9_-]+)?$', queryKeys: ['authorId'], bodyKeys: [] },
      { id: 'LIST_POSTS', method: 'GET', pathPattern: '^/api/posts$', queryKeys: [], bodyKeys: [] },
    ],
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

export class ProbeDeniedError extends Error {
  constructor(ruleId) {
    super(`IDOR delete probe denied by ${ruleId}.`);
    this.name = 'ProbeDeniedError';
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
  const evaluator = new GuardrailEvaluator(createIdorRuleset({ origin: allowedOrigin, plan }));
  const usedStages = new Set();
  const budget = { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 };

  return async function guardedRequest(stage, { signal } = {}) {
    const spec = plan.stages[stage];
    if (!spec || usedStages.has(stage)) throw new ProbeDeniedError('STAGE-UNAVAILABLE');
    const action = { operation: 'http_request', session: 'attacker', method: spec.method, path: spec.path };
    const decision = evaluator.evaluate({
      stage, action,
      trustedContext: {
        targetMode: 'isolated_local_lab', targetOrigin: allowedOrigin,
        testProfile: PROFILE_ID, runId, iteration: 1,
        networkPolicy: { externalRequests: 'DENY' }, budget: { ...budget },
      },
    });
    if (decision.decision !== 'ALLOW') throw new ProbeDeniedError(decision.ruleId);
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

function findingStatus(plan, { control, tamper, verify }) {
  if (control.status !== plan.stages.control.expectStatus) return 'inconclusive';
  if (tamper.status === plan.stages.tamper.expectStatus && verify.removed === true) return 'confirmed';
  if ([403, 404].includes(tamper.status)) return 'not_confirmed';
  return 'inconclusive';
}

export async function probe({ origin, catalogPath, curlImpl = executeCurl, signal } = {}) {
  const allowedOrigin = exactLoopbackOrigin(origin ?? DEFAULT_ORIGIN);
  const plan = loadIdorPlan(catalogPath);
  const runId = `idor-delete-${randomUUID()}`;
  const startedAt = new Date().toISOString();
  const request = createGuardedRequest({ origin: allowedOrigin, runId, plan, curlImpl });

  const controlResponse = await request('control', { signal });
  const tamperResponse = await request('tamper', { signal });
  const verifyResponse = await request('verify', { signal });

  const posts = Array.isArray(verifyResponse?.bodyJson?.posts) ? verifyResponse.bodyJson.posts : null;
  const removed = posts ? !posts.some(item => item && item.id === plan.targetPostId) : null;

  const evidence = {
    control: { check: 'control', [plan.parameter]: plan.stages.control.actor, status: statusOf(controlResponse) },
    tamper: { check: 'tamper', [plan.parameter]: plan.stages.tamper.actor, status: statusOf(tamperResponse) },
    verify: { check: 'verify', targetPostId: plan.targetPostId, removed },
  };

  return {
    schemaVersion: '1.0', runId, fixtureId: 'vul-web-1',
    testProfile: PROFILE_ID, startedAt, completedAt: new Date().toISOString(),
    targetContacted: true, simulated: false,
    finding: { category: plan.cwe, status: findingStatus(plan, evidence) },
    evidence: Object.values(evidence),
    provenance: {
      policy: 'vul-web-1-client-controlled-delete-idor',
      guardrail: 'guardrail/GuardrailEvaluator', attack: 'attack-module/executeCurl',
      catalog: catalogPath ?? 'casper-db.attack_catalog',
      patternId: plan.patternId, patternRevision: plan.patternRevision,
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 2) throw new Error('ARGUMENTS_NOT_ALLOWED');
    const origin = process.env.VULWEB1_ORIGIN;
    if (!origin) throw new Error('VULWEB1_ORIGIN_REQUIRED');
    const report = await probe({ origin });
    console.log(JSON.stringify(report, null, 2));
    if (report.finding.status !== 'confirmed') process.exitCode = 1;
  } catch (error) {
    const reason = error instanceof ProbeDeniedError ? error.ruleId : (error.message || 'NETWORK_OR_RUNTIME_ERROR');
    console.error(JSON.stringify({ error: 'IDOR_PROBE_FAILED', reason }));
    process.exitCode = 1;
  }
}
