import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import attackModule from '../../attack-module/index.js';
import guardrailPackage from '../../guardrail/src/index.js';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';

const { executeUniversityRead } = attackModule;
const { GuardrailEvaluator } = guardrailPackage;

const PROFILES = Object.freeze({
  daehan: Object.freeze({
    origin: 'http://127.0.0.1:4101',
    fixtureId: 'vul-web2-daehan',
    endpoint: '/api/admissions/partner/applications',
    ownerField: 'partner_user_id',
    firstAccount: 'partner1', secondAccount: 'partner2', password: 'Partner2026',
  }),
  wonchang: Object.freeze({
    origin: 'http://127.0.0.1:4102',
    fixtureId: 'vul-web2-wonchang',
    endpoint: '/api/staff/mobile/cases',
    ownerField: 'staff_user_id',
    firstAccount: 'staff1', secondAccount: 'staff2', password: 'Staff2026',
  }),
});

const FIRST_RECORD_ID = 1;
const SECOND_RECORD_ID = 3;
const FIRST_OWNER_ID = 4;
const SECOND_OWNER_ID = 5;
const PROFILE_ID = 'known_record_idor_read';
const STAGES = Object.freeze({
  firstOwner: Object.freeze({ session: 'first-owner', recordId: FIRST_RECORD_ID }),
  secondOwner: Object.freeze({ session: 'second-owner', recordId: SECOND_RECORD_ID }),
  crossOwner: Object.freeze({ session: 'first-owner', recordId: SECOND_RECORD_ID }),
  studentRole: Object.freeze({ session: 'student', recordId: SECOND_RECORD_ID }),
});

function profileFor(siteKey) {
  if (!Object.hasOwn(PROFILES, siteKey)) throw new TypeError('Unknown fixed university site.');
  return PROFILES[siteKey];
}

function exactTargetOrigin(value) {
  return validateUniversityOrigin(value);
}

function pathFor(profile, recordId) {
  return `${profile.endpoint}/${recordId}`;
}

export function createIdorRuleset({ siteKey, origin }) {
  const profile = profileFor(siteKey);
  const allowedOrigin = exactTargetOrigin(origin);
  const firstPath = pathFor(profile, FIRST_RECORD_ID);
  const secondPath = pathFor(profile, SECOND_RECORD_ID);
  return {
    schemaVersion: '1.0.0',
    rulesetId: `vul-web2-${siteKey}-known-record-idor`,
    targetApplication: profile.fixtureId,
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
    endpointCatalog: [firstPath, secondPath].map((path, index) => ({
      id: `KNOWN_RECORD_${index + 1}`, method: 'GET',
      pathPattern: `^${path}$`, queryKeys: [], bodyKeys: [],
    })),
    hardDenyRules: [
      { id: 'SCOPE-ORIGIN', reason: 'The run origin changed.',
        when: { field: 'trustedContext.targetOrigin', operator: 'not_equals', value: allowedOrigin } },
      { id: 'SCOPE-MODE', reason: 'Only the isolated lab mode is allowed.',
        when: { field: 'trustedContext.targetMode', operator: 'not_equals', value: 'isolated_local_lab' } },
      { id: 'SCOPE-NETWORK', reason: 'External requests are forbidden.',
        when: { field: 'trustedContext.networkPolicy.externalRequests', operator: 'not_equals', value: 'DENY' } },
      { id: 'METHOD-READ-ONLY', reason: 'Only GET probes are allowed.',
        when: { field: 'action.method', operator: 'not_equals', value: 'GET' } },
      { id: 'ENDPOINT-ALLOWLIST', reason: 'The path is outside the two known records.',
        when: { operator: 'not_in_endpoint_catalog' } },
      { id: 'REQUEST-BUDGET', reason: 'The four-request budget is exhausted.',
        when: { operator: 'budget_exceeded' } },
    ],
    profiles: { [PROFILE_ID]: {
      trustedContextRequirements: {
        externalRequests: 'DENY', maximumHttpRequests: 4,
        maximumMutations: 0, maximumIterations: 1,
      },
      stageRules: Object.entries(STAGES).map(([stage, spec]) => ({
        stage, decision: 'ALLOW', exactAction: {
          operation: 'http_request', session: spec.session, method: 'GET',
          path: pathFor(profile, spec.recordId),
        },
      })),
    } },
  };
}

export class ProbeDeniedError extends Error {
  constructor(ruleId) {
    super(`IDOR probe denied by ${ruleId}.`);
    this.name = 'ProbeDeniedError';
    this.code = 'GUARDRAIL_DENIED';
    this.ruleId = ruleId;
  }
}

/** Authorize before curl. Each fixed stage can be sent once, even if curl fails. */
export function createGuardedGet({ siteKey, origin, runId, curlImpl = executeUniversityRead }) {
  const profile = profileFor(siteKey);
  const allowedOrigin = exactTargetOrigin(origin);
  if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(runId)) {
    throw new TypeError('A safe runId is required.');
  }
  if (typeof curlImpl !== 'function') throw new TypeError('curlImpl must be a function.');
  const evaluator = new GuardrailEvaluator(createIdorRuleset({ siteKey, origin: allowedOrigin }));
  const usedStages = new Set();
  const budget = { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 };

  return async function guardedGet(stage, { method = 'GET', path, cookie, signal } = {}) {
    const spec = STAGES[stage];
    if (!Object.hasOwn(STAGES, stage) || usedStages.has(stage)) {
      throw new ProbeDeniedError('STAGE-UNAVAILABLE');
    }
    const action = {
      operation: 'http_request', session: spec.session, method,
      path: path ?? pathFor(profile, spec.recordId),
    };
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
    return curlImpl({ method: 'GET', url: `${allowedOrigin}${action.path}` }, {
      allowedOrigin, cookie, signal, siteKey,
    });
  };
}

function sessionCookie(response) {
  if (response.status !== 302 || response.headers.get('location') !== '/mypage') {
    throw new Error('The fixed demo login did not complete.');
  }
  const cookie = response.headers.get('set-cookie')?.split(';', 1)[0]?.trim();
  if (!cookie || !/^[A-Za-z][A-Za-z0-9_-]{0,39}=[A-Za-z0-9._~-]{8,256}$/u.test(cookie)) {
    throw new Error('The fixed demo login did not return a valid session.');
  }
  return cookie;
}

async function login(origin, account, password, { fetchImpl, signal, onContact }) {
  signal?.throwIfAborted();
  const timeout = AbortSignal.timeout(5000);
  const response = await fetchImpl(`${origin}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: account, password }),
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
  });
  signal?.throwIfAborted();
  if (!signal?.aborted) onContact?.();
  return sessionCookie(response);
}

function observation(stage, response, ownerField) {
  const body = response?.bodyJson;
  return {
    check: stage,
    recordId: STAGES[stage].recordId,
    status: Number.isInteger(response?.status) ? response.status : null,
    ownerId: Number.isInteger(body?.[ownerField]) ? body[ownerField] : null,
    returnedRecordId: Number.isInteger(body?.id) ? body.id : null,
  };
}

function findingStatus(evidence) {
  const [first, second, cross, student] = evidence;
  const controlsPass = first.status === 200 && first.recordId === first.returnedRecordId
    && first.ownerId === FIRST_OWNER_ID
    && second.status === 200 && second.recordId === second.returnedRecordId
    && second.ownerId === SECOND_OWNER_ID
    && student.status === 403;
  if (!controlsPass) return 'inconclusive';
  if (cross.status === 200 && cross.recordId === cross.returnedRecordId
    && cross.ownerId === SECOND_OWNER_ID) return 'confirmed';
  if ([403, 404].includes(cross.status)) return 'not_confirmed';
  return 'inconclusive';
}

/** Dashboard targets are validated private HTTP origins; the CLI keeps its fixed origins. */
export async function probeSite({ siteKey, origin, fetchImpl = fetch, curlImpl = executeUniversityRead,
  signal, onObservation, onContact, runId = `idor-${randomUUID()}`, timeoutMs = 60_000 } = {}) {
  const profile = profileFor(siteKey);
  const allowedOrigin = exactTargetOrigin(origin ?? profile.origin);
  if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(runId)) {
    throw new TypeError('A safe runId is required.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new TypeError('The probe timeout must be between 1 and 60000 milliseconds.');
  }
  if (onObservation !== undefined && typeof onObservation !== 'function') {
    throw new TypeError('onObservation must be a function.');
  }
  if (onContact !== undefined && typeof onContact !== 'function') throw new TypeError('onContact must be a function.');
  const deadline = AbortSignal.timeout(timeoutMs);
  const boundedSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const contacted = () => { try { onContact?.(); } catch { /* Diagnostics cannot interrupt the probe. */ } };
  const startedAt = new Date().toISOString();
  boundedSignal.throwIfAborted();
  const cookies = {
    'first-owner': await login(allowedOrigin, profile.firstAccount, profile.password, { fetchImpl, signal: boundedSignal, onContact: contacted }),
    'second-owner': await login(allowedOrigin, profile.secondAccount, profile.password, { fetchImpl, signal: boundedSignal, onContact: contacted }),
    student: await login(allowedOrigin, 'student1', 'Welcome2026', { fetchImpl, signal: boundedSignal, onContact: contacted }),
  };
  const get = createGuardedGet({ siteKey, origin: allowedOrigin, runId, curlImpl });
  const evidence = [];
  for (const [stage, spec] of Object.entries(STAGES)) {
    boundedSignal.throwIfAborted();
    const response = await get(stage, { cookie: cookies[spec.session], signal: boundedSignal });
    boundedSignal.throwIfAborted();
    // A 403/404 is a completed access-control observation, even though curl's
    // adapter marks non-2xx HTTP responses as unsuccessful.
    if (!Number.isInteger(response?.status)) {
      throw Object.assign(new Error('The fixed IDOR request could not complete.'), { code: 'IDOR_REQUEST_FAILED' });
    }
    contacted();
    const entry = observation(stage, response, profile.ownerField);
    evidence.push(entry);
    // Subscribers see only the same bounded summary as the final report. Never
    // pass the HTTP body, session cookie, login request, or credentials onward.
    const safe = { check: entry.check, recordId: entry.recordId, status: entry.status, ownerId: entry.ownerId };
    try { onObservation?.(safe); } catch { /* Observers cannot interrupt the fixed probe. */ }
  }
  return {
    schemaVersion: '1.0', runId, fixtureId: profile.fixtureId,
    testProfile: PROFILE_ID, startedAt, completedAt: new Date().toISOString(),
    targetContacted: true, simulated: false,
    finding: { category: 'CWE-639', status: findingStatus(evidence) },
    evidence: evidence.map(({ check, recordId, status, ownerId }) => ({ check, recordId, status, ownerId })),
    provenance: { policy: `vul-web2-${siteKey}-known-record-idor`,
      guardrail: 'guardrail/GuardrailEvaluator', attack: 'attack-module/executeUniversityRead' },
  };
}

export async function runConfiguredSites({ args = [], probe = probeSite } = {}) {
  if (!Array.isArray(args) || args.length !== 0) {
    throw new TypeError('The IDOR probe accepts no URL or command-line arguments.');
  }
  const reports = [];
  for (const siteKey of ['daehan', 'wonchang']) {
    reports.push(await probe({ siteKey, origin: PROFILES[siteKey].origin }));
  }
  return { schemaVersion: '1.0', reports };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const summary = await runConfiguredSites({ args: process.argv.slice(2) });
    console.log(JSON.stringify(summary, null, 2));
    if (summary.reports.some(report => report.finding.status !== 'confirmed')) process.exitCode = 1;
  } catch (error) {
    const reason = process.argv.length > 2 ? 'ARGUMENTS_NOT_ALLOWED'
      : error instanceof ProbeDeniedError ? error.ruleId : 'NETWORK_OR_RUNTIME_ERROR';
    console.error(JSON.stringify({ error: 'IDOR_PROBE_FAILED', reason }));
    process.exitCode = 1;
  }
}
