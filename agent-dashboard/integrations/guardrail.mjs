import { fileURLToPath } from 'node:url';
import xssCanary from '../../agent/src/xss-canary.js';
import guardrailPackage from '../../guardrail/src/index.js';

const { GuardrailEvaluator, loadRuleset } = guardrailPackage;
const { storedXssCanaryContent } = xssCanary;
const RULESET_FILE = fileURLToPath(new URL('../../guardrail/rules/fsl-ca3p-guardrail-ruleset.json', import.meta.url));
const BOLA_PROFILE = 'agent_cross_user_delete_canary';
const XSS_PROFILE = 'stored_xss_canary';
const PROFILES = new Set([BOLA_PROFILE, XSS_PROFILE]);
const MAX_ITERATIONS = 1;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, required, optional = []) {
  return isRecord(value)
    && required.every(key => Object.hasOwn(value, key))
    && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
}

function localOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw new TypeError('Guardrail targetOrigin must be an absolute URL.'); }
  if (typeof value !== 'string'
    || url.protocol !== 'http:'
    || url.hostname !== '127.0.0.1'
    || !url.port
    || url.origin !== value
    || url.pathname !== '/'
    || url.search || url.hash || url.username || url.password) {
    throw new Error('Guardrail accepts only the exact private 127.0.0.1 HTTP origin.');
  }
  return url.origin;
}

function runtimeRuleset(origin) {
  const ruleset = structuredClone(loadRuleset(RULESET_FILE));
  const scopeRule = ruleset.hardDenyRules.find(rule => rule.id === 'SCOPE-002');
  if (ruleset.targetApplication !== 'vul-web-1'
    || !scopeRule
    || scopeRule.when?.field !== 'trustedContext.targetOrigin'
    || scopeRule.when?.operator !== 'not_in'
    || !Array.isArray(scopeRule.when.values)) {
    throw new Error('Guardrail ruleset has an unsupported local origin policy.');
  }
  // The checked-in profile names port 3000. The private board gets a random
  // loopback port, so bind a per-run copy to that one exact origin.
  ruleset.scope.allowedOrigins = [origin];
  ruleset.scope.canonicalOrigin = origin;
  scopeRule.when.values = [origin];
  return ruleset;
}

function projectedCurl(payload, origin) {
  if (!exactKeys(payload, ['operation', 'session', 'curl'])
    || payload.operation !== 'execute_curl'
    || !exactKeys(payload.curl, ['method', 'url'], ['body'])
    || !['POST', 'DELETE'].includes(payload.curl.method)
    || typeof payload.curl.url !== 'string') {
    throw new TypeError('Guardrail requires structured POST or DELETE curl JSON.');
  }
  let url;
  try { url = new URL(payload.curl.url); }
  catch { throw new TypeError('Guardrail curl URL must be absolute.'); }
  if (url.href !== payload.curl.url
    || url.origin !== origin
    || url.username || url.password || url.hash) {
    throw new Error('Guardrail curl URL is outside the exact private lab origin.');
  }
  const query = {};
  for (const [key, value] of url.searchParams) {
    if (Object.hasOwn(query, key)) {
      throw new Error('Guardrail rejects duplicate curl query parameters.');
    }
    query[key] = value;
  }
  const action = {
    operation: 'http_request',
    session: payload.session,
    method: payload.curl.method,
    path: url.pathname,
  };
  if (Object.keys(query).length) action.query = query;
  if (Object.hasOwn(payload.curl, 'body')) {
    if (!isRecord(payload.curl.body)) {
      throw new TypeError('Guardrail curl body must be a JSON object.');
    }
    action.body = payload.curl.body;
  }
  return action;
}

function stageIteration(stage) {
  if (typeof stage !== 'string') throw new TypeError('Guardrail stage must be a string.');
  if (stage.startsWith('setup.')) return 0;
  if (stage.startsWith('loop.')) return 1;
  if (stage === 'xss.setup_session') return 0;
  if (['xss.inject_canary', 'xss.observe'].includes(stage)) return 1;
  throw new Error(`Guardrail does not accept stage ${stage} in this run profile.`);
}

export class GuardrailDeniedError extends Error {
  constructor(result) {
    super(`Guardrail denied ${result.stage} [${result.ruleId}]: ${result.reason}`);
    this.name = 'GuardrailDeniedError';
    this.code = 'GUARDRAIL_DENIED';
    this.guardrailDecision = result;
  }
}

/**
 * A per-run bridge to the repository's real GuardrailEvaluator. The caller
 * supplies only actions; trusted target, identity, canary and budget come from
 * this instance and never from the model or module request.
 */
export function createLocalGuardrail({ origin: targetOrigin, runId, profile = BOLA_PROFILE }) {
  const origin = localOrigin(targetOrigin);
  if (typeof runId !== 'string' || runId.length === 0 || runId.length > 128) {
    throw new TypeError('Guardrail requires a non-empty trusted runId.');
  }
  if (!PROFILES.has(profile)) throw new Error('Guardrail accepts only a supported local canary profile.');
  const ruleset = runtimeRuleset(origin);
  const evaluator = new GuardrailEvaluator(ruleset);
  const maxRequests = ruleset.profiles[profile]?.trustedContextRequirements?.maximumHttpRequests;
  if (!Number.isInteger(maxRequests) || maxRequests < 1) {
    throw new Error('Guardrail profile has no valid HTTP request budget.');
  }
  const budget = {
    requestCount: 0,
    mutationCount: 0,
    deleteCount: 0,
    xssSubmissionCount: 0,
  };
  let boundCanary = profile === XSS_PROFILE
    ? { titlePrefix: `agent-xss-canary-${runId}-`, createdByRunId: runId }
    : undefined;
  const decisions = [];

  function trustedContext(stage) {
    return {
      targetMode: 'isolated_local_lab',
      targetOrigin: origin,
      testProfile: profile,
      runId,
      iteration: stageIteration(stage),
      currentUser: { id: 'alice' },
      fixtureOwner: { id: 'bob' },
      ...(boundCanary ? { boundCanary: { ...boundCanary } } : {}),
      networkPolicy: { externalRequests: 'DENY' },
      budget: { ...budget },
    };
  }

  function authorizeAction(stage, action) {
    if (profile === XSS_PROFILE && stage === 'xss.inject_canary') {
      const title = action.body?.title;
      const prefix = boundCanary.titlePrefix;
      const marker = typeof title === 'string' && title.startsWith(prefix)
        ? title.slice(prefix.length) : null;
      if (typeof marker !== 'string' || !/^[0-9a-f]{32}$/.test(marker)
        || action.body?.content !== storedXssCanaryContent(marker)) {
        const denied = {
          decision: 'DENY', ruleId: 'XSS-CANARY-MISMATCH',
          reason: 'XSS submission must be the exact in-run local canary probe.',
          runId, stage, normalizedTarget: null, matchedClassifiers: [],
          budgetSnapshot: { ...budget },
        };
        decisions.push(structuredClone(denied));
        throw new GuardrailDeniedError(denied);
      }
    }
    const result = evaluator.evaluate({ stage, action, trustedContext: trustedContext(stage) });
    decisions.push(structuredClone(result));
    if (result.decision !== 'ALLOW') throw new GuardrailDeniedError(result);
    // Reserve the request before dispatch, including failures, so a failed
    // mutation cannot be retried under the same budget slot.
    budget.requestCount += 1;
    if (action.method === 'POST' && action.path === '/api/posts') budget.mutationCount += 1;
    if (stage === 'xss.inject_canary') budget.xssSubmissionCount += 1;
    if (action.method === 'DELETE') {
      budget.mutationCount += 1;
      budget.deleteCount += 1;
    }
    return result;
  }

  function bindCanary({ resourceId, ownerId, createdByRunId }) {
    if (profile === XSS_PROFILE) {
      if (boundCanary.resourceId !== undefined) throw new Error('Guardrail canary is already bound.');
      if (!Number.isInteger(resourceId) || resourceId <= 2
        || ownerId !== 'alice' || createdByRunId !== runId) {
        throw new Error('Guardrail can bind only the observed Alice XSS canary from this run.');
      }
      boundCanary = { ...boundCanary, resourceId, ownerId };
      return;
    }
    if (boundCanary) throw new Error('Guardrail canary is already bound.');
    if (!Number.isInteger(resourceId) || resourceId <= 2
      || ownerId !== 'bob' || createdByRunId !== runId) {
      throw new Error('Guardrail can bind only the observed Bob canary from this run.');
    }
    boundCanary = { resourceId, ownerId, createdByRunId };
  }

  return {
    targetOrigin: origin,
    rulesetId: ruleset.rulesetId,
    bindCanary,
    authorize(stage, actionOrCurl, context = {}) {
      if (!exactKeys(context, [], ['boundCanary'])) {
        throw new TypeError('Guardrail context accepts only a trusted boundCanary.');
      }
      if (context.boundCanary !== undefined) {
        const supplied = context.boundCanary;
        if (!isRecord(supplied)) throw new TypeError('Guardrail boundCanary must be an object.');
        if (!boundCanary) bindCanary(supplied);
        else if (supplied.resourceId !== boundCanary.resourceId
          || supplied.ownerId !== boundCanary.ownerId
          || supplied.createdByRunId !== boundCanary.createdByRunId) {
          throw new Error('Guardrail boundCanary cannot change during a run.');
        }
      }
      if (actionOrCurl?.operation === 'execute_curl') {
        return authorizeAction(stage, projectedCurl(actionOrCurl, origin));
      }
      if (!exactKeys(actionOrCurl, ['operation', 'session', 'method', 'path'])
        || actionOrCurl.operation !== 'http_request' || actionOrCurl.method !== 'GET') {
        throw new TypeError('Guardrail read requests must be structured GET actions.');
      }
      return authorizeAction(stage, actionOrCurl);
    },
    authorizeRead(stage, action) {
      if (!exactKeys(action, ['operation', 'session', 'method', 'path'])
        || action.operation !== 'http_request' || action.method !== 'GET') {
        throw new TypeError('Guardrail read requests must be structured GET actions.');
      }
      return authorizeAction(stage, action);
    },
    authorizeCurl(stage, payload) {
      return authorizeAction(stage, projectedCurl(payload, origin));
    },
    metrics() {
      return { ...budget, maxRequests, maxIterations: MAX_ITERATIONS };
    },
    audit() {
      return structuredClone(decisions);
    },
  };
}

export const createGuardrailForRun = ({ targetOrigin, runId, profile }) => createLocalGuardrail({
  origin: targetOrigin, runId, profile,
});
