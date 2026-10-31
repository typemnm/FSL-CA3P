import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { emptyRun, assertIdentifier, redact } from '../../packages/contracts/index.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, validateGeneralLoopBudget } from '../../packages/contracts/general-loop-budget.mjs';
import { verifyAttack } from '../../packages/verifier/index.mjs';
import generalCore from '../../agent/src/general-assessment.js';
import generalPlanner from '../../agent/src/general-model-planner.js';
import { judgeAttackRecord, projectGeneralEvent, recordForProbe } from './general-runtime.mjs';
import { externalScopeRejectionReason, normalizeExternalTarget, requestExternalHttp } from './external-target.mjs';
import { createAssessmentPlanner, createLocalJsonClient, isGeneralPlannerModel, LOCAL_PLANNER_MODEL_ID } from '../../packages/models/local-planner.mjs';

const { runGeneralAssessment } = generalCore;
const { GeneralModelPlanner } = generalPlanner;
const ACTIVE = new Set(['preparing', 'running', 'stopping']);
const INITIAL_PAGE_LIMIT = 2;
const MAX_LINK_CANDIDATES = 64;
const BODY_PREVIEW_BYTES = 4 * 1024;
const ASSESSMENT_DURATION_MS = 300_000;
const fault = (status, message, code) => Object.assign(new Error(message), { status, code });
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const digest = value => createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 16);
const evidenceId = value => `external-${digest(value)}`;
const pathOnly = value => {
  try { return new URL(value).pathname; } catch { return '/'; }
};
async function invokeHook(callback, ...args) {
  if (!callback) return undefined;
  try { return await callback(...args); }
  catch (error) {
    const failure = fault(503, 'Assessment probe authorization or recording failed.', 'PROBE_HOOK_FAILED');
    failure.fatalProbe = true;
    failure.cause = error;
    throw failure;
  }
}
function utf8Prefix(value, maxBytes) {
  const bytes = Buffer.from(String(value ?? ''), 'utf8');
  return bytes.subarray(0, maxBytes).toString('utf8').replace(/�$/u, '');
}
function safeText(value, maxBytes = 500) {
  return utf8Prefix(String(value ?? '').replace(/[\u0000-\u001f\u007f]/gu, ' ')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/giu, '$1 [redacted]')
    .replace(/\bnonce-[A-Za-z0-9+/_=-]{6,}/giu, 'nonce-[redacted]')
    .replace(/\b(password|passwd|api[_-]?key|secret|token|session|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      '$1=[redacted]'), maxBytes);
}
function publicPreview(body, contentType) {
  const source = /(?:text\/html|application\/xhtml\+xml)/iu.test(contentType ?? '')
    ? String(body ?? '').replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/giu, ' ')
      .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/giu, ' ')
      .replace(/<[^>]*>/gu, ' ').replace(/\s+/gu, ' ')
    : String(body ?? '');
  return safeText(source.replace(/https?:\/\/[^\s"'<>]+/giu, '[url]'), 450);
}
function verifierCallMetadata(item, modelId, probeId, iteration) {
  if (!record(item)) return null;
  const usage = record(item.usage) ? Object.fromEntries(
    ['prompt_tokens', 'completion_tokens', 'total_tokens']
      .filter(key => Number.isSafeInteger(item.usage[key]) && item.usage[key] >= 0)
      .map(key => [key, item.usage[key]])) : {};
  return { provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek', role: 'verifier', requestedModel: modelId,
    model: isGeneralPlannerModel(item.model) ? item.model : modelId,
    ...(typeof item.reportedModel === 'string' && /^[A-Za-z0-9._:/-]{1,128}$/u.test(item.reportedModel)
      ? { reportedModel: item.reportedModel } : {}),
    status: 'completed', iteration, probeId,
    ...(Object.keys(usage).length ? { usage } : {}) };
}

function pageLinks(body, base, scope) {
  const links = [];
  const rejected = {};
  let count = 0;
  const consider = raw => {
    if (++count > MAX_LINK_CANDIDATES) {
      rejected.link_candidate_limit = (rejected.link_candidate_limit ?? 0) + 1; return;
    }
    try {
      const url = new URL(raw, base);
      url.hash = '';
      const reason = externalScopeRejectionReason(url, scope) ?? (url.search ? 'query_link' : null);
      if (reason) rejected[reason] = (rejected[reason] ?? 0) + 1;
      else if (!links.includes(url.href)) links.push(url.href);
    } catch { rejected.invalid_url = (rejected.invalid_url ?? 0) + 1; }
  };
  const pattern = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/giu;
  for (const match of String(body ?? '').matchAll(pattern)) {
    consider(match[1] ?? match[2] ?? match[3]);
  }
  for (const match of String(body ?? '').matchAll(/<form\b([^>]*)>/giu)) {
    const attributes = match[1];
    const method = /\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/iu.exec(attributes);
    if (method && (method[1] ?? method[2] ?? method[3]).toUpperCase() !== 'GET') {
      rejected.unsupported_method = (rejected.unsupported_method ?? 0) + 1; continue;
    }
    const action = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/iu.exec(attributes);
    if (action) consider(action[1] ?? action[2] ?? action[3]);
  }
  return { links, rejected };
}

function scopedProbeUrl(path, origin, scope, allowedPaths) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')
    || path.length > 2048 || path.includes('#') || /[\u0000-\u001f\u007f\\]/u.test(path)) return null;
  try {
    const url = new URL(path, origin);
    return externalScopeRejectionReason(url, scope) === null && allowedPaths.has(url.pathname) ? url : null;
  } catch { return null; }
}

function observationSummary(url, response) {
  const body = String(response.body ?? '');
  const title = /(?:text\/html|application\/xhtml\+xml)/iu.test(response.contentType ?? '')
    ? safeText(body.match(/<title\b[^>]*>([^<]{0,300})<\/title>/iu)?.[1] ?? '', 180) : '';
  const headers = record(response.headers) ? Object.fromEntries(Object.entries(response.headers)
    .map(([name, value]) => [name, safeText(value, 180)])) : {};
  return { path: pathOnly(url), status: response.status ?? null,
    contentType: safeText(response.contentType, 120), title,
    securityHeaders: headers, truncated: Boolean(response.truncated) };
}

/**
 * A general assessment over a preflighted public scope. Every target request uses
 * requestExternalHttp; the AI verifier has no browser transport to escape that scope.
 */
export function createExternalGeneralRuntime({ targetUrl, scope: suppliedScope, modelId,
  limits = GENERAL_LOOP_BUDGET_DEFAULTS, runIdFactory = () => 'external-general-' + randomUUID(),
  requestImpl = requestExternalHttp, plannerFactory, verifyAttackImpl, verifierModel,
  verificationRoot, env = process.env, envFile, signal, onModelCall, beforeProbe, afterProbe } = {}) {
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: targetUrl,
    scope: { pathPrefix: suppliedScope?.pathPrefix ?? '/' } });
  if (suppliedScope && JSON.stringify(suppliedScope) !== JSON.stringify(scope)) {
    throw new TypeError('External scope changed after run preparation.');
  }
  if (!isGeneralPlannerModel(modelId)) throw new TypeError('A registered planner model is required for an external assessment.');
  for (const dependency of [requestImpl, runIdFactory]) if (typeof dependency !== 'function') {
    throw new TypeError('Invalid external runtime dependency.');
  }
  for (const callback of [plannerFactory, verifyAttackImpl, onModelCall, beforeProbe, afterProbe]) {
    if (callback !== undefined && typeof callback !== 'function') throw new TypeError('Invalid external runtime callback.');
  }
  const configuredLimits = validateGeneralLoopBudget(limits);
  const loopLimits = { ...configuredLimits,
    maxProbes: Math.min(configuredLimits.maxProbes, scope.maxRequests - INITIAL_PAGE_LIMIT) };
  const listeners = new Set();
  const instanceId = randomUUID();
  const initial = () => ({ ...emptyRun(), mode: 'external-general', assessmentMode: 'general',
    testProfile: 'external-general', fixtureId: null, target: redact(normalizedUrl),
    targetKind: 'external', coreTargetOrigin: scope.origin, simulated: false,
    targetContacted: false, requestAttempted: false, totalSteps: 1, iterations: 0,
    modelId, provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek' });
  let run = initial(); let controller = null; let task = null; let closed = false;

  function getState() {
    if (ACTIVE.has(run.status)) run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    return structuredClone({ run, mode: run.mode, instanceId,
      lab: { available: true, generalSupported: true, externalSupported: true,
        model: modelId, provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek' } });
  }
  function publish() {
    const state = getState();
    for (const listener of listeners) { try { listener(structuredClone(state)); } catch { /* Isolate subscribers. */ } }
  }
  function appendEvent(event) {
    const row = { id: `${run.id}:event-${run.events.length + 1}`, time: new Date().toISOString(),
      module: 'external-general', source: 'apps/application/external-general-runtime',
      simulated: false, targetContacted: run.targetContacted, ...event };
    run.events.push(row); run.snapshots['external-general'] = row;
    run.step = run.events.length; run.totalSteps = Math.max(1, run.step); publish();
  }

  async function runTask() {
    const assessmentDeadline = AbortSignal.timeout(ASSESSMENT_DURATION_MS);
    const runSignal = AbortSignal.any([controller.signal, assessmentDeadline, ...(signal ? [signal] : [])]);
    const allowedPaths = new Set([new URL(normalizedUrl).pathname]);
    const observedPaths = new Set();
    const pages = []; const observationErrors = []; const rejectionCounts = {};
    const queue = [normalizedUrl]; const queued = new Set(queue);
    let observed = false; let requestsUsed = 0; let targetRequestMs = 0; let verificationAttempts = 0;
    const verifierModelCalls = [];
    let requestBudgetReached = false; let partialResponse = false;
    function rejectCandidates(counts, sourcePageId) {
      for (const [reason, count] of Object.entries(counts)) {
        if (!count) continue;
        rejectionCounts[reason] = (rejectionCounts[reason] ?? 0) + count;
        appendEvent({ stage: 'scope.rejected', type: 'warning', title: '외부 요청 후보 거부',
          policy: { reason, count, sourcePageId } });
      }
    }
    async function scopedRequest(url, probe) {
      if (requestsUsed >= scope.maxRequests || targetRequestMs >= scope.maxDurationMs) {
        requestBudgetReached = true;
        throw fault(429, 'External request budget exhausted.', 'EXTERNAL_REQUEST_BUDGET');
      }
      const remainingMs = Math.max(1, scope.maxDurationMs - targetRequestMs);
      const requestSignal = AbortSignal.any([runSignal, AbortSignal.timeout(remainingMs)]);
      const reservation = await invokeHook(beforeProbe, { ...probe, method: 'GET', url: url.href });
      const started = Date.now();
      requestsUsed += 1; run.requestAttempted = true;
      let result;
      try {
        result = await requestImpl(url.href, { scope, method: 'GET', signal: requestSignal,
          maxBytes: scope.maxResponseBytes, timeoutMs: scope.requestTimeoutMs });
        run.targetContacted = true;
        if (result.contentEncoding && String(result.contentEncoding).toLowerCase() !== 'identity') {
          throw fault(422, 'Compressed external response is unsupported.', 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED');
        }
        if (result.truncated) partialResponse = true;
        if (result.status >= 300 && result.status < 400) {
          rejectCandidates({ redirect_not_followed: 1 }, probe.id);
        }
        return result;
      } finally {
        targetRequestMs += Date.now() - started;
        await invokeHook(afterProbe, { ...probe, method: 'GET', url: url.href },
          { status: result?.status ?? 'failed' }, reservation);
      }
    }
    function probeEvidence(probe, url, response, control) {
      const observed = observationSummary(url, response);
      const controlSummary = control ? observationSummary(control.url, control.response) : null;
      const responseBody = safeText(response.body, BODY_PREVIEW_BYTES);
      const controlBody = control ? safeText(control.response.body, BODY_PREVIEW_BYTES) : null;
      const summary = safeText(`GET ${observed.path}: HTTP ${observed.status}, type ${observed.contentType}, `
        + `sha256 ${digest(response.body)}, headers ${JSON.stringify(observed.securityHeaders)}`
        + (controlSummary ? `; control HTTP ${controlSummary.status}, sha256 ${digest(control.response.body)}` : '')
        + `; body preview ${publicPreview(response.body, response.contentType)}`, 1500);
      const evidence = { id: evidenceId(probe.id), source: 'http/external', kind: control ? 'http-comparison' : 'http-response',
        asset: observed.path, summary };
      const attackRecord = { schemaVersion: 'attack-record/1', id: probe.id,
        kind: 'external-http', target: { origin: scope.origin },
        request: { method: 'GET', url: url.href, headers: {}, body: null },
        response: { status: Number.isInteger(response.status) ? response.status : null,
          headers: { ...observed.securityHeaders }, bodyText: responseBody,
          truncated: Boolean(response.truncated) },
        ...(control && { control: {
          request: { method: 'GET', url: control.url.href, headers: {}, body: null },
          response: { status: Number.isInteger(control.response.status) ? control.response.status : null,
            headers: { ...controlSummary.securityHeaders }, bodyText: controlBody,
            truncated: Boolean(control.response.truncated) },
        } }),
      };
      return { kind: probe.tool, result: observed, evidence: [evidence], attackRecord };
    }
    try {
      runSignal.throwIfAborted(); run.status = 'running'; publish();
      const planner = plannerFactory
        ? await plannerFactory({ modelId, env, envFile, signal: runSignal })
        : await createAssessmentPlanner({ modelId, env, envFile });
      if (!planner || typeof planner.propose !== 'function') throw new TypeError('General planner is unavailable.');
      const localVerifier = verifierModel ?? (modelId === LOCAL_PLANNER_MODEL_ID && (verifyAttackImpl ?? verifyAttack) === verifyAttack
        ? await createLocalJsonClient({ env, envFile }) : undefined);
      const observer = { async observe() {
        if (observed) return { inventory: undefined, evidence: [] };
        observed = true;
        const evidence = [];
        while (queue.length && pages.length < INITIAL_PAGE_LIMIT && requestsUsed < scope.maxRequests) {
          runSignal.throwIfAborted();
          const url = new URL(queue.shift());
          try {
            const response = await scopedRequest(url, { id: `inventory-${pages.length + 1}`,
              iteration: 1, tool: 'http_get', session: 'public' });
            const page = observationSummary(url, response);
            pages.push(page);
            observedPaths.add(url.pathname);
            evidence.push({ id: evidenceId('inventory-' + pages.length + url.href),
              source: 'http/external', kind: 'surface-observation', asset: page.path,
              summary: safeText(`GET ${page.path}: HTTP ${page.status}, type ${page.contentType}, `
                + `title ${page.title}, headers ${JSON.stringify(page.securityHeaders)}`, 1500) });
            if (/(?:text\/html|application\/xhtml\+xml)/iu.test(response.contentType ?? '')
              && !(response.status >= 300 && response.status < 400) && !response.truncated) {
              const { links, rejected } = pageLinks(response.body, url, scope);
              rejectCandidates(rejected, `inventory-${pages.length}`);
              for (const link of links) if (!queued.has(link) && queued.size < MAX_LINK_CANDIDATES) {
                queued.add(link); queue.push(link); allowedPaths.add(new URL(link).pathname);
              }
            }
          } catch (error) {
            if (runSignal.aborted || error?.fatalProbe) throw error;
            observationErrors.push({ path: url.pathname, code: safeText(error?.code ?? 'REQUEST_FAILED', 80) });
            evidence.push({ id: evidenceId('inventory-error-' + url.href), source: 'http/external',
              kind: 'unavailable', asset: url.pathname,
              summary: `GET ${url.pathname} could not be observed; no safety conclusion follows.` });
          }
        }
        if (!pages.length) throw fault(502, 'No public page could be observed.', 'EXTERNAL_TARGET_UNAVAILABLE');
        return { inventory: { kind: 'external', origin: scope.origin, entryPath: pathOnly(normalizedUrl),
          pages, discoveredInScope: queued.size, authentication: 'none',
          toolCapabilities: {
            http_get: 'input {path}: one GET to an observed or discovered in-scope path, optionally with a safe query; redirects are not followed',
            http_compare: 'input {path,controlPath}: compare two GET responses at the same observed or discovered in-scope path',
          },
          limitations: ['Only public GET requests are permitted; no authentication, writes, browser navigation, or source access.',
            'A completed run covers only the bounded pages and probes it actually observed.'],
        }, evidence };
      } };
      const policy = { async authorize({ probe }) {
        if (!['http_get', 'http_compare'].includes(probe.tool) || !record(probe.input)) {
          return { allowed: false, reason: 'tool_unavailable' };
        }
        const compare = probe.tool === 'http_compare';
        const expected = compare ? ['path', 'controlPath'] : ['path'];
        if (Object.keys(probe.input).length !== expected.length
          || expected.some(key => !Object.hasOwn(probe.input, key))) {
          return { allowed: false, reason: 'invalid_probe_input' };
        }
        const candidate = scopedProbeUrl(probe.input.path, scope.origin, scope, allowedPaths);
        const control = compare ? scopedProbeUrl(probe.input.controlPath, scope.origin, scope, allowedPaths) : null;
        if (!candidate || compare && (!control || candidate.pathname !== control.pathname)) {
          return { allowed: false, reason: 'path_out_of_scope' };
        }
        if (requestsUsed + (compare ? 2 : 1) > scope.maxRequests || targetRequestMs >= scope.maxDurationMs) {
          requestBudgetReached = true;
          return { allowed: false, reason: 'request_budget' };
        }
        return { allowed: true };
      } };
      const executor = { async execute({ probe }) {
        const candidate = scopedProbeUrl(probe.input.path, scope.origin, scope, allowedPaths);
        const controlUrl = probe.tool === 'http_compare'
          ? scopedProbeUrl(probe.input.controlPath, scope.origin, scope, allowedPaths) : null;
        try {
          const control = controlUrl ? { url: controlUrl,
            response: await scopedRequest(controlUrl, { id: `${probe.id}-control`, iteration: run.iterations,
              tool: probe.tool, session: 'public' }) } : null;
          const response = await scopedRequest(candidate, { id: probe.id, iteration: run.iterations,
            tool: probe.tool, session: 'public' });
          observedPaths.add(candidate.pathname);
          if (control) observedPaths.add(control.url.pathname);
          return probeEvidence(probe, candidate, response, control);
        } catch (error) {
          if (runSignal.aborted || error?.fatalProbe) throw error;
          observationErrors.push({ path: candidate.pathname,
            code: safeText(error?.code ?? 'REQUEST_FAILED', 80) });
          return { kind: probe.tool, error: 'request_unavailable',
            evidence: [{ id: evidenceId(probe.id), source: 'http/external', kind: 'unavailable',
              asset: candidate.pathname, summary: `GET ${candidate.pathname} failed; the hypothesis remains unverified.` }] };
        }
      } };
      const verifier = { async verify({ hypothesis, probe, execution, evidence }) {
        const id = execution.evidence[0].id;
        if (execution.error || execution.attackRecord?.response?.truncated
          || execution.attackRecord?.control?.response?.truncated) {
          return { status: 'inconclusive', evidenceIds: [id], reason: execution.error ?? 'truncated_response' };
        }
        const relatedEvidence = evidence.filter(item => hypothesis.evidenceIds.includes(item.id)
          && item.id !== id).slice(-8);
        const attack = recordForProbe({ probe, hypothesis, execution, origin: scope.origin, relatedEvidence });
        verificationAttempts += 1;
        const verify = async (attackRecord, options) => {
          const result = await (verifyAttackImpl ?? verifyAttack)(attackRecord, options);
          for (const item of Array.isArray(result.model) ? result.model : []) {
            const metadata = verifierCallMetadata(item, modelId, probe.id, run.iterations);
            if (!metadata) continue;
            await invokeHook(onModelCall, metadata);
            verifierModelCalls.push(metadata);
          }
          return result;
        };
        return judgeAttackRecord(attack, { evidenceId: id, verify,
          model: localVerifier, outDir: verificationRoot ? join(verificationRoot, probe.id) : undefined,
          browserFactory: async () => { throw fault(403, 'External browser navigation is disabled.', 'EXTERNAL_BROWSER_DISABLED'); },
          env: { ...env, CA3P_VERIFIER_MODEL: modelId }, envFile, signal: runSignal });
      } };
      const wrappedPlanner = { async propose(context) {
        let plan;
        try { plan = await planner.propose(context); }
        catch (error) {
          const attempts = planner instanceof GeneralModelPlanner && Array.isArray(error?.modelAttempts)
            ? error.modelAttempts : [{ provider: modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : 'deepseek', requestedModel: modelId,
              status: 'failed', iteration: context.iteration }];
          for (const attempt of attempts) await onModelCall?.(attempt);
          throw error;
        }
        const trusted = planner instanceof GeneralModelPlanner;
        for (const attempt of trusted && Array.isArray(plan?.modelAttempts)
          ? plan.modelAttempts : [plan?.modelMetadata]) if (attempt) await onModelCall?.(attempt);
        if (!trusted && record(plan) && Object.hasOwn(plan, 'modelAttempts')) {
          plan = { ...plan }; delete plan.modelAttempts;
        }
        return plan;
      } };
      const { report } = await runGeneralAssessment({
        target: { kind: 'external', entryUrl: redact(normalizedUrl), origin: scope.origin },
        observer, planner: wrappedPlanner, policy, executor, verifier,
        availableTools: ['http_get', 'http_compare'], limits: loopLimits, signal: runSignal,
        onEvent: async event => {
          run.iterations = Math.max(run.iterations, event.iteration ?? 0);
          appendEvent({ ...projectGeneralEvent(event, loopLimits),
            module: 'agent', source: 'agent/general-assessment', iteration: event.iteration });
        },
      });
      report.runId = run.id;
      report.modelCalls.push(...verifierModelCalls);
      report.inspectionMode = 'external-general';
      report.targetContacted = run.targetContacted;
      report.requestAttempted = run.requestAttempted;
      report.scope = { ...scope, authentication: 'none', supportedTools: ['http_get', 'http_compare'],
        supportedIndependentVerifiers: ['ai-attack-record'], browserVisits: 'disabled',
        targetHttpDurationMs: scope.maxDurationMs, assessmentDurationMs: ASSESSMENT_DURATION_MS };
      report.policyRejections = { total: Object.values(rejectionCounts).reduce((sum, count) => sum + count, 0),
        byReason: { ...rejectionCounts } };
      report.observationErrors = observationErrors;
      report.coverage = { ...report.coverage, observedPages: observedPaths.size, requestsUsed,
        discoveredInScope: queued.size,
        unobservedPages: [...allowedPaths].filter(path => !observedPaths.has(path)).length,
        independentVerifierAttempts: verificationAttempts,
        supportedIndependentChecks: report.probes.filter(item => ['confirmed', 'not_reproduced'].includes(item.status)).length };
      report.partial ||= observationErrors.length > 0 || partialResponse || report.coverage.unobservedPages > 0
        || requestBudgetReached || report.probes.some(item => item.status === 'blocked');
      if (requestBudgetReached && report.status === 'completed') report.stopReason = 'request_budget';
      if (assessmentDeadline.aborted && !controller.signal.aborted && !signal?.aborted) {
        report.status = 'completed'; report.partial = true; report.stopReason = 'assessment_duration';
      }
      run.report = report;
      run.status = report.status === 'cancelled' ? 'stopped' : report.status;
      run.error = report.status === 'failed' ? report.error?.code ?? 'GENERAL_ASSESSMENT_FAILED' : undefined;
      run.reviewItems = report.findings.map(finding => ({ id: `${run.id}:${finding.id}`,
        title: `${finding.category} · ${finding.asset}`, description: finding.rationale,
        evidenceId: finding.evidenceIds[0] ?? null, evidence: finding.evidenceIds.join(', '),
        vulnerabilityConfirmed: finding.status === 'confirmed', status: finding.status, simulated: false }));
    } catch (error) {
      run.status = controller.signal.aborted || signal?.aborted ? 'stopped' : 'failed';
      run.error = run.status === 'stopped' ? '사용자가 실행을 중지했습니다.'
        : assessmentDeadline.aborted ? 'EXTERNAL_ASSESSMENT_DURATION'
          : safeText(error?.code ?? 'EXTERNAL_GENERAL_FAILED', 100);
      appendEvent({ stage: 'external.failed', type: 'error', title: '외부 범용 점검 실패', detail: run.error });
    } finally {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
      run.totalSteps = Math.max(1, run.events.length);
      task = null; publish();
    }
  }
  function startLab(options = {}) {
    if (closed) throw fault(503, 'External general runtime is closed.');
    if (task || ACTIVE.has(run.status)) throw fault(409, 'An external assessment is already active.');
    if (!record(options) || Object.keys(options).length) throw fault(400, 'External runtime accepts no additional options.');
    const id = assertIdentifier(runIdFactory(), 'runId');
    controller = new AbortController();
    run = { ...initial(), id, coreRunId: id, status: 'preparing', startedAt: new Date().toISOString() };
    task = Promise.resolve().then(runTask); publish(); return getState();
  }
  function stop(id) {
    if (!id || id !== run.id) throw fault(404, 'External assessment not found.');
    if (ACTIVE.has(run.status)) { run.status = 'stopping'; controller.abort(); publish(); }
    return getState();
  }
  async function close() {
    closed = true;
    if (ACTIVE.has(run.status)) stop(run.id);
    await task; listeners.clear();
  }
  return { getState, startLab, stop, close,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); } };
}
