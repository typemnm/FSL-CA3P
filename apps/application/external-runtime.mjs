import { randomUUID } from 'node:crypto';
import { emptyRun, assertIdentifier, redact } from '../../packages/contracts/index.mjs';
import { externalScopeRejectionReason, normalizeExternalTarget, requestExternalHttp } from './external-target.mjs';

export { createExternalGeneralRuntime } from './external-general-runtime.mjs';

const ACTIVE = new Set(['preparing', 'running', 'stopping']);
const fault = (status, message) => Object.assign(new Error(message), { status });
const safeText = value => String(value ?? '').replace(/[\u0000-\u001f]/gu, ' ').slice(0, 180);
const MAX_LINK_CANDIDATES = 64;
const REJECTION_LABELS = Object.freeze({
  invalid_url: '올바르지 않은 링크', unsupported_scheme: '지원하지 않는 URL 방식',
  credential_userinfo: '인증 정보가 포함된 링크', credential_query: '인증 쿼리가 포함된 링크',
  out_of_scope_origin: '허용 원점 밖 링크', out_of_scope_path: '허용 경로 밖 링크',
  query_link: '쿼리가 포함된 발견 링크',
  link_candidate_limit: '링크 후보 수 한도', crawl_queue_limit: '탐색 대기열 한도',
  redirect_not_followed: '리다이렉트 미추적',
});

function increment(counts, reason, amount = 1) {
  counts[reason] = (counts[reason] ?? 0) + amount;
}

function linksFromHtml(body, base, scope) {
  const found = [];
  const rejected = {};
  let inspected = 0;
  const pattern = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/giu;
  for (const match of body.matchAll(pattern)) {
    if (++inspected > MAX_LINK_CANDIDATES) {
      increment(rejected, 'link_candidate_limit');
      continue;
    }
    try {
      const url = new URL(match[1] ?? match[2] ?? match[3], base);
      url.hash = '';
      const reason = externalScopeRejectionReason(url, scope);
      if (reason) increment(rejected, reason);
      else if (url.search) increment(rejected, 'query_link');
      else if (!found.includes(url.href)) found.push(url.href);
    } catch { increment(rejected, 'invalid_url'); }
  }
  return { links: found, rejected };
}

function redirectDestinationReason(location, base, scope) {
  if (!location) return 'missing_location';
  try { return externalScopeRejectionReason(new URL(location, base), scope) ?? 'in_scope'; }
  catch { return 'invalid_url'; }
}

export function createExternalRuntime({ targetUrl, scope: suppliedScope, modelId = 'rule-baseline',
  runIdFactory = () => 'external-' + randomUUID(), requestImpl = requestExternalHttp,
  signal, beforeProbe, afterProbe } = {}) {
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: targetUrl,
    scope: { pathPrefix: suppliedScope?.pathPrefix ?? '/' } });
  if (suppliedScope?.origin && JSON.stringify(suppliedScope) !== JSON.stringify(scope)) {
    throw new TypeError('External scope changed after run preparation.');
  }
  if (modelId !== 'rule-baseline') throw new TypeError('Initial external observation uses the rule baseline.');
  if (typeof requestImpl !== 'function' || typeof runIdFactory !== 'function') throw new TypeError('Invalid external runtime dependency.');
  const listeners = new Set();
  const instanceId = randomUUID();
  const initial = () => ({ ...emptyRun(), mode: 'external-general', assessmentMode: 'general',
    testProfile: 'external-read-only', fixtureId: null, target: redact(normalizedUrl),
    targetKind: 'external', coreTargetOrigin: scope.origin, simulated: false,
    targetContacted: false, requestAttempted: false,
    totalSteps: 1, iterations: 0, modelId, provider: 'rules' });
  let run = initial(); let controller = null; let task = null; let closed = false;

  function getState() {
    if (ACTIVE.has(run.status)) run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    return structuredClone({ run, mode: run.mode, instanceId,
      lab: { available: true, externalSupported: true, model: modelId, provider: 'rules' } });
  }
  function publish() {
    const state = getState();
    for (const listener of listeners) { try { listener(structuredClone(state)); } catch { /* Subscriber is isolated. */ } }
  }
  function appendEvent(event) {
    const row = { id: run.id + ':event-' + (run.events.length + 1), time: new Date().toISOString(),
      module: 'external-observer', type: 'info', source: 'apps/application/external-runtime',
      simulated: false, targetContacted: run.targetContacted, ...event };
    run.events.push(row); run.snapshots['external-observer'] = row;
    run.step = run.events.length; run.totalSteps = Math.max(1, run.step); publish();
  }
  async function runTask() {
    const begunAt = new Date().toISOString();
    const budgetSignal = AbortSignal.timeout(scope.maxDurationMs);
    const pages = []; const evidence = []; const queue = [normalizedUrl]; const queued = new Set(queue);
    const rejectionCounts = {};
    let requestsUsed = 0;
    const errors = [];
    function recordRejections(rejected, sourcePageId, details = {}) {
      for (const [reason, count] of Object.entries(rejected)) {
        if (!count) continue;
        increment(rejectionCounts, reason, count);
        appendEvent({ stage: 'scope.rejected', title: '외부 요청 후보 거부', type: 'warning',
          detail: `${REJECTION_LABELS[reason]} ${count}건`,
          policy: { reason, count, sourcePageId, ...details } });
      }
    }
    try {
      const runSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      runSignal.throwIfAborted();
      run.status = 'running'; run.iterations = 1; publish();
      while (queue.length && requestsUsed < scope.maxRequests && !budgetSignal.aborted) {
        runSignal.throwIfAborted();
        const url = queue.shift();
        requestsUsed += 1;
        const probe = { id: 'page-' + requestsUsed, iteration: 1, tool: 'http_get',
          session: 'public', method: 'GET', url };
        let reservation; let response;
        try {
          reservation = await beforeProbe?.(probe);
          run.requestAttempted = true;
          response = await requestImpl(url, { scope, method: 'GET',
            signal: AbortSignal.any([runSignal, budgetSignal]) });
          run.targetContacted = true;
          if (response.contentEncoding && String(response.contentEncoding).toLowerCase() !== 'identity') {
            throw Object.assign(new Error('Compressed external response is unsupported.'),
              { code: 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED' });
          }
          const redirect = response.status >= 300 && response.status < 400;
          const html = !redirect && /(?:text\/html|application\/xhtml\+xml)/iu.test(response.contentType);
          const { links, rejected } = html ? linksFromHtml(response.body, url, scope)
            : { links: [], rejected: {} };
          for (const link of links) if (!queued.has(link)) {
            if (queued.size < MAX_LINK_CANDIDATES) { queued.add(link); queue.push(link); }
            else increment(rejected, 'crawl_queue_limit');
          }
          const title = html ? safeText(response.body.match(/<title\b[^>]*>([^<]{0,300})<\/title>/iu)?.[1] ?? '') : '';
          const page = { url: redact(url), status: response.status, contentType: safeText(response.contentType),
            title, linksDiscovered: links.length, truncated: !!response.truncated, durationMs: response.durationMs };
          pages.push(page);
          evidence.push({ id: 'external-page-' + pages.length, source: 'http/public', kind: 'observed-page',
            asset: redact(url), summary: `GET returned HTTP ${response.status}; ${redirect
              ? 'redirect was not followed.' : 'body was not retained.'}` });
          appendEvent({ stage: 'observe', title: '공개 페이지 관찰', request: { method: 'GET', url: redact(url) },
            response: { status: response.status, contentType: page.contentType, truncated: page.truncated } });
          recordRejections(rejected, probe.id);
          if (redirect) recordRejections({ redirect_not_followed: 1 }, probe.id,
            { responseStatus: response.status,
              destinationReason: redirectDestinationReason(response.location, url, scope) });
        } catch (error) {
          if (runSignal.aborted) throw error;
          if (budgetSignal.aborted) {
            errors.push({ url: redact(url), code: 'EXTERNAL_DURATION_BUDGET' });
            appendEvent({ stage: 'observe.budget', title: '외부 관찰 시간 한도 도달', type: 'warning' });
            break;
          }
          errors.push({ url: redact(url), code: safeText(error?.code ?? 'REQUEST_FAILED') });
          appendEvent({ stage: 'observe.failed', title: '페이지 관찰 실패', type: 'warning',
            request: { method: 'GET', url: redact(url) }, response: { errorCode: safeText(error?.code ?? 'REQUEST_FAILED') } });
          if (!pages.length && error?.code !== 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED') throw error;
        } finally {
          await afterProbe?.(probe, { status: response?.status ?? 'failed' }, reservation);
        }
      }
      const rejectedTotal = Object.values(rejectionCounts).reduce((sum, count) => sum + count, 0);
      run.report = { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
        inspectionMode: 'external-read-only', runId: run.id, status: 'completed',
        target: { kind: 'external', entryUrl: redact(normalizedUrl), origin: scope.origin },
        targetContacted: run.targetContacted,
        requestAttempted: run.requestAttempted,
        scope: { ...scope, authentication: 'none', supportedTools: ['http_get'],
          supportedIndependentVerifiers: [] },
        inventory: { pages, discoveredInScope: queued.size }, evidence, hypotheses: [], probes: [],
        findings: [], rejectedProposals: [], modelCalls: [],
        policyRejections: { total: rejectedTotal, byReason: { ...rejectionCounts } },
        coverage: { totalHypotheses: 0, confirmed: 0, notReproduced: 0, inconclusive: 0,
          notTested: 0, observedPages: pages.length, requestsUsed, discoveredInScope: queued.size,
          rejectedCandidates: rejectedTotal,
          supportedIndependentChecks: 0, unobservedPages: Math.max(0, queued.size - pages.length),
          limitations: ['No independent verifier is available for arbitrary external targets.'] },
        partial: errors.length > 0 || queued.size > pages.length || budgetSignal.aborted
          || pages.some(page => page.truncated)
          || !!rejectionCounts.redirect_not_followed,
        observationErrors: errors,
        stopReason: budgetSignal.aborted ? 'duration_budget'
          : errors.length ? 'partial_observation' : queue.length ? 'request_budget'
            : pages.some(page => page.truncated) ? 'response_limit'
            : rejectionCounts.redirect_not_followed ? 'redirect_not_followed' : 'read_only_observation',
        startedAt: begunAt, completedAt: new Date().toISOString() };
      run.status = 'completed'; run.reviewItems = [];
      appendEvent({ stage: 'complete', title: '외부 대상 관찰 완료', detail: pages.length + '개 공개 페이지 관찰' });
    } catch (error) {
      run.status = controller.signal.aborted || signal?.aborted ? 'stopped' : 'failed';
      run.error = run.status === 'stopped' ? '사용자가 실행을 중지했습니다.'
        : safeText(error?.code ?? 'EXTERNAL_OBSERVATION_FAILED');
      appendEvent({ stage: 'external.failed', title: run.status === 'stopped' ? '외부 점검 중지' : '외부 점검 실패',
        type: 'error', detail: run.error });
    } finally {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
      run.totalSteps = Math.max(1, run.events.length);
      task = null; publish();
    }
  }
  function startLab(options = {}) {
    if (closed) throw fault(503, 'External runtime is closed.');
    if (task || ACTIVE.has(run.status)) throw fault(409, 'An external observation is already active.');
    if (!options || Object.keys(options).length) throw fault(400, 'External runtime accepts no additional options.');
    const id = assertIdentifier(runIdFactory(), 'runId');
    controller = new AbortController();
    run = { ...initial(), id, coreRunId: id, status: 'preparing', startedAt: new Date().toISOString() };
    task = Promise.resolve().then(runTask); publish(); return getState();
  }
  function stop(id) {
    if (!id || id !== run.id) throw fault(404, 'External observation not found.');
    if (ACTIVE.has(run.status)) { run.status = 'stopping'; controller.abort(); publish(); }
    return getState();
  }
  async function close() {
    closed = true;
    if (ACTIVE.has(run.status)) stop(run.id);
    await task; listeners.clear();
  }
  return { getState, startLab, stop, close, subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); } };
}
