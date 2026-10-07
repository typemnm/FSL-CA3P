'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { curlFromHttpAction } = require('./curl-command');
const { RuleReasoningEngine } = require('./reasoning-engine');
const { assertModuleSuccess, createEnvelope, invokeJson } = require('./protocol');
const { createStoredXssCanary } = require('./xss-canary');

const CANARY_CONTENT = 'Authorization-test canary requested by the agent.';
const BOLA_PROFILE = 'agent_cross_user_delete_canary';
const XSS_PROFILE = 'stored_xss_canary';

function localOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw new Error('Target must be an explicit local HTTP origin'); }
  if (typeof value !== 'string' || url.protocol !== 'http:'
    || url.hostname !== '127.0.0.1' || !url.port
    || value !== url.origin || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Target must be an explicit local HTTP origin');
  }
  return url.origin;
}

function responseJson(response) {
  const body = response?.payload?.response?.bodyJson;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('Expected a JSON HTTP response body');
  }
  return body;
}

function assertGateway(gateway) {
  if (!gateway || typeof gateway.exchange !== 'function') {
    throw new TypeError('runOnce requires gateway.exchange(serializedRequest)');
  }
}

function ensureCompleteParserResult(response) {
  const payload = response.payload;
  if (payload.truncated || payload.errors.length > 0) {
    const error = new Error('xss-parser observation is incomplete');
    error.code = 'XSS_PARSER_INCOMPLETE';
    error.source = 'external_module';
    error.externalModule = 'xss-parser';
    throw error;
  }
  return payload.observedPosts;
}

function findTrustedCanary(posts, fixturePost) {
  const id = String(fixturePost.id);
  const byId = posts.filter(post => post.id === id);
  const titleConflicts = posts.filter(post => post.title === fixturePost.title && post.id !== id);
  if (byId.length !== 1 || byId[0].title !== fixturePost.title || titleConflicts.length > 0) {
    throw new Error('xss-parser did not show the exact canary ID and title returned by fixture creation');
  }
}

function assertBoundDeleteAction(action, fixturePost, ownerId) {
  if (!action || typeof action !== 'object' || Array.isArray(action)
    || Object.keys(action).sort().join(',') !== 'method,operation,path,query,session'
    || action.operation !== 'http_request'
    || action.session !== 'attacker'
    || action.method !== 'DELETE'
    || action.path !== `/api/posts/${fixturePost.id}`
    || !action.query || typeof action.query !== 'object' || Array.isArray(action.query)
    || Object.keys(action.query).join(',') !== 'authorId'
    || action.query.authorId !== ownerId) {
    throw new Error('Reasoning action does not match the trusted local canary');
  }
}

function localCanaryCandidate({ fixturePost, ownerId, attackerId, parserEvidenceId, fixtureEvidenceId }) {
  return {
    knowledgeId: 'local-canary-cross-user-delete',
    cwe: 'CWE-639',
    severity: 'high',
    severityBasis: 'bounded_local_canary_hypothesis',
    attackerId,
    resource: { id: fixturePost.id, ownerId },
    actionTemplate: { method: 'DELETE', pathTemplate: '/api/posts/{resourceId}' },
    successCriteria: ['different users', '2xx deletion', 'resource absent from browser verification'],
    provenance: {
      source: 'agent_bound_local_canary',
      parserEvidenceId,
      fixtureEvidenceId,
    },
  };
}

function observedXssInput(report, origin) {
  return report.pages.some(page => {
    if (page.url !== `${origin}/`) return false;
    const formFields = (page.areas ?? []).flatMap(area => area.forms ?? [])
      .some(form => Array.isArray(form.fields)
        && ['title', 'content'].every(name => form.fields.some(field => field.name === name)));
    const postBehavior = (page.behaviors ?? []).some(behavior =>
      (behavior.api ?? []).some(api => api.method === 'POST'
        && api.url === `${origin}/api/posts`
        && Array.isArray(api.bodyKeys)
        && isDeepStrictEqual([...api.bodyKeys].sort(), ['content', 'title'])));
    const htmlSink = (page.renderRules ?? []).some(rule => rule.selector === '.post-content'
      && rule.operation === 'innerHTML' && rule.value === 'post.content');
    return formFields && postBehavior && htmlSink;
  });
}

function localXssCandidate({ report, origin, attackerId, marker, title, content,
  parserEvidenceId, catalog, catalogEvidenceId, historyEvidenceId }) {
  const advised = catalog?.vulnType === 'stored_xss'
    && catalog.target?.application === 'vul-web-1'
    && catalog.target?.endpoint === 'POST /api/posts'
    && catalog.payloads?.some(item => item.payloadId === 'img-onerror'
      && item.injectionPoint?.parameter === 'content'
      && item.injectionPoint?.sink === 'innerHTML'
      && item.successCheck?.method === 'browser');
  if (!observedXssInput(report, origin) || !advised) {
    throw new Error('The local XSS canary has no matching live parser input and catalog guidance');
  }
  return {
    knowledgeId: 'local-stored-xss-canary',
    cwe: 'CWE-79', severity: 'medium', severityBasis: 'bounded_local_browser_execution',
    attackerId, marker, title, content,
    actionTemplate: { method: 'POST', pathTemplate: '/api/posts' },
    successCriteria: ['canary post created', 'matching post visible', 'unique browser handler executed'],
    provenance: { source: 'parser_observed_local_input', parserEvidenceId,
      catalogEvidenceId, historyEvidenceId, advisoryPayloadId: 'img-onerror' },
  };
}

function assertBoundXssAction(action, title, content) {
  if (!action || typeof action !== 'object' || Array.isArray(action)
    || !isDeepStrictEqual(Object.keys(action).sort(), ['body', 'method', 'operation', 'path', 'session'])
    || action.operation !== 'http_request' || action.session !== 'attacker'
    || action.method !== 'POST' || action.path !== '/api/posts'
    || !isDeepStrictEqual(action.body, { title, content })) {
    throw new Error('Reasoning action does not match the trusted stored-XSS canary');
  }
}

async function runOnce({
  gateway,
  targetOrigin,
  targetMode = 'isolated_local_lab',
  targetApplication = 'external_target',
  maxIterations = 1,
  testProfile = BOLA_PROFILE,
  reasoningEngine = new RuleReasoningEngine(),
}) {
  if (targetMode !== 'isolated_local_lab') throw new Error('MVP only supports an isolated local lab target');
  if (maxIterations !== 1) throw new Error('MVP requires maxIterations to equal 1');
  if (![BOLA_PROFILE, XSS_PROFILE].includes(testProfile)) throw new Error('Unsupported local test profile');
  assertGateway(gateway);
  const allowedOrigin = localOrigin(targetOrigin);
  const runId = `run-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();
  const policyContext = {
    targetMode,
    targetOrigin: allowedOrigin,
    maxIterations,
    testProfile,
    rawChainOfThoughtStored: false,
  };
  const progress = {
    iterationStarted: 0,
    actionAttempted: false,
    actionCompleted: false,
    verificationCompleted: false,
  };
  const guardrailDecisions = [];
  const metrics = { requestCount: 0, parserRuns: 0, iterations: 0 };

  async function sendStorage(iteration, operation, payload) {
    const request = createEnvelope({
      runId,
      iteration,
      sender: 'agent',
      receiver: 'pentest-db',
      type: 'storage.request',
      payload: { operation, ...payload },
      policyContext,
    });
    return assertModuleSuccess(await invokeJson(gateway, request));
  }

  async function writeEvent(iteration, stage, request, response) {
    return sendStorage(iteration, 'append', { event: { stage, request, response } });
  }

  async function recordInternalEvent(iteration, stage, input, output) {
    JSON.stringify({ input, output });
    return sendStorage(iteration, 'append', {
      event: {
        stage,
        request: { sender: 'agent', operation: input.operation, payload: input },
        response: { sender: 'agent', payload: output },
      },
    });
  }

  async function callExternal(receiver, iteration, stage, payload, { onSuccess, requestType = 'module.request' } = {}) {
    const request = createEnvelope({
      runId,
      iteration,
      sender: 'agent',
      receiver,
      type: requestType,
      payload,
      policyContext,
    });
    if (receiver === 'attack-module') metrics.requestCount += 1;
    if (receiver === 'xss-parser') metrics.parserRuns += 1;
    const timeoutMs = receiver === 'xss-parser' ? 30_000 : receiver === 'casper-db' ? 15_000 : undefined;
    const response = await invokeJson(gateway, request, timeoutMs ? { timeoutMs } : {});
    let validated;
    try {
      validated = assertModuleSuccess(response);
      if (receiver === 'attack-module') {
        if (validated.payload.guardrail) guardrailDecisions.push(validated.payload.guardrail);
        if (validated.payload.success !== true) {
          const error = new Error(validated.payload.error
            || `Attack module request failed with HTTP ${validated.payload.response.status}`);
          error.code = validated.payload.guardrail?.decision === 'DENY'
            ? 'GUARDRAIL_DENIED' : 'ATTACK_MODULE_FAILURE';
          error.source = 'external_module';
          error.externalModule = 'attack-module';
          error.moduleResponse = validated;
          throw error;
        }
      }
      if (onSuccess) onSuccess(validated);
    } catch (error) {
      try { await writeEvent(iteration, stage, request, response); }
      catch (storageError) { error.eventStorageError = storageError; }
      throw error;
    }
    await writeEvent(iteration, stage, request, response);
    return validated;
  }

  function attackRequestFor(action, proposedCurl) {
    const expectedCurl = curlFromHttpAction(action, allowedOrigin);
    if (proposedCurl !== undefined && (!proposedCurl || typeof proposedCurl !== 'object'
      || Array.isArray(proposedCurl)
      || !isDeepStrictEqual(proposedCurl, expectedCurl))) {
      throw new Error('AI curl JSON does not match the trusted canary action');
    }
    return {
      operation: 'execute_curl',
      session: action.session,
      curl: proposedCurl === undefined ? expectedCurl : proposedCurl,
    };
  }

  async function finalize(report) {
    return sendStorage(report.iterations, 'finalize', { report });
  }

  try {
    const attackerSession = await callExternal('attack-module', 0, 'setup.attacker_session', attackRequestFor({
      operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/session',
    }));
    const attacker = responseJson(attackerSession).user;
    if (attacker?.id !== 'alice') throw new Error('Expected the default attacker session to be Alice');

    let fixtureSession;
    let fixtureCreate;
    let owner;
    let fixturePost;
    if (testProfile === BOLA_PROFILE) {
      fixtureSession = await callExternal('attack-module', 0, 'setup.fixture_session', attackRequestFor({
        operation: 'http_request', session: 'fixture', method: 'POST', path: '/api/session',
        body: { userId: 'bob' },
      }));
      owner = responseJson(fixtureSession).user;
      if (owner?.id !== 'bob') throw new Error('Expected the fixture owner session to be Bob');

      fixtureCreate = await callExternal('attack-module', 0, 'setup.canary_post', attackRequestFor({
        operation: 'http_request', session: 'fixture', method: 'POST', path: '/api/posts',
        body: { title: `agent-canary-${runId}`, content: CANARY_CONTENT },
      }));
      fixturePost = responseJson(fixtureCreate).post;
      if (!Number.isInteger(fixturePost?.id) || fixturePost.id <= 2
        || fixturePost.authorId !== owner.id
        || fixturePost.title !== `agent-canary-${runId}`) {
        throw new Error('Failed to obtain the trusted Bob canary fixture');
      }
    }

    let reflection;
    let historicalContext;
    let catalogContext;
    for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
      progress.iterationStarted = iteration;
      const observation = await callExternal('xss-parser', iteration, 'loop.observe', {
        operation: 'parse_site', origin: allowedOrigin, phase: 'before',
      });
      const postsBefore = ensureCompleteParserResult(observation);
      if (testProfile === BOLA_PROFILE) findTrustedCanary(postsBefore, fixturePost);

      const history = await callExternal('casper-db', iteration, 'loop.history', {
        operation: 'assess_xss_history', parserReport: observation.payload.report,
      });
      historicalContext = {
        category: 'historical_xss_only',
        assessments: history.payload.assessments.length,
        readyCaseCount: history.payload.readyCaseCount,
        evidenceId: history.payload.evidenceId,
      };

      const catalog = await callExternal('pentest-db', iteration, 'loop.catalog', {
        operation: 'get_attack_info',
        vulnType: 'stored_xss',
        target: { endpoint: 'POST /api/posts', parameter: 'content' },
      }, { requestType: 'storage.request' });
      catalogContext = {
        category: testProfile === XSS_PROFILE
          ? 'stored_xss_advisory_guidance' : 'stored_xss_reference_only',
        available: catalog.payload.attackInfo !== null,
        evidenceId: catalog.payload.evidenceId,
      };

      const xssCanary = testProfile === XSS_PROFILE ? createStoredXssCanary() : null;
      const xssTitle = xssCanary && `agent-xss-canary-${runId}-${xssCanary.marker}`;
      const candidate = testProfile === XSS_PROFILE
        ? localXssCandidate({
          report: observation.payload.report, origin: allowedOrigin,
          attackerId: attacker.id, marker: xssCanary.marker,
          title: xssTitle, content: xssCanary.content,
          parserEvidenceId: observation.payload.evidenceId,
          catalog: catalog.payload.attackInfo,
          catalogEvidenceId: catalog.payload.evidenceId,
          historyEvidenceId: history.payload.evidenceId,
        })
        : localCanaryCandidate({
          fixturePost,
          ownerId: owner.id,
          attackerId: attacker.id,
          parserEvidenceId: observation.payload.evidenceId,
          fixtureEvidenceId: fixtureCreate.payload.evidenceId,
        });
      const planInput = {
        operation: 'plan', testProfile,
        candidates: [candidate],
        expectedTarget: testProfile === XSS_PROFILE
          ? { marker: xssCanary.marker, title: xssTitle, content: xssCanary.content,
            attackerId: attacker.id }
          : { resourceId: fixturePost.id, ownerId: owner.id, attackerId: attacker.id },
        targetOrigin: allowedOrigin,
      };
      const plan = await reasoningEngine.plan(planInput);
      await recordInternalEvent(iteration, 'loop.think', planInput, plan);
      if (plan.state !== 'act' || !plan.action) {
        throw new Error(`Reasoning engine stopped before action: ${plan.decisionSummary}`);
      }
      if (testProfile === XSS_PROFILE) assertBoundXssAction(plan.action, xssTitle, xssCanary.content);
      else assertBoundDeleteAction(plan.action, fixturePost, owner.id);
      const attackPayload = attackRequestFor(plan.action, plan.curl);
      progress.actionAttempted = true;
      const action = await callExternal('attack-module', iteration, 'loop.act', attackPayload, {
        onSuccess: () => { progress.actionCompleted = true; },
      });
      const actionBody = responseJson(action);
      let verification;
      let reflectionInput;
      if (testProfile === XSS_PROFILE) {
        const post = actionBody.post;
        if (action.payload.response.status !== 201
          || !Number.isInteger(post?.id) || post.id <= 2
          || post.authorId !== attacker.id || post.title !== xssTitle
          || post.content !== xssCanary.content) {
          throw new Error('The local board did not return the exact stored-XSS canary post');
        }
        verification = await callExternal('xss-parser', iteration, 'loop.verify', {
          operation: 'verify_stored_xss', origin: allowedOrigin,
          postId: post.id, marker: xssCanary.marker,
        });
        progress.verificationCompleted = true;
        reflectionInput = {
          operation: 'reflect', testProfile, runId, targetOrigin: allowedOrigin,
          target: { marker: xssCanary.marker, title: xssTitle,
            attackerId: attacker.id, postId: post.id },
          knowledge: { id: candidate.knowledgeId, cwe: candidate.cwe,
            severity: candidate.severity, severityBasis: candidate.severityBasis,
            provenance: candidate.provenance },
          before: { inputObserved: true, sinkObserved: true },
          actionResult: { status: action.payload.response.status, postId: post.id },
          after: verification.payload.execution,
          evidenceRefs: [attackerSession.payload.evidenceId,
            observation.payload.evidenceId, history.payload.evidenceId,
            catalog.payload.evidenceId, action.payload.evidenceId,
            verification.payload.evidenceId],
        };
      } else {
        verification = await callExternal('xss-parser', iteration, 'loop.verify', {
          operation: 'parse_site', origin: allowedOrigin, phase: 'after',
        });
        const postsAfter = ensureCompleteParserResult(verification);
        progress.verificationCompleted = true;
        const afterExists = postsAfter.some(post => post.id === String(fixturePost.id)
          || post.title === fixturePost.title);
        reflectionInput = {
          operation: 'reflect', testProfile, runId,
          target: { resourceId: fixturePost.id, ownerId: owner.id, attackerId: attacker.id },
          knowledge: { id: candidate.knowledgeId, cwe: candidate.cwe,
            severity: candidate.severity, severityBasis: candidate.severityBasis,
            provenance: candidate.provenance },
          before: { exists: true },
          actionResult: { status: action.payload.response.status, deletedId: actionBody.deletedId },
          after: { exists: afterExists },
          evidenceRefs: [attackerSession.payload.evidenceId,
            fixtureSession.payload.evidenceId, fixtureCreate.payload.evidenceId,
            observation.payload.evidenceId, action.payload.evidenceId,
            verification.payload.evidenceId],
        };
      }
      reflection = await reasoningEngine.reflect(reflectionInput);
      await recordInternalEvent(iteration, 'loop.reflect', reflectionInput, reflection);
    }

    metrics.iterations = maxIterations;
    const report = {
      schemaVersion: '1.0',
      runId,
      status: 'completed',
      testProfile,
      target: { origin: allowedOrigin, mode: targetMode, application: targetApplication },
      iterations: maxIterations,
      progress,
      finding: reflection.finding,
      metrics,
      guardrail: { decisions: guardrailDecisions },
      referenceContext: { casperDb: historicalContext, pentestDb: catalogContext },
      safety: {
        externalJsonOnly: true,
        externalModulesImplementedByAgent: false,
        agentHandlesCookies: false,
        rawChainOfThoughtStored: false,
      },
      startedAt,
      completedAt: new Date().toISOString(),
    };
    const stored = await finalize(report);
    return { report, artifacts: stored.payload };
  } catch (error) {
    metrics.iterations = progress.iterationStarted;
    const failureReport = {
      schemaVersion: '1.0',
      runId,
      status: 'failed',
      testProfile,
      target: { origin: allowedOrigin, mode: targetMode, application: targetApplication },
      iterations: progress.iterationStarted,
      progress,
      error: {
        name: error.name,
        code: error.code || 'AGENT_FAILURE',
        source: error.source || 'agent',
        message: error.message,
      },
      metrics,
      guardrail: { decisions: guardrailDecisions },
      startedAt,
      completedAt: new Date().toISOString(),
    };
    error.runId = runId;
    error.failureReport = failureReport;
    try { await finalize(failureReport); }
    catch (storageError) { error.failureReportStorageError = storageError; }
    throw error;
  }
}

module.exports = { runOnce };
