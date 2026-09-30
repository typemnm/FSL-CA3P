'use strict';

const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { assertModuleSuccess, createEnvelope, invokeJson } = require('./protocol');
const { PentestDb } = require('./modules/pentest-db');
const { RuleReasoner } = require('./modules/rule-reasoner');
const { ScopeGuard } = require('./modules/scope-guard');
const { VulnerabilityDb } = require('./modules/vulnerability-db');
const { WebExplorer } = require('./modules/web-explorer');
const { consumeIsolatedLabCapability } = require('./target-harness');

function responseJson(response) {
  const body = response?.payload?.response?.bodyJson;
  if (!body || typeof body !== 'object') throw new Error('Expected a JSON HTTP response body');
  return body;
}

async function runOnce({
  harnessCapability,
  outputRoot,
  targetMode = 'isolated_local_lab',
  maxIterations = 1,
  knowledgeFile = path.join(__dirname, '..', 'knowledge', 'vulnerabilities.json'),
  fetchImpl = fetch,
}) {
  if (targetMode !== 'isolated_local_lab') throw new Error('MVP only supports an isolated local lab target');
  if (maxIterations !== 1) throw new Error('MVP requires maxIterations to equal 1');

  const { baseUrl } = consumeIsolatedLabCapability(harnessCapability);

  const runId = `run-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();
  const allowedOrigin = new URL(baseUrl).origin;
  const policyContext = {
    targetMode,
    allowedOrigin,
    maxIterations,
    rawChainOfThoughtStored: false,
  };

  const scopeGuard = new ScopeGuard({ allowedOrigin, maxRequests: 8 });
  const modules = {
    web_explorer: new WebExplorer({ baseUrl: allowedOrigin, scopeGuard, fetchImpl }),
    vulnerability_db: new VulnerabilityDb({ knowledgeFile }),
    rule_reasoner: new RuleReasoner(),
  };
  const pentestDb = new PentestDb({ outputRoot, runId });
  const progress = {
    iterationStarted: 0,
    actionAttempted: false,
    actionCompleted: false,
    verificationCompleted: false,
  };

  async function writeEvent(iteration, stage, request, response) {
    const storageRequest = createEnvelope({
      runId,
      iteration,
      sender: 'orchestrator',
      receiver: 'pentest_db',
      type: 'storage.request',
      payload: {
        operation: 'append',
        event: { stage, request, response },
      },
      policyContext,
    });
    assertModuleSuccess(await invokeJson(pentestDb, storageRequest));
  }

  async function callModule(moduleName, iteration, stage, payload, { onSuccess } = {}) {
    const request = createEnvelope({
      runId,
      iteration,
      sender: 'orchestrator',
      receiver: moduleName,
      type: 'module.request',
      payload,
      policyContext,
    });
    const response = await invokeJson(modules[moduleName], request);
    let successfulResponse;
    try {
      successfulResponse = assertModuleSuccess(response);
      if (onSuccess) onSuccess(successfulResponse);
    } catch (error) {
      await writeEvent(iteration, stage, request, response);
      throw error;
    }
    await writeEvent(iteration, stage, request, response);
    return successfulResponse;
  }

  async function finalize(report) {
    const request = createEnvelope({
      runId,
      iteration: report.iterations,
      sender: 'orchestrator',
      receiver: 'pentest_db',
      type: 'storage.request',
      payload: { operation: 'finalize', report },
      policyContext,
    });
    return assertModuleSuccess(await invokeJson(pentestDb, request));
  }

  try {
    const attackerSession = await callModule('web_explorer', 0, 'setup.attacker_session', {
      operation: 'http_request',
      session: 'attacker',
      method: 'GET',
      path: '/api/session',
    });
    const attacker = responseJson(attackerSession).user;
    if (attacker?.id !== 'alice') throw new Error('Expected the default attacker session to be Alice');

    const fixtureSession = await callModule('web_explorer', 0, 'setup.fixture_session', {
      operation: 'http_request',
      session: 'fixture',
      method: 'POST',
      path: '/api/session',
      body: { userId: 'bob' },
    });
    const owner = responseJson(fixtureSession).user;
    if (owner?.id !== 'bob') throw new Error('Expected the fixture owner session to be Bob');

    const canaryTitle = `agent-canary-${runId}`;
    const fixtureCreate = await callModule('web_explorer', 0, 'setup.canary_post', {
      operation: 'http_request',
      session: 'fixture',
      method: 'POST',
      path: '/api/posts',
      body: {
        title: canaryTitle,
        content: 'Isolated authorization-test canary. No real user data.',
      },
    });
    const fixturePost = responseJson(fixtureCreate).post;
    if (!fixturePost?.id || fixturePost.authorId !== owner.id) throw new Error('Failed to create Bob canary post');

    let reflection;
    for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
      progress.iterationStarted = iteration;
      const observation = await callModule('web_explorer', iteration, 'loop.observe', {
        operation: 'http_request',
        session: 'attacker',
        method: 'GET',
        path: '/api/posts',
      });
      const postsBefore = responseJson(observation).posts;
      const beforeExists = postsBefore.some(post => String(post.id) === String(fixturePost.id));

      const knowledge = await callModule('vulnerability_db', iteration, 'loop.knowledge', {
        operation: 'match',
        observation: {
          posts: postsBefore,
          resourceId: fixturePost.id,
          attackerId: attacker.id,
        },
      });

      const plan = await callModule('rule_reasoner', iteration, 'loop.think', {
        operation: 'plan',
        candidates: knowledge.payload.candidates,
      });
      if (plan.payload.state !== 'act' || !plan.payload.action) {
        throw new Error(`Reasoner stopped before action: ${plan.payload.decisionSummary}`);
      }

      progress.actionAttempted = true;
      const action = await callModule(
        'web_explorer',
        iteration,
        'loop.act',
        plan.payload.action,
        { onSuccess: () => { progress.actionCompleted = true; } },
      );
      const actionBody = responseJson(action);

      const verification = await callModule(
        'web_explorer',
        iteration,
        'loop.verify',
        {
          operation: 'http_request',
          session: 'attacker',
          method: 'GET',
          path: '/api/posts',
        },
        { onSuccess: () => { progress.verificationCompleted = true; } },
      );
      const postsAfter = responseJson(verification).posts;
      const afterExists = postsAfter.some(post => String(post.id) === String(fixturePost.id));

      reflection = await callModule('rule_reasoner', iteration, 'loop.reflect', {
        operation: 'reflect',
        target: plan.payload.target,
        knowledge: plan.payload.knowledge,
        before: { exists: beforeExists },
        actionResult: {
          status: action.payload.response.status,
          deletedId: actionBody.deletedId,
        },
        after: { exists: afterExists },
        evidenceRefs: [
          attackerSession.payload.evidenceId,
          fixtureSession.payload.evidenceId,
          fixtureCreate.payload.evidenceId,
          observation.payload.evidenceId,
          action.payload.evidenceId,
          verification.payload.evidenceId,
        ],
      });
    }

    const report = {
      schemaVersion: '1.0',
      runId,
      status: 'completed',
      target: { origin: allowedOrigin, mode: targetMode, application: 'vul-web-1' },
      iterations: maxIterations,
      progress,
      finding: reflection.payload.finding,
      metrics: {
        ...scopeGuard.metrics(),
        iterations: maxIterations,
      },
      safety: {
        exactOriginOnly: true,
        loopbackOnly: true,
        isolatedTemporaryData: true,
        cookiesPersisted: false,
        rawChainOfThoughtStored: false,
      },
      startedAt,
      completedAt: new Date().toISOString(),
    };
    const stored = await finalize(report);
    return {
      report,
      artifacts: stored.payload,
    };
  } catch (error) {
    const failureReport = {
      schemaVersion: '1.0',
      runId,
      status: 'failed',
      target: { origin: allowedOrigin, mode: targetMode, application: 'vul-web-1' },
      iterations: progress.iterationStarted,
      progress,
      error: { name: error.name, message: error.message },
      metrics: {
        ...scopeGuard.metrics(),
        iterations: progress.iterationStarted,
      },
      startedAt,
      completedAt: new Date().toISOString(),
    };
    try {
      await finalize(failureReport);
    } catch {
      // Preserve the original execution error if persistence also fails.
    }
    error.runId = runId;
    throw error;
  }
}

module.exports = { runOnce };
