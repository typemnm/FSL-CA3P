'use strict';

const { randomUUID } = require('node:crypto');
const { ActionPolicy } = require('./action-policy');
const { RuleReasoningEngine } = require('./reasoning-engine');
const { assertModuleSuccess, createEnvelope, invokeJson } = require('./protocol');

function responseJson(response) {
  const body = response?.payload?.response?.bodyJson;
  if (!body || typeof body !== 'object') throw new Error('Expected a JSON HTTP response body');
  return body;
}

function assertGateway(gateway) {
  if (!gateway || typeof gateway.exchange !== 'function') {
    throw new TypeError('runOnce requires gateway.exchange(serializedRequest)');
  }
}

async function runOnce({
  gateway,
  targetOrigin,
  targetMode = 'isolated_local_lab',
  targetApplication = 'external_target',
  maxIterations = 1,
  reasoningEngine = new RuleReasoningEngine(),
}) {
  if (targetMode !== 'isolated_local_lab') throw new Error('MVP only supports an isolated local lab target');
  if (maxIterations !== 1) throw new Error('MVP requires maxIterations to equal 1');
  assertGateway(gateway);

  const actionPolicy = new ActionPolicy({ targetOrigin, maxRequests: 8 });
  const allowedOrigin = actionPolicy.allowed.origin;
  const runId = `run-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();
  const policyContext = {
    targetMode,
    targetOrigin: allowedOrigin,
    maxIterations,
    rawChainOfThoughtStored: false,
  };
  const progress = {
    iterationStarted: 0,
    actionAttempted: false,
    actionCompleted: false,
    verificationCompleted: false,
  };

  async function sendStorage(iteration, operation, payload) {
    const request = createEnvelope({
      runId,
      iteration,
      sender: 'agent',
      receiver: 'pentest_db',
      type: 'storage.request',
      payload: { operation, ...payload },
      policyContext,
    });
    return assertModuleSuccess(await invokeJson(gateway, request));
  }

  async function writeEvent(iteration, stage, request, response) {
    return sendStorage(iteration, 'append', {
      event: { stage, request, response },
    });
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

  async function callExternal(receiver, iteration, stage, payload, { onSuccess } = {}) {
    if (receiver === 'web_explorer') actionPolicy.authorize(stage, payload);
    const request = createEnvelope({
      runId,
      iteration,
      sender: 'agent',
      receiver,
      type: 'module.request',
      payload,
      policyContext,
    });
    const response = await invokeJson(gateway, request);

    let successfulResponse;
    try {
      successfulResponse = assertModuleSuccess(response);
      if (onSuccess) onSuccess(successfulResponse);
    } catch (error) {
      try {
        await writeEvent(iteration, stage, request, response);
      } catch (storageError) {
        error.eventStorageError = storageError;
      }
      throw error;
    }

    await writeEvent(iteration, stage, request, response);
    return successfulResponse;
  }

  async function finalize(report) {
    return sendStorage(report.iterations, 'finalize', { report });
  }

  try {
    const attackerSession = await callExternal('web_explorer', 0, 'setup.attacker_session', {
      operation: 'http_request',
      session: 'attacker',
      method: 'GET',
      path: '/api/session',
    });
    const attacker = responseJson(attackerSession).user;
    if (attacker?.id !== 'alice') throw new Error('Expected the default attacker session to be Alice');

    const fixtureSession = await callExternal('web_explorer', 0, 'setup.fixture_session', {
      operation: 'http_request',
      session: 'fixture',
      method: 'POST',
      path: '/api/session',
      body: { userId: 'bob' },
    });
    const owner = responseJson(fixtureSession).user;
    if (owner?.id !== 'bob') throw new Error('Expected the fixture owner session to be Bob');

    const fixtureCreate = await callExternal('web_explorer', 0, 'setup.canary_post', {
      operation: 'http_request',
      session: 'fixture',
      method: 'POST',
      path: '/api/posts',
      body: {
        title: `agent-canary-${runId}`,
        content: 'Authorization-test canary requested by the agent.',
      },
    });
    const fixturePost = responseJson(fixtureCreate).post;
    if (!fixturePost?.id || fixturePost.authorId !== owner.id) throw new Error('Failed to obtain the Bob canary fixture');
    actionPolicy.bindDeleteTarget({ resourceId: fixturePost.id, ownerId: owner.id });

    let reflection;
    for (let iteration = 1; iteration <= maxIterations; iteration += 1) {
      progress.iterationStarted = iteration;
      const observation = await callExternal('web_explorer', iteration, 'loop.observe', {
        operation: 'http_request',
        session: 'attacker',
        method: 'GET',
        path: '/api/posts',
      });
      const postsBefore = responseJson(observation).posts;
      const beforeExists = postsBefore.some(post => String(post.id) === String(fixturePost.id));

      const knowledge = await callExternal('vulnerability_db', iteration, 'loop.knowledge', {
        operation: 'match',
        observation: {
          posts: postsBefore,
          resourceId: fixturePost.id,
          attackerId: attacker.id,
        },
      });

      const planInput = {
        operation: 'plan',
        candidates: knowledge.payload.candidates,
        expectedTarget: {
          resourceId: fixturePost.id,
          ownerId: owner.id,
          attackerId: attacker.id,
        },
      };
      const plan = reasoningEngine.plan(planInput);
      await recordInternalEvent(iteration, 'loop.think', planInput, plan);
      if (plan.state !== 'act' || !plan.action) {
        throw new Error(`Reasoning engine stopped before action: ${plan.decisionSummary}`);
      }

      progress.actionAttempted = true;
      const action = await callExternal(
        'web_explorer',
        iteration,
        'loop.act',
        plan.action,
        { onSuccess: () => { progress.actionCompleted = true; } },
      );
      const actionBody = responseJson(action);

      const verification = await callExternal(
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

      const reflectionInput = {
        operation: 'reflect',
        runId,
        target: plan.target,
        knowledge: plan.knowledge,
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
      };
      reflection = reasoningEngine.reflect(reflectionInput);
      await recordInternalEvent(iteration, 'loop.reflect', reflectionInput, reflection);
    }

    const report = {
      schemaVersion: '1.0',
      runId,
      status: 'completed',
      target: { origin: allowedOrigin, mode: targetMode, application: targetApplication },
      iterations: maxIterations,
      progress,
      finding: reflection.finding,
      metrics: { ...actionPolicy.metrics(), iterations: maxIterations },
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
    const failureReport = {
      schemaVersion: '1.0',
      runId,
      status: 'failed',
      target: { origin: allowedOrigin, mode: targetMode, application: targetApplication },
      iterations: progress.iterationStarted,
      progress,
      error: {
        name: error.name,
        code: error.code || 'AGENT_FAILURE',
        source: error.source || 'agent',
        message: error.message,
      },
      metrics: { ...actionPolicy.metrics(), iterations: progress.iterationStarted },
      startedAt,
      completedAt: new Date().toISOString(),
    };
    error.runId = runId;
    error.failureReport = failureReport;
    try {
      await finalize(failureReport);
    } catch (storageError) {
      error.failureReportStorageError = storageError;
    }
    throw error;
  }
}

module.exports = { runOnce };
