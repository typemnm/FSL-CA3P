'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createEnvelope, invokeJson, parseEnvelope } = require('../src/protocol');
const { runOnce } = require('../src/orchestrator');
const { ScopeGuard } = require('../src/modules/scope-guard');
const { WebExplorer } = require('../src/modules/web-explorer');
const { startIsolatedLab, withIsolatedLab } = require('../src/target-harness');

async function snapshot(file) {
  try {
    return await fs.readFile(file);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

test('one JSON reasoning loop confirms cross-user deletion in an isolated lab', async () => {
  const originalData = path.resolve(__dirname, '..', '..', 'vul-web-1', 'data', 'posts.json');
  const originalBefore = await snapshot(originalData);
  const outputRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ca3p-agent-output-'));
  let target;

  try {
    target = await startIsolatedLab();
    assert.notEqual(new URL(target.baseUrl).port, '0', 'The child must report its OS-assigned port');
    const result = await runOnce({
      harnessCapability: target.capability,
      outputRoot,
      targetMode: 'isolated_local_lab',
      maxIterations: 1,
    });

    assert.equal(result.report.status, 'completed');
    assert.equal(result.report.iterations, 1);
    assert.deepEqual(result.report.progress, {
      iterationStarted: 1,
      actionAttempted: true,
      actionCompleted: true,
      verificationCompleted: true,
    });
    assert.equal(result.report.finding.status, 'confirmed');
    assert.equal(result.report.finding.actorId, 'alice');
    assert.equal(result.report.finding.ownerId, 'bob');
    assert.deepEqual(result.report.finding.checks, {
      differentUsers: true,
      existedBefore: true,
      deleteAccepted: true,
      absentAfter: true,
    });
    assert.equal(result.report.metrics.requestCount, 6);
    assert.equal(result.report.finding.evidenceRefs.length, 6);

    const storedReport = JSON.parse(await fs.readFile(result.artifacts.reportFile, 'utf8'));
    assert.equal(storedReport.runId, result.report.runId);
    const eventLines = (await fs.readFile(result.artifacts.eventsFile, 'utf8')).trim().split('\n');
    assert.equal(eventLines.length, 9);
    eventLines.forEach(line => JSON.parse(line));

    const persistedText = `${await fs.readFile(result.artifacts.eventsFile, 'utf8')}\n${JSON.stringify(storedReport)}`;
    assert.equal(persistedText.includes('board_user='), false, 'Cookies must never be persisted');
  } finally {
    if (target) await target.stop();
    await fs.rm(outputRoot, { recursive: true, force: true });
  }

  assert.ok(target, 'The isolated target must have started');
  await assert.rejects(
    () => fs.stat(target.tempDir),
    error => error.code === 'ENOENT',
    'The isolated target directory must be removed',
  );
  assert.ok(
    target.child.exitCode !== null || target.child.signalCode !== null,
    'The isolated target process must be stopped',
  );

  const originalAfter = await snapshot(originalData);
  if (originalBefore === null) {
    assert.equal(originalAfter, null, 'The original site data file must not be created');
  } else {
    assert.deepEqual(originalAfter, originalBefore, 'The original site data file must not change');
  }
});

test('isolated harness stops the process and removes temp data when its task fails', async () => {
  let captured;
  await assert.rejects(
    () => withIsolatedLab(async target => {
      captured = target;
      throw new Error('deliberate task failure');
    }),
    /deliberate task failure/,
  );
  assert.ok(captured);
  assert.ok(captured.child.exitCode !== null || captured.child.signalCode !== null);
  await assert.rejects(() => fs.stat(captured.tempDir), error => error.code === 'ENOENT');
});

test('scope guard returns a JSON error envelope for a different origin', async () => {
  const guard = new ScopeGuard({ allowedOrigin: 'http://127.0.0.1:3000' });
  const request = createEnvelope({
    runId: 'run-test',
    iteration: 0,
    sender: 'web_explorer',
    receiver: 'scope_guard',
    type: 'scope.request',
    payload: {
      operation: 'authorize_http',
      method: 'GET',
      url: 'http://127.0.0.1:3001/api/posts',
    },
    policyContext: { targetMode: 'isolated_local_lab' },
  });
  const response = await invokeJson(guard, request);
  assert.equal(response.type, 'module.error');
  assert.match(response.payload.error.message, /outside the exact allowed scope/);
  assert.equal(response.correlationId, request.messageId);
  assert.equal(guard.metrics().requestCount, 0);
});

test('scope guard rejects non-allowlisted paths and enforces its request budget', async () => {
  const guard = new ScopeGuard({ allowedOrigin: 'http://127.0.0.1:3000', maxRequests: 1 });
  const requestFor = url => createEnvelope({
    runId: 'run-guard',
    iteration: 0,
    sender: 'web_explorer',
    receiver: 'scope_guard',
    type: 'scope.request',
    payload: { operation: 'authorize_http', method: 'GET', url },
    policyContext: { targetMode: 'isolated_local_lab' },
  });

  const badPath = await invokeJson(guard, requestFor('http://127.0.0.1:3000/admin'));
  assert.equal(badPath.type, 'module.error');
  assert.equal(guard.metrics().requestCount, 0);

  const allowed = await invokeJson(guard, requestFor('http://127.0.0.1:3000/api/posts'));
  assert.equal(allowed.type, 'scope.authorized');
  const overBudget = await invokeJson(guard, requestFor('http://127.0.0.1:3000/api/posts'));
  assert.equal(overBudget.type, 'module.error');
  assert.match(overBudget.payload.error.message, /budget exhausted/);
  assert.equal(guard.metrics().requestCount, 1);
});

test('scope guard rejects non-allowlisted methods and malformed DELETE queries', async () => {
  const guard = new ScopeGuard({ allowedOrigin: 'http://127.0.0.1:3000' });
  const requestFor = (method, url) => createEnvelope({
    runId: 'run-guard-method',
    iteration: 0,
    sender: 'web_explorer',
    receiver: 'scope_guard',
    type: 'scope.request',
    payload: { operation: 'authorize_http', method, url },
    policyContext: { targetMode: 'isolated_local_lab' },
  });

  const patch = await invokeJson(
    guard,
    requestFor('PATCH', 'http://127.0.0.1:3000/api/posts/1'),
  );
  assert.equal(patch.type, 'module.error');
  assert.match(patch.payload.error.message, /not allowlisted/);

  const missingAuthor = await invokeJson(
    guard,
    requestFor('DELETE', 'http://127.0.0.1:3000/api/posts/1'),
  );
  assert.equal(missingAuthor.type, 'module.error');
  assert.match(missingAuthor.payload.error.message, /exactly one non-empty authorId/);

  const extraQuery = await invokeJson(
    guard,
    requestFor('DELETE', 'http://127.0.0.1:3000/api/posts/1?authorId=bob&force=1'),
  );
  assert.equal(extraQuery.type, 'module.error');
  assert.equal(guard.metrics().requestCount, 0);
});

test('web explorer never calls fetch when scope guard rejects the target', async () => {
  let fetchCalls = 0;
  const guard = new ScopeGuard({ allowedOrigin: 'http://127.0.0.1:3000' });
  const explorer = new WebExplorer({
    baseUrl: 'http://127.0.0.1:3000',
    scopeGuard: guard,
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error('fetch must not run');
    },
  });
  const request = createEnvelope({
    runId: 'run-web-scope',
    iteration: 0,
    sender: 'orchestrator',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: {
      operation: 'http_request',
      method: 'GET',
      path: 'http://127.0.0.1:3001/api/posts',
    },
  });
  const response = await invokeJson(explorer, request);
  assert.equal(response.type, 'module.error');
  assert.match(response.payload.error.message, /outside the exact allowed scope/);
  assert.equal(fetchCalls, 0);
});

test('web explorer stops reading a streamed response above the 1 MB limit', async () => {
  const guard = new ScopeGuard({ allowedOrigin: 'http://127.0.0.1:3000' });
  const oversizedStream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(600_000));
      controller.enqueue(new Uint8Array(500_001));
    },
  });
  const explorer = new WebExplorer({
    baseUrl: 'http://127.0.0.1:3000',
    scopeGuard: guard,
    fetchImpl: async () => new Response(oversizedStream, {
      status: 200,
      headers: { 'content-type': 'application/octet-stream' },
    }),
  });
  const request = createEnvelope({
    runId: 'run-web-limit',
    iteration: 0,
    sender: 'orchestrator',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'http_request', method: 'GET', path: '/api/posts' },
  });
  const response = await invokeJson(explorer, request);
  assert.equal(response.type, 'module.error');
  assert.match(response.payload.error.message, /exceeded the 1 MB lab limit/);
  assert.equal(guard.metrics().requestCount, 1);
});

test('invalid module output is normalized to a correlated JSON error envelope', async () => {
  const request = createEnvelope({
    runId: 'run-invalid-module',
    iteration: 0,
    sender: 'orchestrator',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'noop' },
  });
  const response = await invokeJson({ handle: async () => '{"not":"an envelope"}' }, request);
  assert.equal(response.type, 'module.error');
  assert.equal(response.correlationId, request.messageId);
  assert.equal(response.payload.error.retryable, false);
});

test('orchestrator refuses more than one reasoning iteration', async () => {
  await assert.rejects(
    () => runOnce({
      outputRoot: os.tmpdir(),
      maxIterations: 2,
    }),
    /maxIterations to equal 1/,
  );
});

test('orchestrator rejects a forged or stopped isolated-lab capability', async () => {
  await assert.rejects(
    () => runOnce({
      harnessCapability: Object.freeze({}),
      outputRoot: os.tmpdir(),
    }),
    /live isolated-lab capability/,
  );

  const target = await startIsolatedLab();
  await target.stop();
  await assert.rejects(
    () => runOnce({ harnessCapability: target.capability, outputRoot: os.tmpdir() }),
    /live isolated-lab capability|no longer active/,
  );
});

test('isolated-lab capabilities are single-use', async () => {
  const outputRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ca3p-agent-once-output-'));
  const target = await startIsolatedLab();
  try {
    await runOnce({ harnessCapability: target.capability, outputRoot });
    await assert.rejects(
      () => runOnce({ harnessCapability: target.capability, outputRoot }),
      /live isolated-lab capability/,
    );
  } finally {
    await target.stop();
    await fs.rm(outputRoot, { recursive: true, force: true });
  }
});

test('failure after the DELETE records the action and the started iteration', async () => {
  const outputRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ca3p-agent-failure-output-'));
  const target = await startIsolatedLab();
  const realFetch = global.fetch;
  let deleteCompleted = false;
  let failedRunId;

  const failingFetch = async (url, options = {}) => {
    const method = String(options.method || 'GET').toUpperCase();
    if (deleteCompleted && method === 'GET' && String(url).endsWith('/api/posts')) {
      throw new Error('forced verification failure after action');
    }
    const response = await realFetch(url, options);
    if (method === 'DELETE') deleteCompleted = true;
    return response;
  };

  try {
    await assert.rejects(
      async () => {
        try {
          await runOnce({
            harnessCapability: target.capability,
            outputRoot,
            fetchImpl: failingFetch,
          });
        } catch (error) {
          failedRunId = error.runId;
          throw error;
        }
      },
      /forced verification failure after action/,
    );

    assert.ok(failedRunId);
    const failureReport = JSON.parse(
      await fs.readFile(path.join(outputRoot, failedRunId, 'report.json'), 'utf8'),
    );
    assert.equal(failureReport.status, 'failed');
    assert.equal(failureReport.iterations, 1);
    assert.deepEqual(failureReport.progress, {
      iterationStarted: 1,
      actionAttempted: true,
      actionCompleted: true,
      verificationCompleted: false,
    });
    assert.equal(failureReport.metrics.iterations, 1);

    const persistedTarget = JSON.parse(await fs.readFile(target.dataFile, 'utf8'));
    assert.equal(
      persistedTarget.posts.some(post => post.title === `agent-canary-${failedRunId}`),
      false,
      'The failure report must not hide that the DELETE changed the target',
    );
  } finally {
    await target.stop();
    await fs.rm(outputRoot, { recursive: true, force: true });
  }
});

test('module boundary rejects non-serialized input', () => {
  assert.throws(() => parseEnvelope({}, 'web_explorer'), /serialized JSON only/);
});
