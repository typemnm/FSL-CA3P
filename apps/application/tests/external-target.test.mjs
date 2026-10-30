import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRunService } from '../run-service.mjs';
import { createExternalRuntime } from '../external-runtime.mjs';
import { isPublicAddress, normalizeExternalTarget, preflightExternalTarget,
  requestExternalHttp, resolvePublicAddresses, verifyExternalPreflightToken } from '../external-target.mjs';

test('external addresses reject local, metadata, mapped, and documentation ranges', () => {
  for (const address of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.1.1',
    '100.64.0.1', '203.0.113.10', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1',
    '2001:db8::1']) assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});

test('external URL normalization binds an origin and a narrow path', async () => {
  assert.deepEqual(normalizeExternalTarget({ target: 'https://Example.COM/start#fragment',
    scope: { pathPrefix: '/start' } }), {
    normalizedUrl: 'https://example.com/start',
    scope: { origin: 'https://example.com', pathPrefix: '/start', methods: ['GET', 'HEAD'],
      maxRequests: 8, maxResponseBytes: 65536, requestTimeoutMs: 5000, maxDurationMs: 30000 },
  });
  assert.throws(() => normalizeExternalTarget('file:///etc/passwd'));
  assert.throws(() => normalizeExternalTarget('http://user:pass@example.com/'));
  assert.throws(() => normalizeExternalTarget('https://example.com/?token=private'));
  assert.throws(() => normalizeExternalTarget('https://example.com/?X-Amz-Credential=ACCESS&X-Amz-Signature=SECRET'));
  assert.throws(() => normalizeExternalTarget('https://example.com/?sig=AZURE&sp=r'));
  assert.throws(() => normalizeExternalTarget('https://example.com/?auth=private'));
  assert.throws(() => normalizeExternalTarget({ target: 'https://example.com/outside',
    scope: { pathPrefix: '/start' } }));
  assert.throws(() => normalizeExternalTarget({ target: 'https://example.com/',
    scope: { pathPrefix: '//internal.example/' } }));
  await assert.rejects(resolvePublicAddresses('public.test', { lookup: async () => [
    { address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 },
  ] }), { code: 'EXTERNAL_ADDRESS_BLOCKED' });
  const controller = new AbortController();
  const waitingDns = resolvePublicAddresses('public.test', { lookup: () => new Promise(() => {}),
    signal: controller.signal });
  controller.abort();
  await assert.rejects(waitingDns, { code: 'EXTERNAL_TIMEOUT' });
  await assert.rejects(requestExternalHttp('https://8.8.8.8/outside', {
    scope: normalizeExternalTarget({ target: 'https://8.8.8.8/start',
      scope: { pathPrefix: '/start' } }).scope,
  }), { code: 'EXTERNAL_SCOPE_BLOCKED' });
  await assert.rejects(requestExternalHttp('https://8.8.8.8/start/secret?session=private', {
    scope: normalizeExternalTarget({ target: 'https://8.8.8.8/start',
      scope: { pathPrefix: '/start' } }).scope,
  }), { code: 'EXTERNAL_SCOPE_BLOCKED' });
});

test('preflight binds the URL and scope and cannot authorize a changed target', async () => {
  const calls = [];
  const checked = await preflightExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } }, { request: async (url, options) => {
    calls.push([url, options.method]); return { status: 200 };
  } });
  assert.equal(checked.ready, true);
  assert.deepEqual(calls, [['https://8.8.8.8/start', 'HEAD']]);
  assert.equal(verifyExternalPreflightToken(checked.token, checked.normalizedUrl, checked.scope), true);
  assert.equal(verifyExternalPreflightToken(checked.token, 'https://8.8.8.8/other', checked.scope), false);
  assert.equal(verifyExternalPreflightToken(checked.token, checked.normalizedUrl,
    { ...checked.scope, pathPrefix: '/' }), false);
});

test('external runtime observes only in-scope public links and leaves findings unconfirmed', async () => {
  const requested = [];
  const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' }, runIdFactory: () => 'external-test',
    requestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 2, truncated: false,
        body: url.endsWith('/start') ? '<title>Start</title><a href="/start/child">child</a>'
          + '<a href="/start/signed?token=private">signed</a>'
          + '<a href="/outside">outside</a><a href="http://169.254.169.254/latest">metadata</a>' : '<title>Child</title>' };
    } });
  try {
    const completed = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('external runtime timeout')), 5000);
      const detach = runtime.subscribe(state => {
        if (['completed', 'failed', 'stopped'].includes(state.run.status)) {
          clearTimeout(timer); detach(); resolve(state.run);
        }
      });
    });
    runtime.startLab();
    const run = await completed;
    assert.equal(run.status, 'completed');
    assert.deepEqual(requested, ['https://8.8.8.8/start', 'https://8.8.8.8/start/child']);
    assert.equal(run.targetContacted, true);
    assert.equal(run.report.inspectionMode, 'external-read-only');
    assert.deepEqual(run.report.findings, []);
    assert.equal(run.report.inventory.pages.length, 2);
    assert.deepEqual(run.report.policyRejections, { total: 3, byReason: {
      credential_query: 1, out_of_scope_path: 1, out_of_scope_origin: 1,
    } });
    assert.equal(run.report.coverage.rejectedCandidates, 3);
    assert.deepEqual(run.events.filter(event => event.stage === 'scope.rejected')
      .map(event => event.policy.reason).sort(),
    ['credential_query', 'out_of_scope_origin', 'out_of_scope_path']);
    assert.equal(JSON.stringify(run).includes('token=private'), false);
    assert.equal(JSON.stringify(run).includes('169.254.169.254'), false);
  } finally { await runtime.close(); }
});

test('external runtime records redirects without following or persisting their locations', async () => {
  for (const [index, location, destinationReason] of [
    [1, '/start/next', 'in_scope'],
    [2, 'http://169.254.169.254/latest', 'out_of_scope_origin'],
    [3, '/start/next?token=redirect-secret', 'credential_query'],
  ]) {
    const requested = [];
    const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
      scope: { pathPrefix: '/start' }, runIdFactory: () => `external-redirect-${index}`,
      requestImpl: async url => {
        requested.push(url);
        return { status: 302, location, contentType: 'text/html', durationMs: 1,
          truncated: false, body: '<a href="/start/next">Continue</a>' };
      } });
    try {
      const completed = new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('external redirect timeout')), 5000);
        const detach = runtime.subscribe(state => {
          if (['completed', 'failed', 'stopped'].includes(state.run.status)) {
            clearTimeout(timer); detach(); resolve(state.run);
          }
        });
      });
      runtime.startLab();
      const run = await completed;
      assert.equal(run.status, 'completed');
      assert.deepEqual(requested, ['https://8.8.8.8/start']);
      assert.equal(run.report.policyRejections.byReason.redirect_not_followed, 1);
      assert.equal(run.report.coverage.rejectedCandidates, 1);
      assert.equal(run.report.partial, true);
      assert.equal(run.report.stopReason, 'redirect_not_followed');
      const event = run.events.find(row => row.stage === 'scope.rejected');
      assert.equal(event.policy.reason, 'redirect_not_followed');
      assert.equal(event.policy.destinationReason, destinationReason);
      assert.equal(JSON.stringify(run).includes(location), false);
      assert.equal(JSON.stringify(run).includes('redirect-secret'), false);
    } finally { await runtime.close(); }
  }
});

test('discovered signed query links are rejected while the preflighted entry query is retained', async () => {
  const entry = 'https://8.8.8.8/start?view=public';
  const requested = [];
  const runtime = createExternalRuntime({ targetUrl: entry, scope: { pathPrefix: '/start' },
    runIdFactory: () => 'external-signed-links', requestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1, truncated: false,
        body: url === entry ? '<a href="/start/aws?X-Amz-Credential=aws-secret&X-Amz-Signature=signature">AWS</a>'
          + '<a href="/start/azure?sig=azure-secret&sp=r">Azure</a>'
          + '<a href="/start/ordinary?sort=asc">ordinary</a>'
          + '<a href="/start/child">child</a>' : '<title>Child</title>' };
    } });
  try {
    const completed = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('external signed-link timeout')), 5000);
      const detach = runtime.subscribe(state => {
        if (['completed', 'failed', 'stopped'].includes(state.run.status)) {
          clearTimeout(timer); detach(); resolve(state.run);
        }
      });
    });
    runtime.startLab();
    const run = await completed;
    assert.equal(run.status, 'completed');
    assert.deepEqual(requested, [entry, 'https://8.8.8.8/start/child']);
    assert.deepEqual(run.report.policyRejections, { total: 3, byReason: { credential_query: 2, query_link: 1 } });
    assert.equal(run.events.find(event => event.policy?.reason === 'credential_query')?.policy.count, 2);
    assert.equal(JSON.stringify(run).includes('aws-secret'), false);
    assert.equal(JSON.stringify(run).includes('azure-secret'), false);
    assert.equal(JSON.stringify(run).includes('signature'), false);
  } finally { await runtime.close(); }
});

test('compressed and truncated external responses are not reported as complete observations', async () => {
  for (const [name, response, status, reason] of [
    ['compressed', { status: 200, contentType: 'text/html', contentEncoding: 'gzip', body: 'opaque' },
      'completed', 'partial_observation'],
    ['truncated', { status: 200, contentType: 'text/html', truncated: true, body: '<title>Partial</title>' },
      'completed', 'response_limit'],
  ]) {
    const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
      runIdFactory: () => `external-${name}`, requestImpl: async () => response });
    try {
      const completed = new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('external response timeout')), 5000);
        const detach = runtime.subscribe(state => {
          if (['completed', 'failed', 'stopped'].includes(state.run.status)) {
            clearTimeout(timer); detach(); resolve(state.run);
          }
        });
      });
      runtime.startLab();
      const run = await completed;
      assert.equal(run.status, status);
      if (status === 'completed') {
        assert.equal(run.report.partial, true);
        assert.equal(run.report.stopReason, reason);
        if (name === 'compressed') {
          assert.equal(run.report.observationErrors[0].code, 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED');
          assert.equal(run.report.coverage.observedPages, 0);
        }
      } else assert.equal(run.error, reason);
    } finally { await runtime.close(); }
  }
});

test('run service persists an external run only after bound preflight and confirmation', async () => {
  const checked = await preflightExternalTarget({ target: 'https://8.8.8.8/start' },
    { request: async () => ({ status: 200 }) });
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-external-'));
  const service = createRunService({ storePath: join(directory, 'runs.sqlite3'),
    autoStartWorker: false, importLegacy: false, envFile: null,
    env: { DEEPSEEK_API_KEY: 'test-key' } });
  try {
    const body = { mode: 'external-general',
      target: checked.normalizedUrl, scope: { pathPrefix: '/' },
      preflightToken: checked.token, authorizationConfirmed: true };
    assert.equal(service.getState().lab.externalAvailable, true);
    assert.equal(service.getState().lab.models.find(model => model.id === 'deepseek-flash')
      .supportedModes.includes('external-general'), true);
    await assert.rejects(service.start({ ...body, authorizationConfirmed: false }), { status: 400 });
    await assert.rejects(service.start({ ...body, target: 'https://8.8.8.8/changed' }), { status: 400 });
    await assert.rejects(service.start({ ...body, modelId: 'rule-baseline' }), { status: 400 });
    const state = await service.start(body);
    assert.equal(state.run.mode, 'external-general');
    assert.equal(state.run.modelId, 'deepseek-flash');
    assert.equal(state.run.testProfile, 'external-general');
    assert.equal(state.run.manifest.target.kind, 'external');
    assert.equal(state.run.manifest.policy.methods[0], 'GET');
    assert.equal(state.run.manifest.model.provider, 'deepseek');
    assert.deepEqual(state.run.manifest.execution.loopBudget, service.getGeneralLoopBudget());
    assert.equal(service.getRun(state.run.id).target, checked.normalizedUrl);
    const lease = service.store.claimNext('external-options-test');
    assert.equal(lease.options.testProfile, 'external-general');
    assert.deepEqual(lease.options.loopBudget, service.getGeneralLoopBudget());
    assert.equal(lease.options.caseSnapshot, undefined);
    service.store.finish(lease, 'completed');
  } finally { await service.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('external general assessment requires a configured model before queueing', async () => {
  const checked = await preflightExternalTarget({ target: 'https://8.8.8.8/start' },
    { request: async () => ({ status: 200 }) });
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-external-model-'));
  const service = createRunService({ storePath: join(directory, 'runs.sqlite3'),
    autoStartWorker: false, importLegacy: false, envFile: null, env: { DEEPSEEK_API_KEY: '' } });
  try {
    assert.equal(service.getState().lab.externalAvailable, false);
    await assert.rejects(service.start({ mode: 'external-general', target: checked.normalizedUrl,
      scope: { pathPrefix: '/' }, preflightToken: checked.token,
      authorizationConfirmed: true }), { status: 503 });
    assert.equal(service.store.listRuns({ limit: 1 }).total, 0);
  } finally { await service.close(); rmSync(directory, { recursive: true, force: true }); }
});
