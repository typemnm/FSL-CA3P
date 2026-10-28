import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGeneralRuntime } from '../general-runtime.mjs';
import plannerModule from '../../../agent/src/general-model-planner.js';
import { readKnowledgeCatalog } from '../../../packages/adapters/integrations/knowledge-db.mjs';

function terminal(runtime) {
  return new Promise(resolve => {
    const detach = runtime.subscribe(({ run }) => {
      if (['completed', 'failed', 'stopped'].includes(run.status)) {
        detach(); resolve(run);
      }
    });
  });
}

function response(path) {
  if (path === '/api/search') return new Response(JSON.stringify({ site: '대한대학교', results: [] }), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  return new Response('<html><title>대한대학교</title><a href="/about">About</a><form action="/api/search" method="get"></form></html>', {
    status: path === '/api/admissions/partner/applications/1' ? 403 : 200,
    headers: { 'content-type': 'text/html', 'x-content-type-options': 'nosniff' },
  });
}

const confirmedIdor = () => ({ finding: { status: 'confirmed' }, evidence: [
  { check: 'firstOwner', recordId: 1, status: 200, ownerId: 4 },
  { check: 'secondOwner', recordId: 3, status: 200, ownerId: 5 },
  { check: 'crossOwner', recordId: 3, status: 200, ownerId: 5 },
  { check: 'studentRole', recordId: 3, status: 403, ownerId: null },
] });

test('general university run uses multiple model hypotheses and confirms only the guarded role comparison', async () => {
  const calls = [];
  const modelCalls = [];
  const hooks = [];
  let liveVerify;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'general-university-test',
    unavailableInputs: ['casper-db'],
    catalogReader: async () => { throw new Error('catalog must not read the shared database without a snapshot'); },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), method: init.method });
      return response(new URL(url).pathname);
    },
    beforeProbe: async probe => { hooks.push(probe); },
    onModelCall: async call => { modelCalls.push(call); },
    historyProvider: async () => [{ runId: 'prior', status: 'completed',
      findings: [{ category: 'access_control', status: 'confirmed', asset: '/old' }] }],
    plannerFactory: () => ({ async propose(context) {
      assert.equal(context.inventory.referenceSources.some(item =>
        item.source === 'run-store/previous-runs' && item.status === 'available'), true);
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
      const id = context.evidence[0].id;
      return { done: false, hypotheses: [
        { id: 'h-idor', category: 'access_control', asset: '/api/admissions/partner/applications/:id',
          rationale: 'Role boundary should be compared. event-private-marker',
          evidenceIds: [id] },
        { id: 'h-xss', category: 'xss', asset: '/api/search?token=event-private-asset',
          rationale: 'A query input exists but no browser verifier is connected.',
          evidenceIds: [id], secret: 'event-private-extra' },
      ], probes: [{ id: 'p-idor', hypothesisId: 'h-idor', tool: 'known_record_idor_read', input: {} }],
      modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
    } }),
    idorProbe: async () => confirmedIdor(),
  });
  const detach = runtime.subscribe(({ run }) => {
    const event = run.events.find(item => item.stage === 'verify' && item.request?.probeId === 'p-idor');
    if (event && !run.report) liveVerify = { event, events: run.events };
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(run.report.schemaVersion, 'general-assessment/1');
  assert.equal(run.report.assessmentMode, 'general');
  assert.equal(run.report.findings.find(item => item.hypothesisId === 'h-idor').status, 'confirmed');
  assert.equal(run.report.findings.find(item => item.hypothesisId === 'h-xss').status, 'not_tested');
  assert.equal(run.report.modelCalls.length, 2);
  assert.equal(modelCalls.length, 2);
  assert.ok(calls.length >= 4);
  assert.ok(calls.every(item => item.url.startsWith('http://127.0.0.1:4101/')));
  assert.ok(hooks.every(item => item.method === 'GET'
    || item.method === 'POST' && new URL(item.url).pathname === '/login'));
  assert.ok(run.report.inventory.referenceSources.some(item => item.source === 'run-store/previous-runs'));
  assert.ok(run.report.inventory.referenceSources.some(item =>
    item.source === 'casper-db/attack-catalog' && item.status === 'unavailable'
      && item.reason === 'snapshot_unavailable'));
  assert.ok(liveVerify, 'the verify event is published before the final report');
  const plan = liveVerify.events.find(item => item.stage === 'plan');
  assert.deepEqual(plan.request.hypothesisIds, ['h-idor', 'h-xss']);
  assert.deepEqual(plan.request.probeLinks, [
    { probeId: 'p-idor', hypothesisId: 'h-idor', tool: 'known_record_idor_read' },
  ]);
  assert.deepEqual(plan.request.hypothesisSummaries, [
    { id: 'h-idor', category: 'access_control',
      asset: '/api/admissions/partner/applications/:id' },
    { id: 'h-xss', category: 'xss', asset: '/api/search' },
  ]);
  const observed = liveVerify.events.find(item => item.stage === 'observe');
  assert.ok(observed.response.evidenceSummaries.length > 0);
  assert.ok(observed.response.evidenceSummaries.every(item =>
    Object.keys(item).every(key => ['id', 'kind', 'asset'].includes(key))));
  const executed = liveVerify.events.find(item => item.stage === 'execute'
    && item.request?.probeId === 'p-idor');
  const probeEvidenceId = run.report.probes.find(item => item.id === 'p-idor').evidenceIds[0];
  assert.deepEqual(executed.response.evidenceSummaries, [{ id: probeEvidenceId,
    kind: 'role-comparison', asset: '/api/admissions/partner/applications/:id' }]);
  assert.equal(plan.response.progress.hypothesisCount, 2);
  assert.equal(liveVerify.event.request.hypothesisId, 'h-idor');
  assert.equal(liveVerify.event.request.tool, 'known_record_idor_read');
  assert.equal(liveVerify.event.response.status, 'confirmed');
  assert.deepEqual(liveVerify.event.response.evidenceIds,
    run.report.probes.find(item => item.id === 'p-idor').evidenceIds);
  assert.equal(liveVerify.event.response.progress.confirmedProbeCount, 1);
  assert.equal(run.events.find(item => item.stage === 'complete').response.coverage.confirmed, 1);
  assert.equal(run.events.some(item => 'runId' in item || 'input' in item.request), false);
  assert.doesNotMatch(JSON.stringify(run.events.filter(item => item.stage)),
    /event-private-marker|event-private-asset|event-private-extra/u);
  detach();
  await runtime.close();
});

test('general board run stays isolated and rejects off-origin model probes', async () => {
  const urls = [];
  const catalogReads = [];
  let boardClosed = false;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-v4-pro',
    runIdFactory: () => 'general-board-test',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678',
      close: async () => { boardClosed = true; } }),
    caseSnapshot: { path: '/frozen/general-board-catalog.sqlite',
      caseRevisions: [{ caseId: 'old-case', revision: 2 }],
      caseSummaries: [{ caseId: 'old-case', revision: 2, title: 'Prior finding',
        vulnerabilityType: 'access_control', endpoint: '/api/posts/1', method: 'DELETE',
        description: 'api_key=old-secret', status: 'ready', patchStatus: 'unknown' }] },
    catalogReader: async options => {
      catalogReads.push(options);
      return { schemaVersion: 'casper-attack-catalog-1', status: 'ok',
        provenance: { source: 'casper-db.attack_catalog', sha256: 'a'.repeat(64) },
        patterns: [
          { pattern_id: 'board-xss', revision: 2, definition: {
            vulnType: 'stored_xss', target: { application: 'vul-web-1', endpoint: 'POST /api/posts' },
            payloads: [{ payloadId: 'board-payload', value: 'catalog-private-payload' }],
          } },
          { pattern_id: 'university-idor', revision: 1, definition: {
            vulnType: 'access_control', target: { application: 'vul-web2-daehan', endpoint: 'GET /api/item' },
            payloads: [{ payloadId: 'university-payload' }],
          } },
        ] };
    },
    fetchImpl: async url => { urls.push(String(url)); return response(new URL(url).pathname); },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h1', category: 'configuration',
        asset: '/admin', rationale: 'Administrative route should be reviewed.',
        evidenceIds: [context.evidence[0].id] }], probes: [
        { id: 'p1', hypothesisId: 'h1', tool: 'http_get', input: { path: 'http://example.com/admin' } },
        { id: 'p2', hypothesisId: 'h1', tool: 'repository_read',
          input: { file: 'vul-web-1/package.json' } },
        { id: 'p3', hypothesisId: 'h1', tool: 'http_get',
          input: { path: '/unobserved-internal-route' } },
      ] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(run.report.probes.find(item => item.id === 'p1').status, 'blocked');
  assert.equal(run.report.probes.find(item => item.id === 'p2').status, 'inconclusive');
  assert.equal(run.report.probes.find(item => item.id === 'p3').status, 'blocked');
  assert.equal(run.report.findings[0].status, 'inconclusive');
  assert.ok(urls.every(url => url.startsWith('http://127.0.0.1:49678/')));
  assert.ok(run.report.inventory.referenceSources.some(item =>
    item.source === 'casper-db/case-snapshot' && item.summaries[0].caseId === 'old-case'));
  const catalog = run.report.inventory.referenceSources.find(item =>
    item.source === 'casper-db/attack-catalog');
  assert.equal(catalog.status, 'available');
  assert.equal(catalog.sha256, 'a'.repeat(64));
  assert.deepEqual(catalog.entries, [{ patternId: 'board-xss', revision: 2,
    category: 'stored_xss', endpoint: 'POST /api/posts', payloadIds: ['board-payload'] }]);
  assert.equal(catalogReads.length, 1);
  assert.equal(catalogReads[0].databasePath, '/frozen/general-board-catalog.sqlite');
  assert.doesNotMatch(JSON.stringify(run.report), /catalog-private-payload/u);
  assert.doesNotMatch(JSON.stringify(run.report), /old-secret/u);
  await runtime.close();
  assert.equal(boardClosed, true);
});

test('general university catalog uses its frozen snapshot and excludes other targets', async () => {
  const reads = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'university-catalog-snapshot',
    caseSnapshot: { path: '/frozen/university-catalog.sqlite', caseRevisions: [] },
    catalogReader: async options => {
      reads.push(options);
      return { schemaVersion: 'casper-attack-catalog-1', status: 'ok',
        provenance: { source: 'casper-db.attack_catalog', sha256: 'b'.repeat(64) },
        patterns: [
          { pattern_id: 'board-xss', revision: 1, definition: {
            vulnType: 'stored_xss', target: { application: 'vul-web-1', endpoint: 'POST /api/posts' },
            payloads: [{ payloadId: 'board-only' }],
          } },
          { pattern_id: 'university-access', revision: 3, definition: {
            vulnType: 'access_control', target: { application: 'vul-web2-daehan', endpoint: 'GET /api/item' },
            payloads: [{ payloadId: 'university-only' }],
          } },
        ] };
    },
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => ({ async propose() {
      return { done: true, hypotheses: [], probes: [] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  const catalog = run.report.inventory.referenceSources.find(item =>
    item.source === 'casper-db/attack-catalog');
  assert.equal(catalog.status, 'available');
  assert.deepEqual(catalog.entries, [{ patternId: 'university-access', revision: 3,
    category: 'access_control', endpoint: 'GET /api/item', payloadIds: ['university-only'] }]);
  assert.equal(reads.length, 1);
  assert.equal(reads[0].databasePath, '/frozen/university-catalog.sqlite');
  await runtime.close();
});

test('general runtime default catalog reader preserves the frozen database', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'general-catalog-readonly-'));
  const databasePath = join(directory, 'snapshot.sqlite3');
  let runtime;
  try {
    const seeded = await readKnowledgeCatalog({ databasePath });
    assert.equal(seeded.status, 'ok');
    const before = await readFile(databasePath);
    runtime = createGeneralRuntime({
      fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
      modelId: 'deepseek-flash', runIdFactory: () => 'general-catalog-readonly',
      caseSnapshot: { path: databasePath, caseRevisions: [] },
      fetchImpl: async url => response(new URL(url).pathname),
      plannerFactory: () => ({ async propose() {
        return { done: true, hypotheses: [], probes: [] };
      } }),
    });
    const done = terminal(runtime);
    runtime.startLab();
    const run = await done;
    assert.equal(run.status, 'completed');
    const catalog = run.report.inventory.referenceSources.find(item =>
      item.source === 'casper-db/attack-catalog');
    assert.equal(catalog.status, 'available');
    assert.equal(catalog.sha256, seeded.provenance.sha256);
    assert.deepEqual(await readFile(databasePath), before);
  } finally {
    await runtime?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('multibyte repository excerpts stay within the core evidence byte limit', async () => {
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'multibyte-source-excerpt',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-readme', category: 'configuration',
        asset: 'vul-web-1/README.md', rationale: 'Inspect the available local source excerpt.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-readme', hypothesisId: 'h-readme', tool: 'repository_read',
        input: { file: 'vul-web-1/README.md' } }] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  assert.equal(run.report.probes[0].status, 'inconclusive');
  const excerpt = run.report.evidence.find(item => item.kind === 'source-excerpt'
    && item.source === 'repository/vul-web-1/README.md');
  assert.ok(excerpt);
  assert.ok(Buffer.byteLength(excerpt.summary, 'utf8') <= 1800);
  assert.match(excerpt.summary, /CA3P/u);
  await runtime.close();
});

test('general runtime rejects unregistered targets and rule-only models', () => {
  assert.throws(() => createGeneralRuntime({ fixtureId: 'outside', modelId: 'deepseek-flash' }));
  assert.throws(() => createGeneralRuntime({ fixtureId: 'vul-web-1', modelId: 'rule-baseline' }));
  assert.throws(() => createGeneralRuntime({ fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    targetOrigin: 'http://8.8.8.8:4101' }));
  assert.throws(() => createGeneralRuntime({ fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    targetOrigin: 'http://127.0.0.1:9999' }));
});

test('wrong private service fails identity binding before the model or general probes run', async () => {
  let modelUsed = false;
  const paths = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    targetOrigin: 'http://192.168.0.42:4101', runIdFactory: () => 'wrong-site',
    fetchImpl: async url => {
      paths.push(new URL(url).pathname);
      return new Response('<html><title>Internal service</title></html>', {
        status: 200, headers: { 'content-type': 'text/html' },
      });
    },
    plannerFactory: () => { modelUsed = true; return { propose: async () => ({ done: true }) }; },
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'failed');
  assert.equal(run.error, 'FIXTURE_IDENTITY_MISMATCH');
  assert.deepEqual(paths, ['/']);
  assert.equal(modelUsed, false);
  await runtime.close();
});

test('a model cannot turn guarded IDOR evidence into an XSS confirmation', async () => {
  let idorCalls = 0;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    runIdFactory: () => 'mislabelled-idor',
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'wrong-type', category: 'xss',
        asset: '/api/search', rationale: 'Incorrectly linked probe.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p1', hypothesisId: 'wrong-type', tool: 'known_record_idor_read', input: {} }] };
    } }),
    idorProbe: async () => { idorCalls += 1; return confirmedIdor(); },
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(run.report.probes[0].status, 'blocked');
  assert.equal(run.report.probes[0].reason, 'hypothesis_tool_mismatch');
  assert.equal(run.report.findings[0].status, 'not_tested');
  assert.equal(run.report.findings[0].reason, 'hypothesis_tool_mismatch');
  assert.equal(run.report.coverage.confirmed, 0);
  assert.equal(idorCalls, 0);
  await runtime.close();
});

test('mismatched IDOR probes leave the one-shot comparison for the registered asset', async () => {
  let idorCalls = 0;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    runIdFactory: () => 'idor-mismatch-then-valid',
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      const evidenceIds = [context.evidence[0].id];
      return { done: false, hypotheses: [
        { id: 'wrong-category', category: 'xss',
          asset: '/api/admissions/partner/applications/:id',
          rationale: 'Wrong vulnerability class.', evidenceIds },
        { id: 'wrong-asset', category: 'access_control', asset: '/api/search',
          rationale: 'Wrong registered asset.', evidenceIds },
        { id: 'registered-idor', category: 'access_control',
          asset: '/api/admissions/partner/applications/:id',
          rationale: 'Compare registered records.', evidenceIds },
      ], probes: [
        { id: 'p-wrong-category', hypothesisId: 'wrong-category',
          tool: 'known_record_idor_read', input: {} },
        { id: 'p-wrong-asset', hypothesisId: 'wrong-asset',
          tool: 'known_record_idor_read', input: {} },
        { id: 'p-valid', hypothesisId: 'registered-idor',
          tool: 'known_record_idor_read', input: {} },
      ] };
    } }),
    idorProbe: async () => { idorCalls += 1; return confirmedIdor(); },
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  assert.deepEqual(run.report.probes.map(item => item.status), ['blocked', 'blocked', 'confirmed']);
  assert.deepEqual(run.report.probes.slice(0, 2).map(item => item.reason),
    ['hypothesis_tool_mismatch', 'hypothesis_tool_mismatch']);
  assert.equal(run.events.find(item => item.stage === 'policy'
    && item.request?.probeId === 'p-wrong-category').response.reason,
  'hypothesis_tool_mismatch');
  assert.ok(run.report.probes.slice(0, 2).every(item => item.evidenceIds.length === 0));
  assert.equal(run.report.findings.find(item => item.hypothesisId === 'registered-idor').status,
    'confirmed');
  assert.equal(idorCalls, 1);
  await runtime.close();
});

test('a timed-out secondary page is recorded as unavailable without ending the assessment', async () => {
  let sawUnavailable = false;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    runIdFactory: () => 'page-timeout',
    fetchImpl: async url => {
      const path = new URL(url).pathname;
      if (path === '/about') throw new DOMException('The read timed out.', 'TimeoutError');
      return response(path);
    },
    plannerFactory: () => ({ async propose(context) {
      sawUnavailable = context.evidence.some(item => item.kind === 'unavailable' && item.asset === '/about');
      return { done: true, hypotheses: [], probes: [] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(sawUnavailable, true);
  assert.equal(run.report.inventory.pages.find(page => page.path === '/about').status, null);
  await runtime.close();
});

test('fixed demo sessions add bounded authenticated surfaces without exposing credentials', async () => {
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    runIdFactory: () => 'authenticated-inventory',
    fetchImpl: async url => {
      const path = new URL(url).pathname;
      if (path === '/login') return new Response('', { status: 302,
        headers: { location: '/mypage', 'set-cookie': 'session=SecretSession123456; HttpOnly' } });
      return response(path);
    },
    plannerFactory: () => ({ propose: async () => ({ done: true, hypotheses: [], probes: [] }) }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(run.report.inventory.authenticatedPages.length, 4);
  assert.deepEqual(new Set(run.report.inventory.authenticatedPages.map(page => page.sessionRole)),
    new Set(['student', 'owner', 'admin']));
  assert.doesNotMatch(JSON.stringify(run.report), /SecretSession|Partner2026|Welcome2026|admin1234/u);
  await runtime.close();
});

test('form and safe header metadata are bounded while model role reads reuse only fixed sessions', async () => {
  const requests = [];
  const hooks = [];
  const secretValue = 'FormValueMustStayPrivate987';
  const html = '<html><title>대한대학교</title><form action="/api/search" method="get">'
    + '<input name="q" type="search" value="' + secretValue + '">'
    + '<input name="password" type="password" value="' + secretValue + '">'
    + '<select name="faculty"><option value="private-option">A</option></select></form></html>';
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    runIdFactory: () => 'fixed-role-followup',
    beforeProbe: async probe => { hooks.push(probe); },
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      requests.push({ path: parsed.pathname + parsed.search, cookie: init.headers?.cookie ?? null });
      if (parsed.pathname === '/login') {
        const account = init.body.get('username');
        return new Response('', { status: 302, headers: { location: '/mypage',
          'set-cookie': 'sess=' + account + 'SecretSession123456; HttpOnly' } });
      }
      if (parsed.pathname === '/api/search') return new Response(JSON.stringify({ site: '대한대학교', results: [] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
      return new Response(html, { status: 200, headers: {
        'content-type': 'text/html',
        'content-security-policy': "default-src 'self'; script-src 'nonce-AbCdEf123456'",
        'access-control-allow-origin': 'https://name:pass@lab.example',
        'set-cookie': 'leak=HeaderSecret123456',
      } });
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      const home = context.inventory.pages.find(page => page.path === '/');
      assert.deepEqual(home.forms[0].fields, [
        { name: 'q', type: 'search' }, { name: 'password', type: 'password' },
        { name: 'faculty', type: 'select' },
      ]);
      assert.equal(home.securityHeaderValues['content-security-policy'],
        "default-src 'self'; script-src 'nonce-[redacted]'");
      assert.equal(home.securityHeaderValues['access-control-allow-origin'],
        'https://[redacted]@lab.example');
      assert.equal(home.securityHeaderValues['set-cookie'], undefined);
      return { done: false, hypotheses: [{ id: 'h-role', category: 'access_control',
        asset: '/api/search', rationale: 'Compare a fixed demo role response.',
        evidenceIds: [context.evidence[0].id] }], probes: [
        { id: 'p-owner', hypothesisId: 'h-role', tool: 'http_get',
          input: { path: '/api/search?q=role-probe', sessionRole: 'owner' } },
        { id: 'p-unknown', hypothesisId: 'h-role', tool: 'http_get',
          input: { path: '/api/search', sessionRole: 'outsider' } },
        { id: 'p-headers', hypothesisId: 'h-role', tool: 'http_get',
          input: { path: '/api/search', headers: { 'x-test': 'injected' } } },
      ] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  assert.equal(run.report.probes.find(item => item.id === 'p-owner').status, 'inconclusive');
  assert.equal(run.report.probes.find(item => item.id === 'p-unknown').status, 'blocked');
  assert.equal(run.report.probes.find(item => item.id === 'p-headers').status, 'blocked');
  assert.ok(hooks.some(item => item.id === 'p-owner' && item.session === 'owner'));
  assert.ok(requests.some(item => item.path === '/api/search?q=role-probe'
    && item.cookie === 'sess=partner1SecretSession123456'));
  assert.doesNotMatch(JSON.stringify(run.report),
    /FormValueMustStayPrivate|HeaderSecret|SecretSession123456|Partner2026|AbCdEf123456|name:pass/u);
  await runtime.close();
});

test('registered university backend excerpts are available with seed passwords masked', async () => {
  const fixtures = [
    { id: 'vul-web2-daehan', site: '대한대학교', file: 'vul-web2/src/db.mjs',
      source: '../../../vul-web2/src/db.mjs', other: 'vul-web2/src/server.mjs' },
    { id: 'vul-web2-wonchang', site: '원창대학교',
      file: 'vul-web2/wonchang/src/main/java/edu/wonchang/portal/Store.java',
      source: '../../../vul-web2/wonchang/src/main/java/edu/wonchang/portal/Store.java',
      other: 'vul-web2/wonchang/src/main/java/edu/wonchang/portal/PortalController.java' },
  ];
  for (const fixture of fixtures) {
    const source = await readFile(new URL(fixture.source, import.meta.url), 'utf8');
    const at = source.indexOf('Welcome2026');
    assert.ok(at > 0);
    const offset = Math.max(0, at - 120);
    const runtime = createGeneralRuntime({ fixtureId: fixture.id, modelId: 'deepseek-flash',
      runIdFactory: () => 'source-' + fixture.id,
      fetchImpl: async url => {
        const path = new URL(url).pathname;
        if (path === '/api/search') return new Response(JSON.stringify({ site: fixture.site, results: [] }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
        return new Response('<html><title>' + fixture.site + '</title></html>', {
          status: 200, headers: { 'content-type': 'text/html' },
        });
      },
      plannerFactory: () => ({ async propose(context) {
        if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
        assert.ok(context.inventory.repositoryFiles.includes(fixture.file));
        assert.ok(context.inventory.repositoryFiles.includes(fixture.other));
        return { done: false, hypotheses: [{ id: 'h-source', category: 'authentication',
          asset: fixture.file, rationale: 'Review the registered backend source.',
          evidenceIds: [context.evidence[0].id] }], probes: [{ id: 'p-source',
          hypothesisId: 'h-source', tool: 'repository_read',
          input: { file: fixture.file, offset } }] };
      } }),
    });
    const done = terminal(runtime);
    runtime.startLab();
    const run = await done;
    assert.equal(run.status, 'completed', run.error);
    const excerpt = run.report.evidence.find(item => item.source === 'repository/' + fixture.file);
    assert.ok(excerpt);
    assert.match(excerpt.summary, /sha1\(\[redacted\]\)/u);
    assert.doesNotMatch(JSON.stringify(run.report), /Welcome2026|Partner2026|Staff2026|admin1234/u);
    await runtime.close();
  }
});

test('failed model proposal is recorded once without invented token usage', async () => {
  const recorded = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'failed-model',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    onModelCall: async metadata => { recorded.push(metadata); },
    plannerFactory: () => ({ async propose() {
      throw Object.assign(new Error('private upstream output'), {
        code: 'DEEPSEEK_INCOMPLETE_RESPONSE', finishReason: 'length',
      });
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'failed');
  assert.equal(run.report.modelCalls.length, 1);
  assert.deepEqual(recorded, [{ provider: 'deepseek', requestedModel: 'deepseek-flash',
    status: 'failed', iteration: 1, finishReason: 'length' }]);
  assert.equal(run.report.modelCalls[0].usage, undefined);
  assert.doesNotMatch(JSON.stringify(run.report), /private upstream output/u);
  await runtime.close();
});

test('planner schema failures retain only a fixed validation message, not model output', async () => {
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'invalid-plan-diagnostic',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => plannerModule.createGeneralModelPlanner({
      client: { async completeJson() { return {
        value: { done: false, hypotheses: [], probes: [], rawModelSecret: 'do-not-store' },
        metadata: { provider: 'deepseek', model: 'deepseek-flash' },
      }; } },
    }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'failed');
  assert.equal(run.report.modelCalls[0].validationError, 'Model plan contains missing or unexpected fields');
  assert.doesNotMatch(JSON.stringify(run.report), /do-not-store/u);
  await runtime.close();
});

async function runRealBoardCanary(safeMode) {
  const hooks = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => safeMode ? 'safe-board-canary' : 'vulnerable-board-canary',
    boardFactory: async () => {
      const { startLocalLab } = await import('../../../packages/adapters/local-lab-gateway.mjs');
      return startLocalLab({ safeMode });
    },
    beforeProbe: async probe => { hooks.push(probe); },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-board', category: 'access_control',
        asset: '/api/posts/:id', rationale: 'Compare fresh Bob post deletion from Alice.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-board', hypothesisId: 'h-board',
        tool: 'known_cross_user_delete_canary', input: {} }] };
    } }),
  });
  try {
    const done = terminal(runtime);
    runtime.startLab();
    return { run: await done, hooks };
  } finally { await runtime.close(); }
}

test('fresh isolated board canary independently confirms cross-user deletion', async () => {
  const { run, hooks } = await runRealBoardCanary(false);
  assert.equal(run.status, 'completed');
  assert.equal(run.report.findings[0].status, 'confirmed', JSON.stringify(run.report.evidence));
  assert.equal(run.report.coverage.confirmed, 1);
  const canaryHooks = hooks.filter(item => item.tool === 'known_cross_user_delete_canary');
  assert.equal(canaryHooks.length, 8);
  assert.equal(canaryHooks.filter(item => item.method === 'DELETE').length, 2);
  assert.equal(new Set(canaryHooks.map(item => item.id)).size, canaryHooks.length);
  assert.ok(canaryHooks.every(item => item.url.startsWith(run.target)));
  assert.match(run.report.evidence.find(item => item.kind === 'cross-user-delete-comparison').summary,
    /Bob post still present.*independent authorization verdict=confirmed/u);
});

test('safe isolated board retains Bob post and is not reproduced', async () => {
  const { run } = await runRealBoardCanary(true);
  assert.equal(run.status, 'completed');
  assert.equal(run.report.findings[0].status, 'not_reproduced', JSON.stringify(run.report.evidence));
  assert.equal(run.report.coverage.notReproduced, 1);
  assert.match(run.report.evidence.find(item => item.kind === 'cross-user-delete-comparison').summary,
    /Alice cross-user delete HTTP 403.*remains=true/u);
});

function fakeBoardResponses({ removeOnControl = false, onCandidate } = {}) {
  let posts = [];
  return async (urlValue, init = {}) => {
    const url = new URL(urlValue);
    const method = init.method ?? 'GET';
    const json = (value, status = 200, headers = {}) =>
      new Response(JSON.stringify(value), { status,
        headers: { 'content-type': 'application/json', ...headers } });
    if (url.pathname === '/' && method === 'GET') return new Response('<html>Local board</html>', {
      status: 200, headers: { 'content-type': 'text/html' },
    });
    if (url.pathname === '/api/session' && method === 'GET') return json({ user: { id: 'alice' } });
    if (url.pathname === '/api/session' && method === 'POST') {
      const id = JSON.parse(init.body).userId;
      return json({ user: { id } }, 200,
        { 'set-cookie': 'board_session=' + id + 'Secret123456; HttpOnly' });
    }
    if (url.pathname === '/api/posts' && method === 'GET') return json({ posts });
    if (url.pathname === '/api/posts' && method === 'POST') {
      const body = JSON.parse(init.body);
      const post = { id: 7, authorId: 'bob', ...body };
      posts = [...posts, post];
      return json({ post }, 201);
    }
    if (url.pathname === '/api/posts/7' && method === 'DELETE') {
      if (!url.search) {
        if (removeOnControl) posts = [];
        return json({ error: 'denied' }, 403);
      }
      onCandidate?.();
      posts = [];
      return json({ ok: true }, 200);
    }
    return json({ error: 'not_found' }, 404);
  };
}

function fakeBoardPlanner() {
  return { async propose(context) {
    if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
    return { done: false, hypotheses: [{ id: 'h-board', category: 'access_control',
      asset: '/api/posts/:id', rationale: 'Compare a fresh Bob-owned post.',
      evidenceIds: [context.evidence[0].id] }],
    probes: [{ id: 'p-board', hypothesisId: 'h-board',
      tool: 'known_cross_user_delete_canary', input: {} }] };
  } };
}

test('mismatched board probes leave the one-shot canary for the registered asset', async () => {
  let candidateSent = 0;
  const hooks = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'board-mismatch-then-valid',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: fakeBoardResponses({ onCandidate: () => { candidateSent += 1; } }),
    beforeProbe: async hook => { hooks.push(hook); },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      const evidenceIds = [context.evidence[0].id];
      return { done: false, hypotheses: [
        { id: 'board-wrong-category', category: 'xss', asset: '/api/posts/:id',
          rationale: 'Wrong vulnerability class.', evidenceIds },
        { id: 'board-wrong-asset', category: 'access_control', asset: '/api/posts/7',
          rationale: 'Concrete post is not the registered asset.', evidenceIds },
        { id: 'board-valid', category: 'access_control', asset: '/api/posts/:id',
          rationale: 'Compare isolated cross-user delete.', evidenceIds },
      ], probes: [
        { id: 'p-board-wrong-category', hypothesisId: 'board-wrong-category',
          tool: 'known_cross_user_delete_canary', input: {} },
        { id: 'p-board-wrong-asset', hypothesisId: 'board-wrong-asset',
          tool: 'known_cross_user_delete_canary', input: {} },
        { id: 'p-board-valid', hypothesisId: 'board-valid',
          tool: 'known_cross_user_delete_canary', input: {} },
      ] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  assert.deepEqual(run.report.probes.map(item => item.status), ['blocked', 'blocked', 'confirmed']);
  assert.deepEqual(run.report.probes.slice(0, 2).map(item => item.reason),
    ['hypothesis_tool_mismatch', 'hypothesis_tool_mismatch']);
  assert.equal(run.events.find(item => item.stage === 'policy'
    && item.request?.probeId === 'p-board-wrong-category').response.reason,
  'hypothesis_tool_mismatch');
  assert.ok(run.report.probes.slice(0, 2).every(item => item.evidenceIds.length === 0));
  assert.equal(run.report.findings.find(item => item.hypothesisId === 'board-valid').status,
    'confirmed');
  assert.equal(candidateSent, 1);
  assert.equal(hooks.filter(item => item.tool === 'known_cross_user_delete_canary').length, 8);
  await runtime.close();
});

test('denied control that removes the canary never proceeds to candidate deletion', async () => {
  let candidateSent = 0;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'anomalous-control',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: fakeBoardResponses({ removeOnControl: true,
      onCandidate: () => { candidateSent += 1; } }),
    plannerFactory: () => fakeBoardPlanner(),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(run.report.findings[0].status, 'inconclusive');
  assert.equal(candidateSent, 0);
  assert.match(run.report.evidence.find(item => item.kind === 'cross-user-delete-comparison').summary,
    /did not survive the denied control/u);
  await runtime.close();
});

test('cancellation before candidate write prevents the delete and stops the run', async () => {
  let candidateSent = 0;
  let runtime;
  runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'cancel-board-canary',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: fakeBoardResponses({ onCandidate: () => { candidateSent += 1; } }),
    beforeProbe: async hook => {
      if (hook.id.endsWith('-alice-candidate')) runtime.stop('cancel-board-canary');
    },
    plannerFactory: () => fakeBoardPlanner(),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'stopped');
  assert.equal(run.report.status, 'cancelled');
  assert.equal(candidateSent, 0);
  await runtime.close();
});
