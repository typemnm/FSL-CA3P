import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGeneralRuntime } from '../general-runtime.mjs';
import { verifyAttack } from '../../../packages/verifier/index.mjs';
import { readReportHandoff } from '../../../packages/verifier/report-handoff.mjs';
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
  const origin = 'http://127.0.0.1:53987';
  const calls = [];
  const modelCalls = [];
  const hooks = [];
  let liveVerify;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: origin,
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
    idorProbe: async options => {
      assert.equal(options.origin, origin);
      return confirmedIdor();
    },
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
  assert.ok(calls.every(item => item.url.startsWith(`${origin}/`)));
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
});

test('wrong private service fails identity binding before the model or general probes run', async () => {
  let modelUsed = false;
  const paths = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash',
    targetOrigin: 'http://192.168.0.42:53987', runIdFactory: () => 'wrong-site',
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
  const recorded = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'invalid-plan-diagnostic',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    onModelCall: async metadata => { recorded.push(metadata); },
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
  assert.equal(recorded.length, 2);
  assert.equal(run.report.modelCalls.length, 2);
  assert.deepEqual(recorded.map(item => item.status), ['failed', 'failed']);
  assert.equal(run.report.modelCalls[0].validationError, 'Model plan contains missing or unexpected fields');
  assert.doesNotMatch(JSON.stringify(run.report), /do-not-store/u);
  await runtime.close();
});

test('corrected planner schema produces one log entry per actual model call', async () => {
  const recorded = [];
  let attempts = 0;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'corrected-plan-diagnostic',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    onModelCall: async metadata => { recorded.push(metadata); },
    plannerFactory: () => plannerModule.createGeneralModelPlanner({
      client: { async completeJson() { attempts += 1; return {
        value: attempts === 1
          ? { done: true, hypotheses: [], probes: [], rawModelSecret: 'do-not-store' }
          : { done: true, hypotheses: [], probes: [] },
        metadata: { provider: 'deepseek', model: 'deepseek-flash', finishReason: 'stop' },
      }; } },
    }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(attempts, 2);
  assert.equal(recorded.length, 2);
  assert.equal(run.report.modelCalls.length, 2);
  assert.deepEqual(recorded.map(item => item.status), ['failed', 'completed']);
  assert.deepEqual(run.report.modelCalls.map(item => item.status), ['failed', 'completed']);
  assert.equal(recorded[0].validationError, 'Model plan contains missing or unexpected fields');
  assert.doesNotMatch(JSON.stringify(run.report), /do-not-store/u);
  await runtime.close();
});

test('a custom planner cannot forge extra model call attempts', async () => {
  const recorded = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => 'custom-plan-attempts',
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: async url => response(new URL(url).pathname),
    onModelCall: async metadata => { recorded.push(metadata); },
    plannerFactory: () => ({ async propose() { return {
      done: true, hypotheses: [], probes: [],
      modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' },
      modelAttempts: [{ validationError: 'PRIVATE_MODEL_RESPONSE' },
        { validationError: 'PRIVATE_MODEL_RESPONSE' }, { validationError: 'PRIVATE_MODEL_RESPONSE' }],
    }; } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed');
  assert.equal(recorded.length, 1);
  assert.equal(run.report.modelCalls.length, 1);
  assert.doesNotMatch(JSON.stringify(run.report), /PRIVATE_MODEL_RESPONSE/u);
  await runtime.close();
});

// Stands in for the AI verifier with a fixed verdict; the status is the verifier/1 status.
function scriptedVerifier(status, seen = []) {
  return async (record, options) => {
    seen.push({ record, options });
    return { status, reason: 'scripted ' + status, artifacts: [] };
  };
}

async function runRealBoardCanary(safeMode) {
  const hooks = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash',
    runIdFactory: () => safeMode ? 'safe-board-canary' : 'vulnerable-board-canary',
    boardFactory: async () => {
      const { startLocalLab } = await import('../../../packages/adapters/local-lab-gateway.mjs');
      return startLocalLab({ safeMode });
    },
    verifyAttackImpl: scriptedVerifier(safeMode ? 'not_reproduced' : 'confirmed'),
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
    verifyAttackImpl: scriptedVerifier('confirmed'),
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

async function runBoardWithVerifier(runId, options) {
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash', runIdFactory: () => runId,
    boardFactory: async () => ({ origin: 'http://127.0.0.1:49678', close: async () => {} }),
    fetchImpl: fakeBoardResponses(),
    plannerFactory: () => fakeBoardPlanner(),
    ...options,
  });
  try {
    const done = terminal(runtime);
    runtime.startLab();
    return await done;
  } finally { await runtime.close(); }
}

test('AI invalid verdict is the board verdict even when the deterministic canary confirms', async () => {
  const seen = [];
  const run = await runBoardWithVerifier('ai-invalid-canary', { verifyAttackImpl: scriptedVerifier('not_reproduced', seen) });
  assert.equal(run.report.probes.find(item => item.id === 'p-board').status, 'not_reproduced');
  assert.equal(run.report.findings[0].status, 'not_reproduced');
  assert.equal(seen.length, 1);
});

test('AI valid verdict cites the probe evidence id in the probe and finding', async () => {
  const run = await runBoardWithVerifier('ai-valid-canary', { verifyAttackImpl: scriptedVerifier('confirmed') });
  const comparison = run.report.evidence.find(item => item.kind === 'cross-user-delete-comparison');
  const probe = run.report.probes.find(item => item.id === 'p-board');
  assert.equal(probe.status, 'confirmed');
  assert.deepEqual(probe.evidenceIds, [comparison.id]);
  assert.equal(run.report.findings[0].status, 'confirmed');
});

test('verifier failure is recorded as inconclusive verifier_failed', async () => {
  const run = await runBoardWithVerifier('verifier-throws-canary', {
    verifyAttackImpl: async () => { throw new Error('model unavailable'); } });
  assert.equal(run.status, 'completed');
  assert.equal(run.report.findings[0].status, 'inconclusive');
  assert.equal(run.events.find(item => item.stage === 'verify' && item.request?.probeId === 'p-board').response.reason,
    'verifier_failed');
});

test('verification handoff is written per probe and the AttackRecord holds no cookie value', async () => {
  const root = await mkdtemp(join(tmpdir(), 'general-verification-'));
  const seen = [];
  const verifierModel = { async completeJson() {
    return { value: { verdict: 'valid', reason: 'Alice removed the Bob-owned post.' }, metadata: { model: 'scripted' } };
  } };
  try {
    const run = await runBoardWithVerifier('handoff-canary', {
      verificationRoot: root, verifierModel,
      verifyAttackImpl: async (record, options) => { seen.push(record); return verifyAttack(record, options); },
    });
    assert.equal(run.report.findings[0].status, 'confirmed');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].id, 'p-board');
    assert.equal(seen[0].kind, 'cross_user_delete');
    assert.ok(seen[0].control && seen[0].followUp);
    assert.doesNotMatch(JSON.stringify(seen[0]), /Secret123456/u);
    const handoff = await readReportHandoff(join(root, 'p-board'));
    assert.equal(handoff.schemaVersion, 'verification-handoff/1');
    assert.equal(handoff.result.attackId, 'p-board');
    assert.equal(handoff.result.status, 'confirmed');
  } finally { await rm(root, { recursive: true, force: true }); }
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

function fakeTargetInfo(url, extraPaths = []) {
  const parsed = new URL(url);
  return {
    schemaVersion: 'web-parser-1',
    target: { requestedUrl: url, finalUrl: url, origin: parsed.origin },
    navigation: { status: 200, contentType: 'text/html', redirectChain: [], loadTimingMs: 5, securityDetails: null },
    headers: [{ name: 'Content-Type', value: 'text/html' }],
    cookies: [], meta: [], html: '<html><head><title>Fixture ' + parsed.pathname + '</title></head></html>', body: null,
    technologies: [{ name: 'nginx', categories: ['Web servers'], version: null, confidence: 100, evidence: [] }],
    libraries: [],
    structure: { forms: [], links: [], scripts: [], iframes: [], inputs: [], linkTags: [],
      areas: [], formActions: [], frames: [], embeds: [], objects: [], metaRefresh: [], media: [] },
    resources: [{ kind: 'document', method: 'GET', url, status: 200 }],
    paths: extraPaths,
    errors: [],
    truncated: false,
  };
}

function universityLoginFetch() {
  return async (url, init = {}) => {
    const parsed = new URL(url);
    if (parsed.pathname === '/login') {
      const account = init.body.get('username');
      return new Response('', { status: 302, headers: { location: '/mypage',
        'set-cookie': 'sess=' + account + 'TOKEN1234567; HttpOnly' } });
    }
    if (parsed.pathname === '/api/search') return new Response(JSON.stringify({ site: '대한대학교', results: [] }),
      { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response('<html><title>대한대학교</title></html>', { status: 200, headers: { 'content-type': 'text/html' } });
  };
}

test('web_info observes declared paths, extends scope, and rejects off-scope or off-origin paths', async () => {
  const collected = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'web-info-scope',
    fetchImpl: universityLoginFetch(),
    webParserCollect: async (url, opts = {}) => {
      collected.push({ url, cookies: opts.cookies ?? null });
      const origin = new URL(url).origin;
      const extra = new URL(url).pathname === '/' ? [
        { url: origin + '/discovered', sources: ['link'], methods: [], sameOrigin: true, params: [] },
        { url: 'http://evil.example/x', sources: ['link'], methods: [], sameOrigin: false, params: [] },
        { url: origin + '/wild', sources: ['robots:disallow'], methods: [], sameOrigin: true, params: [], wildcard: true },
      ] : [];
      const info = fakeTargetInfo(url, extra);
      const { summarizeTargetInfo } = await import('../../../packages/adapters/integrations/web-parser.mjs');
      return { info, summary: summarizeTargetInfo(info) };
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      const evidenceIds = [context.evidence[0].id];
      return { done: false, hypotheses: [{ id: 'h-web', category: 'configuration',
        asset: '/', rationale: 'Observe the selected origin with a browser.', evidenceIds }],
      probes: [
        { id: 'w-pub', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/' } },
        { id: 'w-role', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/mypage', sessionRole: 'owner' } },
        { id: 'w-discovered', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/discovered' } },
        { id: 'w-wild', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/wild' } },
        { id: 'w-offorigin', hypothesisId: 'h-web', tool: 'web_info', input: { path: 'http://evil.example/x' } },
      ] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  const probe = id => run.report.probes.find(item => item.id === id);
  assert.equal(probe('w-pub').status, 'inconclusive');
  assert.equal(probe('w-role').status, 'inconclusive');
  assert.equal(probe('w-discovered').status, 'inconclusive', 'the discovered same-origin path was authorized');
  assert.equal(probe('w-wild').status, 'blocked');
  assert.equal(probe('w-offorigin').status, 'blocked');
  assert.equal(probe('w-wild').reason, 'path_out_of_scope');
  assert.equal(probe('w-offorigin').reason, 'path_out_of_scope');
  // web_info evidence is observation; the verifier never promotes it to a verdict.
  const pubEvidence = run.report.evidence.find(item => item.id === probe('w-pub').evidenceIds[0]);
  assert.equal(pubEvidence.kind, 'web-info');
  assert.equal(pubEvidence.source, 'web-parser/vul-web2-daehan');
  const roleEvidence = run.report.evidence.find(item => item.id === probe('w-role').evidenceIds[0]);
  assert.equal(roleEvidence.source, 'web-parser/vul-web2-daehan/role:owner');
  // The fixed owner session cookie reached web-parser as a { name, value } pair.
  const roleCall = collected.find(item => new URL(item.url).pathname === '/mypage');
  assert.deepEqual(roleCall.cookies, [{ name: 'sess', value: 'partner1TOKEN1234567' }]);
  assert.ok(run.report.scope.allowedPaths.includes('/discovered'));
  assert.ok(!run.report.scope.allowedPaths.includes('/wild'));
  assert.ok(run.report.scope.toolIds.includes('web_info'));
  assert.doesNotMatch(JSON.stringify(run.report), /TOKEN1234567/u);
  await runtime.close();
});

test('web_info honors cancellation mid-run', async () => {
  const collected = [];
  let runtime;
  runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'web-info-cancel',
    fetchImpl: universityLoginFetch(),
    beforeProbe: async probe => { if (probe.tool === 'web_info') runtime.stop('web-info-cancel'); },
    webParserCollect: async (url, opts = {}) => {
      collected.push(url);
      if (opts.signal?.aborted) { const error = new Error('aborted'); error.name = 'AbortError'; throw error; }
      const info = fakeTargetInfo(url);
      return { info, summary: {} };
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-web', category: 'configuration',
        asset: '/', rationale: 'Observe the selected origin.', evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'w-abort', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/' } }] };
    } }),
  });
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'stopped');
  assert.equal(run.report.status, 'cancelled');
  await runtime.close();
});

const SESSION_VALUE = 'SessionCookieValue12345';
const TRACKER_VALUE = 'TrackerCookieValue67890';

/** A loopback stand-in for the isolated board: session login, Set-Cookie page, robots.txt and JSON. */
async function loopbackBoard() {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://127.0.0.1').pathname;
    if (req.method === 'POST' && path === '/api/session') {
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'sid=' + SESSION_VALUE + '; HttpOnly; Path=/' });
      return res.end('{"ok":true}');
    }
    if (path === '/robots.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('User-agent: *\nDisallow: /hidden-admin\n');
    }
    if (path.startsWith('/api/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"posts":[]}');
    }
    // A logged-in page reflects the session value in a header and a link.
    const reflected = req.headers.cookie?.includes(SESSION_VALUE) ? SESSION_VALUE : null;
    res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.25.3',
      'set-cookie': 'tracker=' + TRACKER_VALUE + '; Path=/; SameSite=Lax',
      ...(reflected ? { 'x-echo': reflected } : {}) });
    return res.end('<html><head><title>Loopback Board</title></head><body>'
      + '<a href="/robots.txt">robots</a><a href="/api/data">data</a>'
      + (reflected ? '<a href="/echo?ref=' + reflected + '">echo</a>' : '')
      + '<form action="/api/posts" method="post"><input name="title"><textarea name="content"></textarea></form></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: 'http://127.0.0.1:' + server.address().port,
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

test('web_info evidence shows the planner real page details from a browser without cookie values', async () => {
  const contexts = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web-1', modelId: 'deepseek-flash', runIdFactory: () => 'web-info-evidence',
    boardFactory: loopbackBoard,
    plannerFactory: () => ({ async propose(context) {
      contexts.push(JSON.stringify({ inventory: context.inventory, evidence: context.evidence }));
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-web', category: 'configuration', asset: '/',
        rationale: 'Observe the board with a browser.', evidenceIds: [context.evidence[0].id] }],
      probes: [
        { id: 'w-home', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/' } },
        { id: 'w-robots', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/robots.txt' } },
        { id: 'w-json', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/api/data' } },
        { id: 'w-alice', hypothesisId: 'h-web', tool: 'web_info', input: { path: '/', sessionRole: 'alice' } },
      ] };
    } }),
  });
  try {
    const done = terminal(runtime);
    runtime.startLab();
    const run = await done;
    assert.equal(run.status, 'completed', run.error);
    const seen = JSON.parse(contexts[1]).evidence;
    const of = id => run.report.probes.find(item => item.id === id).evidenceIds
      .map(evidenceId => seen.find(item => item.id === evidenceId));
    const [home, homePaths, homeSurface] = of('w-home');
    assert.deepEqual([home.kind, homePaths.kind, homeSurface.kind], ['web-info', 'web-info-paths', 'web-info-surface']);
    assert.match(home.summary, /HTTP 200 text\/html; title "Loopback Board"/u);
    assert.match(home.summary, /"name":"Nginx","version":"1\.25\.3"/u);
    assert.match(homePaths.summary, /"url":"\/robots\.txt"/u);
    assert.match(homeSurface.summary, /"action":"\/api\/posts","method":"post","fields":\[\{"name":"title","type":"text"\},\{"name":"content","type":"textarea"\}\]/u);
    assert.match(homeSurface.summary, /"name":"tracker","httpOnly":false/u);
    const [robots, robotsPaths] = of('w-robots');
    assert.match(robots.summary, /HTTP 200 text\/plain/u);
    assert.match(robotsPaths.summary, /"url":"\/hidden-admin","sources":\["robots:disallow"\]/u);
    assert.match(of('w-json')[0].summary, /HTTP 200 application\/json/u);
    const aliceSurface = of('w-alice').find(item => item.kind === 'web-info-surface');
    assert.equal(aliceSurface.source, 'web-parser/vul-web-1/role:alice');
    assert.match(aliceSurface.summary, /"name":"sid",/u);
    assert.match(aliceSurface.summary, /"name":"x-echo","value":"\[redacted\]"/u);
    assert.match(of('w-alice').find(item => item.kind === 'web-info-paths').summary, /"url":"\/echo\?ref \[redacted\]"/u);
    for (const item of seen.filter(entry => entry.kind.startsWith('web-info'))) {
      assert.ok(Buffer.byteLength(item.summary, 'utf8') <= 2048 && Buffer.byteLength(JSON.stringify(item), 'utf8') <= 4096);
    }
    for (const text of [JSON.stringify(run.report), ...contexts]) {
      assert.doesNotMatch(text, new RegExp(SESSION_VALUE + '|' + TRACKER_VALUE, 'u'));
    }
  } finally { await runtime.close(); }
});

function largeTargetInfo(url) {
  const info = fakeTargetInfo(url, Array.from({ length: 400 }, (_, i) => ({ url: new URL('/p/' + i + '?q=1', url).href,
    sources: ['robots:disallow'], methods: ['GET'], sameOrigin: true, params: ['q'] })));
  const fields = Array.from({ length: 60 }, (_, i) => ({ name: '필드' + i, type: 'text' }));
  info.structure.forms = Array.from({ length: 25 }, (_, i) => ({ action: url + 'f' + i, method: 'POST', fields }));
  info.headers = Array.from({ length: 80 }, (_, i) => ({ name: 'X-Header-' + i, value: '값'.repeat(300) }));
  return info;
}

async function runWebInfoBudget({ limits, probes, onEvidence }) {
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'web-info-budget', fetchImpl: universityLoginFetch(), limits,
    webParserCollect: async url => ({ info: largeTargetInfo(url), summary: {} }),
    plannerFactory: () => ({ async propose(context) {
      onEvidence?.(context.evidence);
      if (context.iteration > 1 || !probes.length) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-web', category: 'configuration', asset: '/',
        rationale: 'Observe a large page.', evidenceIds: [context.evidence[0].id] }],
      probes: probes.map(([id, path]) => ({ id, hypothesisId: 'h-web', tool: 'web_info', input: { path } })) };
    } }),
  });
  try {
    const done = terminal(runtime);
    runtime.startLab();
    return await done;
  } finally { await runtime.close(); }
}

test('web_info evidence from a large page stays within core limits and marks shown/total', async () => {
  const run = await runWebInfoBudget({ probes: [['w-large', '/']] });
  assert.equal(run.status, 'completed', run.error);
  const items = run.report.evidence.filter(item => item.kind.startsWith('web-info'));
  assert.deepEqual(items.map(item => item.kind), ['web-info', 'web-info-paths', 'web-info-surface']);
  for (const item of items) {
    assert.ok(Buffer.byteLength(item.summary, 'utf8') <= 2048 && Buffer.byteLength(JSON.stringify(item), 'utf8') <= 4096);
  }
  assert.match(items[1].summary, /paths \d+\/400: \[\{"url":"\/p\/0\?q=1"/u);
  assert.match(items[2].summary, /forms 1\/25: .*"\+30 more"\]\}\]; headers \d+\/80: /u);
});

function heavyTargetInfo(url) {
  const info = fakeTargetInfo(url, Array.from({ length: 150 }, (_, i) => ({ url: new URL('/p/' + i + '?q=1', url).href,
    sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['q'] })));
  info.headers = Array.from({ length: 22 }, (_, i) => ({ name: 'X-Header-' + i, value: 'value-' + i }));
  info.technologies = Array.from({ length: 12 }, (_, i) => ({ name: 'Tech' + i, version: '1.' + i,
    categories: ['Web frameworks'] }));
  info.structure.forms = Array.from({ length: 6 }, (_, i) => ({ action: url + 'f' + i, method: 'POST',
    fields: Array.from({ length: 8 }, (_, j) => ({ name: 'field' + j, type: 'text' })) }));
  return info;
}

test('web_info on heavy pages up to maxProbes keeps the real planner prompt under its limit', async () => {
  const promptBytes = [];
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'web-info-prompt-budget', fetchImpl: universityLoginFetch(),
    webParserCollect: async url => ({ info: heavyTargetInfo(url), summary: {} }),
    plannerFactory: () => plannerModule.createGeneralModelPlanner({ client: { async completeJson({ systemPrompt, userPayload }) {
      promptBytes.push(Buffer.byteLength(systemPrompt, 'utf8') + Buffer.byteLength(JSON.stringify(userPayload), 'utf8'));
      const { iteration, evidence } = userPayload;
      return { value: { done: false, hypotheses: [{ id: 'h' + iteration, category: 'configuration', asset: '/',
        rationale: 'Observe a heavy page.', evidenceIds: [evidence[0].id] }],
      probes: Array.from({ length: 4 }, (_, i) => ({ id: 'w' + iteration + '-' + i, hypothesisId: 'h' + iteration,
        tool: 'web_info', input: { path: '/' } })) }, metadata: { provider: 'deepseek', model: 'deepseek-flash' } };
    } } }),
  });
  try {
    const done = terminal(runtime);
    runtime.startLab();
    const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(promptBytes.length, 6);
    const probes = run.report.probes.filter(item => item.tool === 'web_info');
    assert.equal(probes.length, 24);
    const byId = new Map(run.report.evidence.map(item => [item.id, item]));
    const full = probes[0].evidenceIds.map(id => byId.get(id));
    assert.deepEqual(full.map(item => item.kind), ['web-info', 'web-info-paths', 'web-info-surface']);
    // Without the budget, the 20 calls a planner sees would resend far more than its prompt limit.
    const fullBytes = full.reduce((sum, item) => sum + Buffer.byteLength(JSON.stringify(item), 'utf8'), 0);
    assert.ok(20 * fullBytes > 64 * 1024, String(fullBytes));
    const counts = probes.map(item => item.evidenceIds.length);
    const fullCalls = counts.lastIndexOf(3) + 1;
    assert.deepEqual(counts, counts.map((_, index) => index < fullCalls ? 3 : 1));
    assert.ok(fullCalls < 24);
    for (const probe of probes.slice(fullCalls)) {
      const line = byId.get(probe.evidenceIds[0]);
      assert.equal(line.kind, 'web-info');
      assert.match(line.summary, /^web_info \/: HTTP 200 text\/html; counts \{.*"paths":150.*\}; details withheld: evidence budget$/u);
      assert.ok(Buffer.byteLength(line.summary, 'utf8') <= 300);
    }
  } finally { await runtime.close(); }
});

test('web_info fits the remaining evidence budget with one and then zero free slots', async () => {
  let initial = 0;
  await runWebInfoBudget({ probes: [], onEvidence: evidence => { initial = evidence.length; } });
  assert.ok(initial > 0);
  const limits = { maxIterations: 3, maxProbes: 24, maxEvidenceItems: initial + 1 };
  const run = await runWebInfoBudget({ limits, probes: [['w-one', '/'], ['w-zero', '/about']] });
  assert.equal(run.status, 'completed', run.error);
  assert.equal(run.report.stopReason, 'planner_done');
  const probe = id => run.report.probes.find(item => item.id === id);
  assert.equal(probe('w-one').evidenceIds.length, 1);
  assert.equal(run.report.evidence.find(item => item.id === probe('w-one').evidenceIds[0]).kind, 'web-info');
  assert.equal(probe('w-zero').status, 'inconclusive');
  assert.equal(probe('w-zero').reason, 'no_evidence');
  assert.equal(run.report.evidence.length, initial + 1);
});

test('general runtime routes vulnerability workers through two daemon ports and closes them after completion', async t => {
  let advertised;
  const runtime = createGeneralRuntime({
    fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:53988',
    modelId: 'deepseek-flash', runIdFactory: () => 'general-attack-tool-workers',
    fetchImpl: async url => response(new URL(url).pathname),
    plannerFactory: () => ({ async propose(context) {
      advertised = context.inventory.attackTool;
      assert.equal(advertised.templates.length, 1);
      assert.equal(advertised.templates[0].templateId, 'sqli-like-tautology');
      assert.equal(new Set(advertised.endpoints).size, 2);
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      const evidenceIds = [context.evidence[0].id];
      return { hypotheses: [
        { id: 'headers', category: 'configuration', asset: '/about',
          rationale: 'Review observed response headers.', evidenceIds },
        { id: 'dependencies', category: 'dependency', asset: 'vul-web2/package.json',
          rationale: 'Review declared dependency versions as context.', evidenceIds },
      ], probes: [
        { id: 'headers-read', hypothesisId: 'headers', tool: 'http_get', input: { path: '/about' } },
        { id: 'dependency-read', hypothesisId: 'dependencies', tool: 'repository_read',
          input: { file: 'vul-web2/package.json' } },
      ] };
    } }),
  });
  t.after(() => runtime.close());
  const done = terminal(runtime);
  runtime.startLab();
  const run = await done;
  assert.equal(run.status, 'completed', run.error);
  assert.equal(run.report.probes.length, 2);
  assert.ok(run.report.probes.every(probe => probe.evidenceIds.length));
  assert.equal(new Set(run.report.attackTool.agentIds).size, 2);
  assert.deepEqual(run.report.attackTool.endpoints, advertised.endpoints);
  assert.deepEqual(run.report.attackTool.flow, ['agent', 'attack-tool', 'guardrail', 'executor']);
  assert.deepEqual(run.report.attackTool.templateIds, ['sqli-like-tautology']);
  assert.doesNotMatch(JSON.stringify(run.report.attackTool), /Bearer|authorization|token|secret/i);
  for (const endpoint of advertised.endpoints) {
    await assert.rejects(fetch(endpoint, { signal: AbortSignal.timeout(1000) }));
  }
});
