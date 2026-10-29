import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDbManagement } from '../db-management.mjs';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32'
  ? join(root, '.venv', 'Scripts', 'python.exe') : 'python3');

test('dashboard DB manages the runtime Case DB with revisions, archive and audit', async t => {
  const folder = await mkdtemp(join(tmpdir(), 'ca3p-dashboard-db-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const casePath = join(folder, 'cases.sqlite3');
  const db = createDbManagement({ casePath, workspacePath: join(folder, 'intake'), python });
  const setup = await db.bootstrap();
  assert.equal(resolve(setup.caseDatabase), resolve(casePath));
  assert.deepEqual(await db.listIntakes(), { intakes: [] });
  assert.deepEqual((await db.listCases({})).cases, []);

  const caseRecord = JSON.parse(await readFile(join(root, 'casper-db', 'examples', 'case.example.json'), 'utf8'));
  const inserted = spawnSync(python, ['-c', 'import json,sys; from casper_db.repository import CaseStore; p,c=json.load(sys.stdin); CaseStore(p).add(c)'], {
    input: JSON.stringify([casePath, caseRecord]), encoding: 'utf8',
    env: { ...process.env, PYTHONPATH: [join(root, 'casper-db', 'src'), process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(inserted.status, 0, inserted.stderr);

  const found = await db.listCases({ q: '검색', targetId: 'LAB-DEMO' });
  assert.equal(found.total, 1);
  assert.equal(found.cases[0].case_id, 'CASE-001');
  assert.equal(found.cases[0].archived, false);
  assert.equal((await db.listCases({ q: 'LAB-DEMO' })).total, 1);
  assert.equal((await db.listCases({ q: 'lab.example.invalid' })).total, 1);

  const changed = await db.updateCase('CASE-001', { patch: { title: '검토된 제목' }, expectedRevision: 1 }, 'admin');
  assert.equal(changed.case.title, '검토된 제목');
  assert.equal(changed.case.revision, 2);
  assert.equal((await db.listCaseVersions('CASE-001')).versions.length, 2);

  const archived = await db.archiveCase('CASE-001', { reason: '중복 자료' }, 'admin');
  assert.equal(archived.archived, true);
  assert.equal((await db.listCases({})).total, 0);
  assert.equal((await db.listCases({ archived: true })).total, 1);
  const runtimeQuery = spawnSync(python, ['-c', 'import json,sys; from casper_db.repository import CaseStore; print(len(CaseStore(sys.argv[1]).list_for_target("LAB-DEMO")))', casePath], {
    encoding: 'utf8', env: { ...process.env, PYTHONPATH: [join(root, 'casper-db', 'src'), process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(runtimeQuery.status, 0, runtimeQuery.stderr);
  assert.equal(runtimeQuery.stdout.trim(), '0');

  const restored = await db.restoreCase('CASE-001', 'admin');
  assert.equal(restored.archived, false);
  assert.equal(restored.audit[0].action, 'restore');
  assert.equal((await db.listCases({})).total, 1);
  const audit = await db.listAudit({ limit: 20, offset: 0 });
  assert.equal(audit.total, 3);
  assert.ok(audit.logs.every(row => row.caseId === 'CASE-001' && !('details' in row)));
});

test('dashboard DB stages, reviews and removes an unpublished HWPX without local path disclosure', async t => {
  const folder = await mkdtemp(join(tmpdir(), 'ca3p-dashboard-upload-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const source = join(folder, 'sample.hwpx');
  const xml = '<section><p><run><t>취약점 유형: XSS</t></run></p>'
    + '<p><run><t>제목: 테스트 보고서</t></run></p>'
    + '<p><run><t>발생 URL: https://lab.example.invalid/search</t></run></p></section>';
  const zipped = spawnSync(python, ['-c',
    'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("Contents/section0.xml",sys.stdin.buffer.read()); z.close()', source], {
    input: Buffer.from(xml), encoding: 'buffer', env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(zipped.status, 0, String(zipped.stderr));
  const bytes = await readFile(source);
  const form = new FormData();
  form.append('targetId', 'LAB-DEMO');
  form.append('file', new Blob([bytes], { type: 'application/hwp+zip' }), 'uploaded.hwpx');
  const wire = new Request('http://localhost/upload', { method: 'POST', body: form });
  const request = Readable.from([Buffer.from(await wire.arrayBuffer())]);
  request.headers = { 'content-type': wire.headers.get('content-type') };

  const db = createDbManagement({ casePath: join(folder, 'cases.sqlite3'),
    workspacePath: join(folder, 'intake'), python });
  const staged = await db.stageUpload(request, { actor: 'admin' });
  const draftSha = staged.stage.draft_sha256;
  assert.match(draftSha, /^[a-f0-9]{64}$/);
  assert.match(staged.intake.draft.source.path, /^intake:[a-f0-9]{64}$/);
  assert.equal(staged.stage.draft_file, undefined);
  assert.equal((await db.listIntakes()).intakes.length, 1);

  const reviewed = await db.reviewIntake(draftSha, staged.intake.review, 'admin', staged.intake.validation_sha256);
  assert.equal(reviewed.intake.draft_sha256, draftSha);
  await assert.rejects(db.reviewIntake(draftSha, staged.intake.review, 'admin', staged.intake.validation_sha256),
    failure => failure.status === 409);
  const published = await db.publishIntake(draftSha,
    { expectedValidationSha: reviewed.intake.validation_sha256 }, 'admin');
  assert.equal(published.publish.case_database_written, false);
  const deleted = await db.deleteIntake(draftSha, 'admin');
  assert.equal(deleted.deleted, true);
  assert.equal((await db.listIntakes()).intakes.length, 0);
  assert.ok((await db.listAudit({ limit: 20, offset: 0 })).logs.some(row =>
    row.draftSha === draftSha && row.action === 'delete'));
});

test('reviewed HWPX publishes a Case into the runtime Case DB', async t => {
  const folder = await mkdtemp(join(tmpdir(), 'ca3p-dashboard-publish-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const source = join(folder, 'publish.hwpx');
  const xml = '<section><p><run><t>취약점 유형: XSS</t></run></p>'
    + '<p><run><t>제목: 검토 대상</t></run></p>'
    + '<p><run><t>발생 URL: https://lab.example.invalid/search</t></run></p></section>';
  const zipped = spawnSync(python, ['-c',
    'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("Contents/section0.xml",sys.stdin.buffer.read()); z.close()', source], {
    input: Buffer.from(xml), encoding: 'buffer', env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(zipped.status, 0, String(zipped.stderr));
  const form = new FormData();
  form.append('targetId', 'LAB-DEMO');
  form.append('file', new Blob([await readFile(source)], { type: 'application/hwp+zip' }), 'publish.hwpx');
  const wire = new Request('http://localhost/upload', { method: 'POST', body: form });
  const request = Readable.from([Buffer.from(await wire.arrayBuffer())]);
  request.headers = { 'content-type': wire.headers.get('content-type') };

  const casePath = join(folder, 'cases.sqlite3');
  const db = createDbManagement({ casePath, workspacePath: join(folder, 'intake'), python });
  const staged = await db.stageUpload(request, { actor: 'admin' });
  assert.equal(staged.intake.findings.length, 1);
  const { draft_sha256: draftSha } = staged.intake;
  const caseId = staged.intake.findings[0].case_id;
  const example = JSON.parse(await readFile(join(root, 'casper-db', 'examples', 'case.example.json'), 'utf8'));
  const review = structuredClone(staged.intake.review);
  review.items[0].decision = 'accept';
  review.items[0].reason = '원문과 검토 자료를 대조함';
  review.items[0].acknowledged_issue_codes = staged.intake.draft.findings[0].review_issues.map(issue => issue.code);
  for (const [name, value] of Object.entries(example)) {
    if (['case_id', 'target_id', 'status', 'source', 'source_report'].includes(name)) continue;
    review.items[0].resolutions[name] = { value, reason: '검토 자료에서 확인',
      source_refs: ['manual:case-example-fixture'] };
  }
  const reviewed = await db.reviewIntake(draftSha, review, 'admin', staged.intake.validation_sha256);
  assert.equal(reviewed.review.ready_cases, 1);
  assert.deepEqual(reviewed.review.blocked, []);
  await assert.rejects(db.publishIntake(draftSha,
    { expectedValidationSha: staged.intake.validation_sha256 }, 'admin'), failure => failure.status === 409);
  const published = await db.publishIntake(draftSha,
    { expectedValidationSha: reviewed.intake.validation_sha256 }, 'admin');
  assert.equal(published.publish.status, 'applied');
  assert.equal(published.publish.created, 1);
  assert.equal(published.publish.case_database_written, true);
  const persisted = await db.getCase(caseId);
  assert.equal(persisted.case.case_id, caseId);
  assert.equal(persisted.case.status, 'ready');
  assert.match(persisted.case.source_report, /^intake:[a-f0-9]{64}$/);
  assert.equal((await db.listCases({ targetId: 'LAB-DEMO' })).total, 1);
  await assert.rejects(db.deleteIntake(draftSha, 'admin'), failure => failure.status === 400);
});

test('authenticated HTTP DB flow uses the same Case DB and enforces mutations', async t => {
  const folder = await mkdtemp(join(tmpdir(), 'ca3p-dashboard-http-db-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const casePath = join(folder, 'cases.sqlite3');
  const dbManagement = createDbManagement({ casePath, workspacePath: join(folder, 'intake'), python });
  const runtime = { getState: () => ({ status: 'idle' }), subscribe: () => () => {}, close: async () => {} };
  const auth = createAuthentication({ users: ['admin', 'viewer'].map(role => hashAccount(role, 'test-password', role)) });
  const server = createDashboardServer({ runtime, auth, dbManagement,
    maintenanceCheck: async () => false, platformProvider: async () => ({}) });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, { method = 'GET', headers = {}, body } = {}) => {
    const response = await fetch(base + path, { method, headers, body });
    const text = await response.text();
    let value;
    try { value = JSON.parse(text); } catch { value = text; }
    return { status: response.status, body: value, headers: response.headers };
  };
  const login = async role => {
    const response = await call('/api/auth/login', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: role, password: 'test-password' }) });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0],
      'X-CSRF-Token': response.body.csrfToken };
  };
  const jsonHeaders = headers => ({ ...headers, 'Content-Type': 'application/json' });

  assert.equal((await call('/api/db/cases')).status, 401);
  const viewer = await login('viewer');
  assert.equal((await call('/api/db/cases', { headers: viewer })).status, 200);
  const admin = await login('admin');
  assert.deepEqual((await call('/api/db/intakes', { headers: admin })).body.intakes, []);

  const caseRecord = JSON.parse(await readFile(join(root, 'casper-db', 'examples', 'case.example.json'), 'utf8'));
  const inserted = spawnSync(python, ['-c', 'import json,sys; from casper_db.repository import CaseStore; p,c=json.load(sys.stdin); CaseStore(p).add(c)'], {
    input: JSON.stringify([casePath, caseRecord]), encoding: 'utf8',
    env: { ...process.env, PYTHONPATH: [join(root, 'casper-db', 'src'), process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(inserted.status, 0, inserted.stderr);
  assert.equal((await call('/api/db/cases?q=CASE-001', { headers: admin })).body.total, 1);
  const patch = await call('/api/db/cases/CASE-001', { method: 'PATCH', headers: jsonHeaders(admin),
    body: JSON.stringify({ patch: { title: 'HTTP 변경' }, expectedRevision: 1 }) });
  assert.equal(patch.status, 200);
  assert.equal(patch.body.case.revision, 2);
  const archived = await call('/api/db/cases/CASE-001', { method: 'DELETE', headers: jsonHeaders(admin),
    body: JSON.stringify({ reason: '보관 테스트' }) });
  assert.equal(archived.status, 200);
  assert.equal((await call('/api/db/cases', { headers: admin })).body.total, 0);
  assert.equal((await call('/api/db/cases?archived=true', { headers: admin })).body.total, 1);
  const restored = await call('/api/db/cases/CASE-001/restore', { method: 'POST', headers: jsonHeaders(admin), body: '{}' });
  assert.equal(restored.status, 200);
  assert.equal(restored.body.archived, false);

  const source = join(folder, 'api-report.hwpx');
  const xml = '<section><p><run><t>취약점 유형: XSS</t></run></p></section>';
  const zipped = spawnSync(python, ['-c',
    'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("Contents/section0.xml",sys.stdin.buffer.read()); z.close()', source], {
    input: Buffer.from(xml), encoding: 'buffer', env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
  });
  assert.equal(zipped.status, 0, String(zipped.stderr));
  const form = new FormData();
  form.append('targetId', 'LAB-DEMO');
  form.append('file', new Blob([await readFile(source)], { type: 'application/hwp+zip' }), 'api-report.hwpx');
  assert.equal((await call('/api/db/intakes', { method: 'POST', headers: viewer, body: form })).status, 403);
  const upload = await call('/api/db/intakes', { method: 'POST', headers: admin, body: form });
  assert.equal(upload.status, 201);
  const draftSha = upload.body.stage.draft_sha256;
  const detail = await call(`/api/db/intakes/${draftSha}`, { headers: admin });
  assert.equal(detail.status, 200);
  const review = await call(`/api/db/intakes/${draftSha}`, { method: 'PATCH', headers: jsonHeaders(admin),
    body: JSON.stringify({ review: detail.body.intake.review,
      expectedValidationSha: detail.body.intake.validation_sha256 }) });
  assert.equal(review.status, 200);
  const staleReview = await call(`/api/db/intakes/${draftSha}`, { method: 'PATCH', headers: jsonHeaders(admin),
    body: JSON.stringify({ review: detail.body.intake.review,
      expectedValidationSha: detail.body.intake.validation_sha256 }) });
  assert.equal(staleReview.status, 409);
  const publish = await call(`/api/db/intakes/${draftSha}/publish`, { method: 'POST', headers: jsonHeaders(admin),
    body: JSON.stringify({ expectedValidationSha: review.body.intake.validation_sha256 }) });
  assert.equal(publish.status, 200);
  assert.equal(publish.body.publish.case_database_written, false);
  const deleted = await call(`/api/db/intakes/${draftSha}`, { method: 'DELETE', headers: admin });
  assert.equal(deleted.status, 200);
  assert.equal(deleted.body.deleted, true);
});
