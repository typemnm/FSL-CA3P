import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const bytes = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 255]), Buffer.from('{"password":"synthetic-binary"}')]);
async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-report-api-'));
  const path = join(directory, 'document.hwpx');
  await writeFile(path, bytes);
  const artifact = { id: sha256('synthetic-hwpx'), runId: 'run-report', kind: 'hwpx-report', path,
    sha256: sha256(bytes), size: bytes.length, filename: '취약점 검사 보고서.hwpx', contentType: 'application/hwp+zip' };
  const run = { id: 'run-report', report: { status: 'completed' },
    reportDocument: { status: 'ready', artifactId: artifact.id, filename: artifact.filename } };
  const artifacts = new Map([[artifact.id, artifact]]);
  const store = { getRun: id => id === run.id ? run : null, getArtifact: id => artifacts.get(id) ?? null };
  const runtime = { store, getState: () => ({}), close: async () => {} };
  const auth = createAuthentication({ users: [hashAccount('reader', 'synthetic-password', 'viewer')] });
  const session = auth.login({ headers: {}, socket: { remoteAddress: '127.0.0.1' } }, { username: 'reader', password: 'synthetic-password' });
  const headers = { Cookie: session.cookie.split(';')[0] };
  const server = createDashboardServer({ runtime, auth });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { artifact, artifacts, run, path, get: (route = `/api/runs/${run.id}/report.hwpx`, options = {}) => fetch(base + route, { headers, ...options }) };
}

test('HWPX download requires authentication and preserves binary bytes and a Korean filename for viewers', async t => {
  const { get, artifact } = await setup(t);
  assert.equal((await get(undefined, { headers: {} })).status, 401);
  const result = await get();
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('content-type'), 'application/hwp+zip');
  assert.equal(result.headers.get('content-length'), String(bytes.length));
  assert.match(result.headers.get('content-disposition'), /^attachment; filename="ca3p-report.hwpx"; filename\*=UTF-8''/);
  assert.equal(decodeURIComponent(result.headers.get('content-disposition').split("UTF-8''")[1]), artifact.filename);
  assert.deepEqual(Buffer.from(await result.arrayBuffer()), bytes);
  assert.equal((await get(`/api/artifacts/${artifact.id}`)).status, 404);
});

test('HWPX route refuses another run artifact, non-HWPX artifacts, unavailable references and unready reports', async t => {
  const { get, artifact, run } = await setup(t);
  artifact.runId = 'other-run'; assert.equal((await get()).status, 404);
  artifact.runId = run.id; artifact.kind = 'run-report'; assert.equal((await get()).status, 404);
  artifact.kind = 'hwpx-report'; run.reportDocument.artifactId = sha256('missing'); assert.equal((await get()).status, 404);
  run.reportDocument.artifactId = artifact.id;
  for (const status of ['generating', 'failed', 'unavailable', 'skipped']) {
    run.reportDocument.status = status; assert.equal((await get()).status, 409);
  }
  assert.equal((await get('/api/runs/missing/report.hwpx')).status, 404);
});

test('HWPX download detects altered bytes, missing files, and cannot accept a caller file path', async t => {
  const { get, path } = await setup(t);
  await writeFile(path, Buffer.alloc(bytes.length, 42));
  assert.equal((await get()).status, 409);
  await rm(path);
  assert.equal((await get()).status, 404);
  assert.equal((await get('/api/runs/..%2Freport/report.hwpx?path=anything')).status, 404);
});

test('download filenames cannot inject headers or directory paths', async t => {
  const { get, artifact } = await setup(t);
  artifact.filename = '../가상\\보고서\r\nX-Test: injected.hwpx';
  const result = await get();
  assert.equal(result.status, 200); assert.equal(result.headers.get('x-test'), null);
  const filename = decodeURIComponent(result.headers.get('content-disposition').split("UTF-8''")[1]);
  assert.ok(!/[\\/\r\n]/.test(filename)); assert.ok(filename.endsWith('.hwpx'));
});

test('general report route downloads only ready documents linked to confirmed findings', async t => {
  const { get, artifact, artifacts, run, path } = await setup(t);
  const secondBytes = Buffer.from('PK\x03\x04second-confirmed-finding');
  const secondPath = join(path, '..', 'second.hwpx');
  await writeFile(secondPath, secondBytes);
  const second = { ...artifact, id: sha256('synthetic-hwpx-second'), path: secondPath,
    sha256: sha256(secondBytes), size: secondBytes.length, filename: '두번째 취약점.hwpx',
    findingId: 'finding:h2' };
  artifacts.set(second.id, second);
  artifact.findingId = 'finding:h1';
  run.report = { status: 'completed', assessmentMode: 'general', findings: [
    { id: 'finding:h1', status: 'confirmed' }, { id: 'finding:h2', status: 'confirmed' },
    { id: 'finding:h3', status: 'not_reproduced' },
  ] };
  run.reportDocuments = { schemaVersion: 'general-report-documents/1', status: 'ready', items: [
    { findingId: 'finding:h1', status: 'ready', artifactId: artifact.id, filename: artifact.filename },
    { findingId: 'finding:h2', status: 'ready', artifactId: second.id, filename: second.filename },
  ] };
  for (const [record, expected] of [[artifact, bytes], [second, secondBytes]]) {
    const route = `/api/runs/${run.id}/reports/${record.id}.hwpx`;
    assert.equal((await get(route, { headers: {} })).status, 401);
    const response = await get(route);
    assert.equal(response.status, 200);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), expected);
    assert.equal(decodeURIComponent(response.headers.get('content-disposition').split("UTF-8''")[1]), record.filename);
  }
  assert.equal((await get(`/api/runs/${run.id}/reports/${sha256('unlinked')}.hwpx`)).status, 404);
  assert.equal((await get(`/api/runs/other-run/reports/${artifact.id}.hwpx`)).status, 404);
  assert.equal((await get(`/api/artifacts/${second.id}`)).status, 404);
});

test('general report route rejects unready, unrelated, unconfirmed, and altered documents', async t => {
  const { get, artifact, run, path } = await setup(t);
  const route = `/api/runs/${run.id}/reports/${artifact.id}.hwpx`;
  artifact.findingId = 'finding:h1';
  run.report = { status: 'completed', assessmentMode: 'general',
    findings: [{ id: 'finding:h1', status: 'confirmed' }] };
  const item = { findingId: 'finding:h1', status: 'ready', artifactId: artifact.id, filename: artifact.filename };
  run.reportDocuments = { schemaVersion: 'general-report-documents/1', status: 'ready', items: [item] };
  run.report.assessmentMode = 'legacy'; assert.equal((await get(route)).status, 404);
  run.report.assessmentMode = 'general'; run.reportDocuments.schemaVersion = 'unknown';
  assert.equal((await get(route)).status, 404);
  run.reportDocuments.schemaVersion = 'general-report-documents/1';
  item.status = 'failed'; assert.equal((await get(route)).status, 409);
  item.status = 'ready'; run.report.findings[0].status = 'not_reproduced'; assert.equal((await get(route)).status, 409);
  run.report.findings[0].status = 'confirmed'; artifact.runId = 'other-run'; assert.equal((await get(route)).status, 404);
  artifact.runId = run.id; artifact.kind = 'run-report'; assert.equal((await get(route)).status, 404);
  artifact.kind = 'hwpx-report'; artifact.findingId = 'finding:other'; assert.equal((await get(route)).status, 404);
  artifact.findingId = item.findingId; artifact.filename = 'unexpected.hwpx'; assert.equal((await get(route)).status, 404);
  artifact.filename = item.filename; await writeFile(path, Buffer.alloc(bytes.length, 42));
  assert.equal((await get(route)).status, 409);
});
