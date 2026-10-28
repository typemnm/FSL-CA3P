import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');

test('report preview requires a session, matching finding and intact stored HTML or Markdown', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-report-preview-'));
  const path = join(directory, 'preview.bin');
  const bytes = Buffer.from('# 검사 보고서\n\n| 구분 | 결과 |\n| --- | --- |\n| 검증 | 완료 |\n');
  await writeFile(path, bytes);
  const htmlPath = join(directory, 'preview.html');
  const htmlBytes = Buffer.from('<!doctype html><html><body><table><tr><td>완료</td></tr></table></body></html>');
  await writeFile(htmlPath, htmlBytes);
  const previewId = sha256('preview-artifact');
  const htmlId = sha256('html-preview-artifact');
  const run = { id: 'preview-run', report: { assessmentMode: 'general',
    findings: [{ id: 'finding:h1', status: 'confirmed' }] },
  reportDocuments: { schemaVersion: 'general-report-documents/1', items: [{
    findingId: 'finding:h1', status: 'ready', artifactId: sha256('hwpx-artifact'),
    previewArtifactId: previewId, previewHtmlArtifactId: htmlId, filename: '검사 보고서.hwpx',
  }] } };
  const artifact = { id: previewId, runId: run.id, kind: 'report-preview', findingId: 'finding:h1',
    path, sha256: sha256(bytes), size: bytes.length };
  const htmlArtifact = { id: htmlId, runId: run.id, kind: 'report-preview-html', findingId: 'finding:h1',
    path: htmlPath, sha256: sha256(htmlBytes), size: htmlBytes.length };
  const runtime = { getRun: id => id === run.id ? run : null,
    store: { getArtifact: id => id === previewId ? artifact : id === htmlId ? htmlArtifact : null },
    close: async () => {}, subscribe: () => () => {}, getState: () => ({}) };
  const auth = createAuthentication({ users: [hashAccount('viewer', 'password', 'viewer')] });
  const server = createDashboardServer({ runtime, auth, platformProvider: async () => ({ modules: [] }),
    maintenanceCheck: async () => false });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const endpoint = `${base}/api/runs/${run.id}/report-preview/finding:h1`;

  assert.equal((await fetch(endpoint)).status, 401);
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'viewer', password: 'password' }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const headers = { Cookie: cookie };
  const response = await fetch(endpoint, { headers });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { html: htmlBytes.toString('utf8'), filename: '검사 보고서.hwpx' });
  delete run.reportDocuments.items[0].previewHtmlArtifactId;
  const fallback = await fetch(endpoint, { headers });
  assert.equal(fallback.status, 200);
  assert.deepEqual(await fallback.json(), { markdown: bytes.toString('utf8'), filename: '검사 보고서.hwpx' });
  run.reportDocuments.items[0].previewHtmlArtifactId = htmlId;
  assert.equal((await fetch(`${base}/api/runs/${run.id}/report-preview/finding:h2`, { headers })).status, 404);

  await writeFile(htmlPath, 'tampered report');
  const changed = await fetch(endpoint, { headers });
  assert.equal(changed.status, 409);
  assert.doesNotMatch(await changed.text(), /tampered report/);
});
