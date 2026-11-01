import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createRunService } from '../../application/run-service.mjs';

async function waitFor(service, id) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const run = service.getRun(id);
    if (run.pendingApproval) {
      await service.decideApproval(id, run.pendingApproval.id, 'approve', 'ci');
    }
    if (['completed', 'failed', 'cancelled', 'interrupted'].includes(run.status)) return run;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('university worker did not finish');
}

test('real university worker pins reads, persists evidence, and reopens without model/report calls', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'idor-worker-'));
  const storePath = join(directory, 'runs.sqlite');
  const services = [];
  const servers = [];
  t.after(async () => {
    for (const service of services.reverse()) await service.close();
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    rmSync(directory, { recursive: true, force: true });
  });
  const service = createRunService({ storePath, importLegacy: false, envFile: null,
    env: { ...process.env, DEEPSEEK_API_KEY: '' } });
  services.push(service);
  for (const [siteKey, endpoint, ownerField, prefix, denyCross] of [
    ['daehan', '/api/admissions/partner/applications', 'partner_user_id', 'partner', false],
    ['wonchang', '/api/staff/mobile/cases', 'staff_user_id', 'staff', true],
  ]) {
    const reads = [];
    const server = createServer(async (req, res) => {
      if (req.method === 'POST' && req.url === '/login') {
        let body = ''; for await (const chunk of req) body += chunk;
        const account = new URLSearchParams(body).get('username');
        res.writeHead(302, { location: '/mypage', 'set-cookie': `sid=${account}private; HttpOnly; Path=/` });
        res.end(); return;
      }
      const match = new RegExp(`^${endpoint}/(1|3)$`).exec(req.url);
      if (req.method !== 'GET' || !match) { res.writeHead(404); res.end(); return; }
      const id = Number(match[1]);
      const student = req.headers.cookie === 'sid=student1private';
      const cross = req.headers.cookie === `sid=${prefix}1private` && id === 3;
      reads.push({ method: req.method, path: req.url });
      res.writeHead(student ? 403 : denyCross && cross ? 404 : 200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(student || denyCross && cross ? { error: 'forbidden' }
        : { id, [ownerField]: id === 1 ? 4 : 5, privateBody: 'DO_NOT_PERSIST' }));
    });
    servers.push(server);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const queued = await service.startLab({ fixtureId: `vul-web2-${siteKey}`, target: origin });
    const final = await waitFor(service, queued.run.id);
    assert.equal(final.status, 'completed', final.error);
    assert.equal(final.target, origin);
    assert.equal(final.report.runId, final.id);
    assert.equal(final.report.finding.status, denyCross ? 'not_confirmed' : 'confirmed');
    assert.equal(final.report.evidence.length, 4);
    assert.equal(final.events.filter(event => event.stage === 'approval.requested').length, 1);
    assert.equal(final.events.filter(event => event.stage === 'approval.resolved').length, 1);
    assert.equal(final.events.length, 8);
    assert.equal(final.step, 8);
    assert.equal(final.targetContacted, true);
    assert.equal(final.modelCalls.length, 0);
    assert.equal(final.reportDocument.errorCode, 'IDOR_DOCUMENT_UNSUPPORTED');
    assert.equal(final.historyWrite.status, 'skipped');
    assert.ok(final.artifacts.some(item => item.kind === 'run-report'));
    assert.equal(reads.length, 4);
    assert.doesNotMatch(JSON.stringify(final), /DO_NOT_PERSIST|sid=|Partner2026|Staff2026|Welcome2026/);
  }
  await service.close();
  const reopened = createRunService({ storePath, autoStartWorker: false, importLegacy: false, envFile: null, env: {} });
  services.push(reopened);
  const history = reopened.listRuns().items;
  assert.equal(history.length, 2);
  assert.ok(history.every(item => reopened.getRun(item.id).report.evidence.length === 4));
});
