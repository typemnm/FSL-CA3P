import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { executeReportProcess, generateReportDocument } from '../index.mjs';
import { createRunRepository } from '../../run-store/index.mjs';
import { createDashboardServer } from '../../../apps/api/server.mjs';
import { createAuthentication, hashAccount } from '../../../apps/api/auth.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const filename = '합성 저장형 XSS 검사 보고서.hwpx';
const runId = 'synthetic-report-integration';
const toolCall = (name, args) => ({ role: 'assistant', content: null, tool_calls: [{
  id: name, type: 'function', function: { name, arguments: JSON.stringify(args) },
}] });

/** No opt-in or skip: the report CI preflight must supply the actual Python writer. */
test('actual Python report agent produces a valid HWPX that survives storage, viewer download and DB reopen',
  { timeout: 30_000 }, async t => {
    const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
    await mkdir(temporaryRoot, { recursive: true });
    const directory = await mkdtemp(join(temporaryRoot, 'ri-'));
    const storePath = join(directory, 'runs.sqlite');
    let store; let api;
    let requests = 0; let protocolFailure;
    let report;
    const provider = http.createServer(async (req, res) => {
      try {
        if (req.method === 'GET' && req.url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>synthetic local target</p>'); return;
        }
        assert.equal(req.method, 'POST');
        assert.equal(req.url, '/chat/completions');
        assert.equal(req.headers.authorization, 'Bearer synthetic-report-integration-key');
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.equal(input.model, 'deepseek-flash');
        requests += 1;
        assert.ok(requests <= 2, 'the fake provider only allows the expected two turns');
        let message;
        if (requests === 1) message = toolCall('read_bundle', { path: 'run/report.json' });
        else {
          const tool = input.messages.find(item => item.role === 'tool' && item.tool_call_id === 'read_bundle');
          assert.ok(tool, 'second turn must include the real Python collector output');
          const observed = JSON.parse(JSON.parse(tool.content).content);
          assert.equal(observed.runId, runId);
          assert.equal(observed.report.finding.title, report.finding.title);
          message = toolCall('finish_report', { filename, model: {
            generatedAt: '2026-10-23T00:00:00Z', generator: { profile: 'stored_xss' },
            run: { ...report, metrics: { requestCount: 2 } },
            findings: [{ common: { title: report.finding.title, cwe: 'CWE-79', status: 'confirmed',
              location: { method: 'POST', path: '/api/posts', parameter: 'content' },
              severity: 'medium', summary: '합성 점검의 브라우저 실행 증거입니다.', remediation: '출력 인코딩을 적용합니다.' },
            reproduction: [{ step: 1, text: '합성 카나리를 게시합니다.' }],
            textEvidence: [{ label: '합성 payload', text: '<img data-synthetic="true">' }], checks: [] }],
            priorCases: [], guardrail: { decisions: [] }, safety: { synthetic: true },
            references: { collectors: [{ name: 'collect-run', driver: 'run-store', status: 'ok' }], verifiedByStorage: false },
          } });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ choices: [{ message }] }));
      } catch (error) {
        protocolFailure = error;
        res.writeHead(500, { 'Content-Type': 'application/json' }); res.end('{"error":"synthetic protocol mismatch"}');
      }
    });
    t.after(async () => {
      if (api) await api.shutdown();
      store?.close();
      provider.closeAllConnections();
      if (provider.listening) await new Promise(resolve => provider.close(resolve));
      await rm(directory, { recursive: true, force: true });
    });
    provider.listen(0, '127.0.0.1'); await once(provider, 'listening');
    const origin = `http://127.0.0.1:${provider.address().port}`;
    report = { schemaVersion: '1.0', runId, status: 'completed', testProfile: 'stored_xss_canary',
      target: { origin, mode: 'isolated_local_lab', application: 'owned-local-board' },
      finding: { title: '합성 저장형 XSS', cwe: 'CWE-79', severity: 'medium', status: 'confirmed' },
      startedAt: '2026-10-23T00:00:00Z', completedAt: '2026-10-23T00:00:01Z' };
    store = createRunRepository({ path: storePath });
    store.createRun({ id: runId, mode: 'local-lab-rule', modelId: 'rule-baseline', manifest: { runId },
      state: { id: runId, modelId: 'rule-baseline', mode: 'local-lab-rule', simulated: false, events: [] } });
    const lease = store.claimNext('synthetic-report-owner');
    store.saveState(lease, { ...store.getRun(runId), status: 'running', report });

    const localPython = fileURLToPath(new URL(`../../../.venv/${process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'}`, import.meta.url));
    const python = process.env.CA3P_REPORT_PYTHON || process.env.CASPER_DB_PYTHON || (existsSync(localPython) ? localPython : 'python3');
    // Override every provider setting and disable proxy discovery; only this
    // loopback fake provider can receive the synthetic request or fake key.
    const env = { ...process.env, CA3P_REPORT_PYTHON: python, DEEPSEEK_BASE_URL: origin,
      DEEPSEEK_MODEL: 'deepseek-flash', DEEPSEEK_API_KEY: 'synthetic-report-integration-key',
      HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '', http_proxy: '', https_proxy: '', all_proxy: '',
      NO_PROXY: '127.0.0.1', no_proxy: '127.0.0.1', PYTHONIOENCODING: 'utf-8' };
    let reportProcess;
    const document = await generateReportDocument({ run: store.getRun(runId), storePath, envFile: null, env, timeoutMs: 15_000,
      execute: async options => { reportProcess = await executeReportProcess(options); return reportProcess; } });
    assert.ifError(protocolFailure);
    assert.equal(document.status, 'ready', JSON.stringify({ document, requests, reportProcess }));
    assert.equal(requests, 2);
    assert.equal(document.filename, filename);
    assert.equal(document.sha256, hash(document.bytes));
    // Validate the actual ZIP container, mimetype and XML, not just a PK prefix.
    const inspection = spawnSync(python, ['-c', `import io,json,sys,zipfile,xml.etree.ElementTree as E
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as z:
    sections=[z.read(n).decode('utf-8') for n in z.namelist() if n.startswith('Contents/section') and n.endswith('.xml')]
    for section in sections: E.fromstring(section)
    print(json.dumps({'mimetype':z.read('mimetype').decode(),'sections':len(sections),'korean':'합성 저장형 XSS' in ''.join(sections),'escaped':'&lt;img' in ''.join(sections)}))`],
    { input: document.bytes, encoding: 'utf8', env, timeout: 10_000, maxBuffer: 1_000_000, windowsHide: true });
    assert.equal(inspection.status, 0, inspection.error?.message || inspection.stderr);
    const zip = JSON.parse(inspection.stdout);
    assert.equal(zip.mimetype, 'application/hwp+zip');
    assert.ok(zip.sections > 0); assert.equal(zip.korean, true); assert.equal(zip.escaped, true);

    const artifact = store.writeBinaryArtifact(runId, 'hwpx-report', document.bytes,
      { filename, contentType: 'application/hwp+zip', provenance: 'report-agent-generated' });
    store.saveState(lease, { ...store.getRun(runId), status: 'completed',
      reportDocument: { status: 'ready', artifactId: artifact.id, filename } });
    store.finish(lease, 'completed');
    async function downloadAsViewer() {
      const auth = createAuthentication({ users: [hashAccount('report-reader', 'synthetic-password', 'viewer')], trustedProxyIps: [] });
      api = createDashboardServer({ auth, runtime: { store, getState: () => ({}), close: async () => {} } });
      api.listen(0, '127.0.0.1'); await once(api, 'listening');
      const base = `http://127.0.0.1:${api.address().port}`;
      const route = `/api/runs/${runId}/report.hwpx`;
      assert.equal((await fetch(base + route)).status, 401);
      const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'report-reader', password: 'synthetic-password' }) });
      assert.equal(login.status, 200);
      const cookie = login.headers.get('set-cookie').split(';')[0];
      await login.arrayBuffer();
      const response = await fetch(base + route, { headers: { Cookie: cookie } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('content-type'), 'application/hwp+zip');
      assert.equal(decodeURIComponent(response.headers.get('content-disposition').split("UTF-8''")[1]), filename);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.deepEqual(bytes, document.bytes);
      assert.equal(hash(bytes), artifact.sha256);
      await api.shutdown(); api = null;
    }
    await downloadAsViewer();
    store.close(); store = createRunRepository({ path: storePath });
    assert.equal(store.getRun(runId).reportDocument.artifactId, artifact.id);
    await downloadAsViewer();
    assert.equal(requests, 2, 'downloads and reopening the registry must not call the model again');
  });
