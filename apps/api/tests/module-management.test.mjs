import test from 'node:test';
import assert from 'node:assert/strict';
import { createModuleManagement } from '../module-management.mjs';

test('module management shows deployed configuration and bounded run logs without request payloads', async () => {
  const modules = createModuleManagement({
    platformProvider: async () => ({ source: { commitSha: 'revision-test' }, modules: [
      { id: 'attack-module', status: 'active', version: '1.0', contentDigest: 'attack-digest', path: 'attack-module' },
      { id: 'xss-parser', status: 'replaced', contentDigest: null, path: 'xss-parser' },
      { id: 'web-parser', status: 'active', version: '2.0', contentDigest: 'parser-digest', path: 'web-parser' },
      { id: 'models', status: 'active', contentDigest: 'model-digest', path: 'packages/models' },
    ] }),
    runtime: {
      listModels: async () => [{ id: 'rule-baseline', available: true }],
      listRuns: async () => ({ items: [{ id: 'run-one', startedAt: '2026-10-28T00:00:00Z',
        events: [{ id: 'attack-event', module: 'attack-module', stage: 'execute', status: 'completed',
          time: '2026-10-28T00:01:00Z',
          sequence: 1, payload: { authorization: 'secret-data' } },
        { id: 'parser-event', module: 'xss-parser', stage: 'observe', sequence: 2 }],
        modelCalls: [{ requestedModel: 'deepseek-flash', status: 'completed', latencyMs: 12,
          usage: { total_tokens: 40 }, prompt: 'secret-prompt' }],
      }], total: 1 }),
    },
  });
  const list = await modules.list();
  assert.deepEqual(list.modules.map(item => item.id), ['attack', 'web-parser', 'guardrail', 'llm', 'db']);
  assert.equal(list.modules[0].contentDigest, 'attack-digest');
  const parser = await modules.config('web-parser');
  assert.equal(parser.config.runtimeModuleId, 'web-parser');
  assert.equal(parser.revision, 'parser-digest');
  assert.equal(parser.editable, false);
  const llm = await modules.config('llm');
  assert.equal(llm.config.models[0].id, 'rule-baseline');
  const attackLogs = await modules.logs('attack');
  assert.equal(attackLogs.logs.length, 1);
  assert.equal(attackLogs.logs[0].stage, 'execute');
  assert.equal(attackLogs.logs[0].createdAt, '2026-10-28T00:01:00Z');
  assert.doesNotMatch(JSON.stringify(attackLogs), /secret-data/);
  const modelLogs = await modules.logs('llm');
  assert.equal(modelLogs.logs[0].usage.total_tokens, 40);
  assert.doesNotMatch(JSON.stringify(modelLogs), /secret-prompt/);
  await assert.rejects(modules.logs('attack', { limit: 101 }), { status: 400 });
});

test('web_info.collected logs carry a whitelisted collection summary; other events stay unchanged', async () => {
  const artifactId = 'a'.repeat(64);
  const base = { module: 'web-parser', source: 'web-parser', stage: 'web_info.collected', type: 'info', title: '웹 정보 수집' };
  const modules = createModuleManagement({
    platformProvider: async () => ({ modules: [] }),
    runtime: { listRuns: async () => ({ items: [{ id: 'run-web', startedAt: '2026-10-28T00:00:00Z', events: [
      { ...base, id: 'web-ok', sequence: 1, time: '2026-10-28T00:00:03Z', detail: 'GET /board → HTTP 200',
        probeId: 'p-web-1', iteration: 2, asset: '/board?page=2', sessionRole: 'member', ok: true, status: 200,
        artifactId, counts: { technologies: 3, paths: 34, forms: 1, errors: 0 }, truncated: true,
        html: '<html>raw</html>', headers: [{ name: 'Cookie', value: 'sid=secret-cookie' }], request: { body: 'secret-body' } },
      { ...base, id: 'web-bad', sequence: 2, time: '2026-10-28T00:00:02Z',
        detail: 'Bearer abc.def line1\nline2\u0007 ' + 'x'.repeat(300),
        probeId: '<script>', iteration: -1, asset: 'https://user:pass@app.test/x?access_token=t1&page=2', sessionRole: 'role with space',
        ok: 'yes', status: 999, artifactId: 'A'.repeat(64), counts: { technologies: -1, paths: 1.5, forms: '3' }, truncated: 'true' },
      { id: 'legacy', module: 'xss-parser', stage: 'observe', status: 'completed', title: 'Legacy parse', sequence: 3,
        time: '2026-10-28T00:00:01Z', detail: 'legacy detail', asset: '/legacy', ok: true },
    ] }] }) },
  });
  const { logs } = await modules.logs('web-parser');
  const [ok, bad, legacy] = logs;
  assert.deepEqual(ok, { id: 'web-ok', runId: 'run-web', sequence: 1, module: 'web-parser', stage: 'web_info.collected',
    status: 200, title: '웹 정보 수집', createdAt: '2026-10-28T00:00:03Z', detail: 'GET /board → HTTP 200',
    asset: '/board?page=2', sessionRole: 'member', probeId: 'p-web-1', iteration: 2, ok: true, httpStatus: 200, artifactId,
    counts: { technologies: 3, paths: 34, forms: 1, errors: 0 }, truncated: true });
  assert.doesNotMatch(JSON.stringify(logs), /raw<\/html>|secret-cookie|secret-body|abc\.def|user:pass|t1/);
  assert.equal(bad.detail.length, 200);
  assert.match(bad.detail, /^Bearer \[REDACTED\] line1 line2/);
  assert.doesNotMatch(bad.detail, /[\u0000-\u001f]/u);
  assert.match(bad.asset, /^https:\/\/app\.test\/x\?access_token=%5BREDACTED%5D&page=2$/);
  assert.equal(bad.sessionRole, null);
  assert.equal(bad.probeId, null);
  assert.equal(bad.iteration, null);
  assert.equal(bad.ok, false);
  assert.equal(bad.httpStatus, null);
  assert.equal(bad.status, 999);
  assert.equal('artifactId' in bad, false);
  assert.deepEqual(bad.counts, { technologies: 0, paths: 0, forms: 0, errors: 0 });
  assert.equal(bad.truncated, false);
  assert.deepEqual(legacy, { id: 'legacy', runId: 'run-web', sequence: 3, module: 'xss-parser', stage: 'observe',
    status: 'completed', title: 'Legacy parse', createdAt: '2026-10-28T00:00:01Z' });
});

test('DB module logs show sanitized intake and Case audit entries', async () => {
  const modules = createModuleManagement({
    platformProvider: async () => ({ modules: [] }),
    runtime: { listRuns: async () => ({ items: [] }) },
    dbManagement: { listAudit: async () => ({ total: 1, logs: [{ caseId: 'CASE-001',
      action: 'archive', actor: 'admin', recordedAt: '2026-10-28T01:00:00Z',
      details: 'private report text' }] }) },
  });
  const result = await modules.logs('db');
  assert.equal(result.logs[0].caseId, 'CASE-001');
  assert.equal(result.logs[0].stage, 'archive');
  assert.doesNotMatch(JSON.stringify(result), /private report text/);
});
