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
