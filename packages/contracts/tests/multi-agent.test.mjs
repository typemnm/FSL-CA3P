import test from 'node:test';
import assert from 'node:assert/strict';
import { validateMultiAgentOptions } from '../multi-agent.mjs';

test('multi-agent follow-up is opt-in and expands bounded defaults', () => {
  assert.equal(validateMultiAgentOptions(undefined), undefined);
  assert.deepEqual(validateMultiAgentOptions({ enabled: true }),
    { enabled: true, maxConcurrentAgents: 2, maxTasks: 4 });
  assert.deepEqual(validateMultiAgentOptions({ enabled: true, maxConcurrentAgents: 1, maxTasks: 1 }),
    { enabled: true, maxConcurrentAgents: 1, maxTasks: 1 });
});

test('multi-agent options reject unknown or excessive work', () => {
  for (const options of [null, false, {}, { enabled: false }, { enabled: true, maxTasks: 0 },
    { enabled: true, maxTasks: 5 }, { enabled: true, maxConcurrentAgents: 3 },
    { enabled: true, maxConcurrentAgents: 2, maxTasks: 1 },
    { enabled: true, maxTasks: '4' }, { enabled: true, target: 'https://other.invalid' }]) {
    assert.throws(() => validateMultiAgentOptions(options), { code: 'INVALID_MULTI_AGENT_OPTIONS', status: 400 });
  }
});
