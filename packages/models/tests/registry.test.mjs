import test from 'node:test';
import assert from 'node:assert/strict';
import { listModels } from '../registry.mjs';

test('model registry exposes a real rule baseline without credentials', () => {
  const models = listModels({ env: {}, envFile: false });
  assert.equal(models[0].available, true);
  assert.ok(models.slice(1).every(row => !row.available));
  assert.ok(models.slice(1).every(row => row.supportedModes.includes('local-lab-general')));
  assert.ok(!models[0].supportedModes.includes('local-lab-general'));
  assert.deepEqual(models.map(row => row.mode), ['local-lab-rule', 'local-lab-general', 'local-lab-general']);
  assert.ok(models.every(row => !row.supportedModes.some(mode => ['core-fixture', 'local-lab-deepseek'].includes(mode))));
});
