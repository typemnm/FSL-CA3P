import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSuitePlan } from '../ci-plan.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ca3p-ci-plan-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'dashboard', 'tests'), { recursive: true });
  await writeFile(join(root, 'dashboard', 'tests', 'ui.test.mjs'), '');
  await writeFile(join(root, 'dashboard', 'tests', 'catalog.test.mjs'), '');
  const manifest = { modules: [
    { id: 'dashboard', path: 'dashboard', status: 'active' },
    { id: 'catalog', path: 'catalog', status: 'active' },
    { id: 'casper-db', path: 'casper-db', status: 'active' },
  ], ci: { suiteAssignments: { catalog: ['dashboard/tests/catalog.test.mjs'] } } };
  return { root, manifest };
}

test('integration tests have one reporting owner and every active module has a suite', async t => {
  const { root, manifest } = await fixture(t);
  const plan = await createSuitePlan({ root, manifest, nodeExecutable: 'node', pythonExecutable: 'python' });
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.activeIds, ['dashboard', 'catalog', 'casper-db']);
  assert.deepEqual(plan.suites.map(item => item.id), ['dashboard', 'catalog', 'casper-db']);
  assert.deepEqual(plan.suites.find(item => item.id === 'dashboard').args.slice(2),
    [join(root, 'dashboard/tests/ui.test.mjs')]);
  assert.deepEqual(plan.suites.find(item => item.id === 'catalog').args.slice(2),
    [join(root, 'dashboard/tests/catalog.test.mjs')]);
});

test('missing assignments and untested active modules fail discovery', async t => {
  const { root, manifest } = await fixture(t);
  manifest.ci.suiteAssignments.catalog = ['dashboard/tests/removed.test.mjs'];
  manifest.modules.push({ id: 'worker', path: 'worker', status: 'active' });
  const plan = await createSuitePlan({ root, manifest });
  assert.ok(plan.problems.some(value => value.includes('undiscovered test')));
  assert.ok(plan.problems.some(value => value.includes('no test suite: catalog')));
  assert.ok(plan.problems.some(value => value.includes('no test suite: worker')));
});

test('partial Node checks cannot accidentally include the Python suite', async t => {
  const { root, manifest } = await fixture(t);
  const plan = await createSuitePlan({ root, manifest, nodeOnly: true, selection: ['casper-db'] });
  assert.ok(plan.problems.some(value => value.includes('requires Python')));
  assert.equal(plan.suites.some(item => item.id === 'casper-db'), false);
});
