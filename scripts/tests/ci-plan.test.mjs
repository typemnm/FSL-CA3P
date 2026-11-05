import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSuitePlan, completeSuiteCoverage } from '../ci-plan.mjs';

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

test('report coverage includes Node integration, browser capture and Python without duplicate counts', async t => {
  const { root, manifest } = await fixture(t);
  manifest.modules.push({ id: 'report', path: 'packages/report', status: 'active' });
  for (const name of ['tests/integration.test.mjs', 'capture/tests/sandbox.test.mjs']) {
    const file = join(root, 'packages/report', name);
    await mkdir(join(file, '..'), { recursive: true });
    await writeFile(file, '');
  }
  const plan = await createSuitePlan({ root, manifest, pythonExecutable: 'casper-python',
    reportPythonExecutable: 'report-python' });
  assert.deepEqual(plan.problems, []);
  const report = plan.suites.find(suite => suite.id === 'report');
  assert.deepEqual(report.args.slice(2), [join(root, 'packages/report/tests/integration.test.mjs'),
    join(root, 'packages/report/capture/tests/sandbox.test.mjs')]);
  const python = plan.suites.find(suite => suite.id === 'report-python');
  assert.equal(python.moduleId, 'report');
  assert.equal(python.resultFormat, 'junit');
  assert.equal(python.command, 'report-python');
  assert.equal(python.cwd, join(root, 'packages/report/py'));
  assert.equal(python.args.at(-1), `--junitxml=${join(root, 'reports/ci/report-python.xml')}`);
  const jobs = plan.suites.map(({ id }) => ({ id }));
  assert.equal(completeSuiteCoverage({ ...plan, jobs }), true);
  assert.equal(completeSuiteCoverage({ ...plan, jobs: jobs.filter(job => job.id !== 'report-python') }), false);
  assert.equal(completeSuiteCoverage({ ...plan, jobs: jobs.filter(job => job.id !== 'report') }), false);
});

test('selecting report selects both languages and node-only intentionally excludes Python', async t => {
  const { root, manifest } = await fixture(t);
  manifest.modules.push({ id: 'report', path: 'packages/report', status: 'active' });
  await mkdir(join(root, 'packages/report/capture/tests'), { recursive: true });
  await writeFile(join(root, 'packages/report/capture/tests/sandbox.test.mjs'), '');
  const plan = await createSuitePlan({ root, manifest, selection: ['report'] });
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.suites.map(suite => suite.id), ['report', 'report-python']);
  const nodePlan = await createSuitePlan({ root, manifest, nodeOnly: true, selection: ['report'] });
  assert.deepEqual(nodePlan.problems, []);
  assert.deepEqual(nodePlan.suites.map(suite => suite.id), ['report']);
});
