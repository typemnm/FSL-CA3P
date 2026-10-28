import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRunService } from '../run-service.mjs';
import { digest } from '../../../packages/contracts/index.mjs';
import { PROJECT_ROOT } from '../../../packages/contracts/manifest.mjs';
import { prepareRunFileCleanup } from '../experiment-files.mjs';
import { prepareExperimentCleanup } from '../experiment-cleanup.mjs';

const python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
function sql(path, program) {
  const result = spawnSync(python, ['-c', program, path], { encoding: 'utf8', windowsHide: true,
    env: { ...process.env, PYTHONPATH: join(PROJECT_ROOT, 'casper-db/src') } });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  return result.stdout.trim();
}

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-experiment-reset-'));
  const storePath = join(directory, 'runs.sqlite'); const services = [];
  const calls = [];
  const defaults = { autoStartWorker: false, importLegacy: false, envFile: null,
    env: { ...process.env, DEEPSEEK_API_KEY: '', CASPER_DB_PATH: join(directory, 'absent-cases.sqlite3') },
    experimentFileOptions: { legacyReportsDir: join(directory, 'legacy-reports') },
    experimentCleanupFactory: async input => { calls.push(input); return { execute: async () => ({ files: 3 }) }; } };
  const open = extra => { const service = createRunService({ storePath, ...defaults, ...options, ...extra }); services.push(service); return service; };
  const service = open();
  t.after(async () => { for (const item of services.reverse()) await item.close(); rmSync(directory, { recursive: true, force: true }); });
  return { service, open, calls, directory, storePath };
}

test('confirmed reset removes all central history and publishes a new experiment epoch', async t => {
  const { service, open, calls } = setup(t);
  const first = await service.start({ mode: 'core-fixture' });
  service.stop(first.run.id);
  service.store.importLegacyRun({ runId: 'legacy-old', report: { runId: 'legacy-old', status: 'completed' } });
  assert.equal(service.experimentResetPreview().runCount, 2);
  const notices = []; const off = service.subscribe(value => notices.push(value));
  const result = await service.resetExperiment({ confirmed: true }); off();
  assert.equal(result.run.status, 'idle'); assert.equal(result.experimentReset.status, 'completed');
  assert.equal(result.experimentReset.deleted.runs, 2); assert.equal(result.experimentReset.files, 3);
  assert.equal(calls[0].runs.length, 2); assert.equal(service.listRuns().total, 0);
  assert.equal(result.experiment.epoch, 1); assert.equal(notices.at(-1).experiment.epoch, 1);
  const restarted = open({ importLegacy: true }); await restarted.ready;
  assert.equal(restarted.listRuns().total, 0);
  const fresh = await service.start({ mode: 'core-fixture' });
  assert.equal(fresh.run.manifest.experiment.epoch, 1);
  assert.equal(fresh.run.manifest.experiment.previousRunCount, 0);
  assert.equal(fresh.run.manifest.experiment.lastResetAt, result.experimentReset.completedAt);
});

test('unconfirmed requests and any queued run leave all data untouched', async t => {
  const { service, calls } = setup(t);
  for (const body of [undefined, {}, [], { confirmed: false }, { confirmed: 'true' }, { confirmed: true, target: '/' }]) {
    await assert.rejects(service.resetExperiment(body), { status: 400 });
  }
  await service.start({ mode: 'core-fixture' });
  const latest = await service.start({ mode: 'core-fixture' }); service.stop(latest.run.id);
  // The selected run is terminal, but another queued run must still block deletion.
  await assert.rejects(service.resetExperiment({ confirmed: true }), { code: 'RUN_ACTIVE' });
  assert.equal(calls.length, 0); assert.equal(service.listRuns().total, 2);
  assert.equal(service.getState().experiment.status, 'ready');
});

test('partial cleanup failure survives restart and blocks execution until a successful retry', async t => {
  let fails = true;
  const factory = async () => ({ execute: async () => { if (fails) throw new Error('fixture reset failed'); return { files: 1 }; } });
  const { service, open } = setup(t, { experimentCleanupFactory: factory });
  const run = await service.start({ mode: 'core-fixture' }); service.stop(run.run.id);
  await assert.rejects(service.resetExperiment({ confirmed: true }), { status: 503 });
  assert.equal(service.getState().experiment.status, 'failed');
  assert.equal(service.listRuns().total, 1);
  const restarted = open();
  assert.equal(restarted.getState().experiment.status, 'failed');
  await assert.rejects(restarted.start({ mode: 'core-fixture' }), { status: 409 });
  fails = false;
  await restarted.resetExperiment({ confirmed: true });
  assert.equal(service.getState().experiment.status, 'ready'); assert.equal(service.listRuns().total, 0);
});

test('reset excludes concurrent resets, new runs and external reviews across service instances', async t => {
  let allowCleanup; let cleanupStarted;
  const entered = new Promise(resolve => { cleanupStarted = resolve; });
  const gate = new Promise(resolve => { allowCleanup = resolve; });
  const { service, open } = setup(t, { experimentCleanupFactory: async () => ({ execute: async () => { cleanupStarted(); await gate; return {}; } }) });
  const second = open();
  const pending = service.resetExperiment({ confirmed: true }); await entered;
  try {
    await assert.rejects(service.resetExperiment({ confirmed: true }), { status: 409 });
    await assert.rejects(second.resetExperiment({ confirmed: true }), { code: 'EXPERIMENT_BUSY' });
    await assert.rejects(second.start({ mode: 'core-fixture' }), { status: 409 });
    await assert.rejects(second.withMutationLock(async () => {}), { status: 409 });
  } finally { allowCleanup(); }
  await pending;
});

test('an in-flight history review prevents reset until its external write finishes', async t => {
  const { service } = setup(t);
  let finish; const gate = new Promise(resolve => { finish = resolve; });
  const review = service.withMutationLock(() => gate);
  await assert.rejects(service.resetExperiment({ confirmed: true }), { code: 'EXPERIMENT_BUSY' });
  finish(); await review;
  assert.equal((await service.resetExperiment({ confirmed: true })).experiment.epoch, 1);
});

test('real cleanup removes run-derived files, preserves credentials and never resurrects deleted history', async t => {
  const { service, open, directory, storePath } = setup(t, { experimentCleanupFactory: prepareExperimentCleanup });
  const started = await service.start({ mode: 'core-fixture' }); const id = started.run.id; const hash = digest(id);
  const lease = service.store.claimNext('test-worker');
  const artifact = service.store.writeArtifact(id, 'run-report', { marker: 'prior-model-output' });
  service.store.saveState(lease, { ...started.run, coreRunId: 'old-core-alias', status: 'completed', events: [] });
  service.store.finish(lease, 'completed');
  const paths = [
    join(directory, 'case-snapshots', `${hash}.sqlite`),
    join(directory, 'case-snapshots', `${hash}.sqlite-wal`),
    join(directory, 'reports', hash, 'report-attempt', 'report.hwpx'),
    join(directory, 'legacy-reports', hash, 'report.json'),
    join(directory, 'legacy-reports', digest('old-core-alias'), 'report.json'),
  ];
  for (const path of paths) { mkdirSync(join(path, '..'), { recursive: true }); writeFileSync(path, 'prior-model-output'); }
  const credentials = join(directory, 'auth.json'); writeFileSync(credentials, 'preserve-login');
  const settings = join(directory, 'settings.json'); writeFileSync(settings, 'preserve-model-settings');
  const unrelated = join(directory, 'artifacts', 'operator-owned.txt'); writeFileSync(unrelated, 'preserve-user-file');
  const result = await service.resetExperiment({ confirmed: true });
  assert.equal(result.experimentReset.status, 'completed'); assert.equal(result.experimentReset.runFiles.files, 6);
  for (const path of [...paths, artifact.path]) assert.equal(existsSync(path), false, path);
  assert.equal(readFileSync(credentials, 'utf8'), 'preserve-login'); assert.equal(readFileSync(settings, 'utf8'), 'preserve-model-settings');
  assert.equal(readFileSync(unrelated, 'utf8'), 'preserve-user-file');
  assert.equal(existsSync(storePath), true);
  await service.close(); const reopened = open({ importLegacy: true }); await reopened.ready;
  assert.equal(reopened.listRuns().total, 0); assert.equal(reopened.getState().run.status, 'idle');
  const next = await reopened.start({ mode: 'core-fixture' });
  assert.equal(next.run.manifest.experiment.previousRunCount, 0);
});

test('history clear removes linked files and checks while preserving the later target reset obligation', async t => {
  const { service, open, calls, directory } = setup(t);
  const casesPath = join(directory, 'absent-cases.sqlite3');
  sql(casesPath, String.raw`
import sqlite3,sys
from casper_db.repository import SCHEMA_VERSION
with sqlite3.connect(sys.argv[1]) as c:
    c.executescript('CREATE TABLE cases(id TEXT); CREATE TABLE case_versions(id TEXT); CREATE TABLE checks(check_id TEXT,run_id TEXT,source TEXT,review_status TEXT);')
    c.execute('INSERT INTO cases VALUES (?)', ('curated',))
    c.executemany('INSERT INTO checks VALUES (?,?,?,?)', [('old-check','university-run','tool','reviewed'),('other-check','other-run','manual','reviewed')])
    c.execute('PRAGMA user_version=' + str(SCHEMA_VERSION))
`);
  const id = 'university-run'; const origin = 'http://127.0.0.1:4101';
  const manifest = { runId: id, target: { fixtureId: 'vul-web2-daehan', origin },
    data: { caseDatabaseSourcePath: casesPath } };
  const state = { id, mode: 'local-lab-general', status: 'queued', simulated: false,
    targetContacted: true, fixtureId: 'vul-web2-daehan', target: origin, coreTargetOrigin: origin, events: [] };
  service.store.createRun({ id, mode: state.mode, modelId: 'rule-baseline', manifest, state });
  const lease = service.store.claimNext('test-worker');
  service.store.saveState(lease, { ...state, status: 'completed' }); service.store.finish(lease, 'completed');
  const artifact = service.store.writeArtifact(id, 'run-report', { marker: 'old-run' });
  const reportPath = join(directory, 'reports', digest(id), 'report.hwpx');
  mkdirSync(join(reportPath, '..'), { recursive: true }); writeFileSync(reportPath, 'old-run');
  const credentials = join(directory, 'auth.json'); writeFileSync(credentials, 'keep-account');
  const result = await service.clearRunHistory({ confirmed: true });
  assert.equal(result.historyClear.status, 'completed');
  assert.equal(result.historyClear.deleted.runs, 1);
  assert.equal(result.historyClear.history.checksRemoved, 1);
  assert.equal(result.historyClear.pendingTargetResetCount, 1);
  assert.equal(result.experiment.status, 'failed');
  assert.equal(result.experiment.epoch, 1);
  assert.equal(service.listRuns().total, 0);
  assert.equal(calls.length, 0, 'history clear must not invoke target reset');
  assert.equal(existsSync(artifact.path), false);
  assert.equal(existsSync(reportPath), false);
  assert.equal(readFileSync(credentials, 'utf8'), 'keep-account');
  assert.equal(sql(casesPath, "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT count(*) FROM checks').fetchone()[0])"), '1');
  assert.equal(sql(casesPath, "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT count(*) FROM cases').fetchone()[0])"), '1');
  const restarted = open({ experimentCleanupFactory: prepareExperimentCleanup });
  await assert.rejects(restarted.resetExperiment({ confirmed: true }), { status: 409 });
  assert.equal(restarted.store.pendingTargetResets().length, 1);
  assert.equal(restarted.getState().experiment.status, 'failed');
});

test('history clear of isolated runs advances the epoch and permits another run', async t => {
  const { service } = setup(t);
  const first = await service.start({ mode: 'core-fixture' }); service.stop(first.run.id);
  const result = await service.clearRunHistory({ confirmed: true });
  assert.equal(result.experiment.status, 'ready');
  assert.equal(result.experiment.epoch, 1);
  assert.equal(service.listRuns().total, 0);
  const next = await service.start({ mode: 'core-fixture' });
  assert.equal(next.run.manifest.experiment.epoch, 1);
});

test('history clear retains an unmanaged contacted target blocker after runs disappear', async t => {
  const { service, open } = setup(t);
  const id = 'external-run';
  service.store.createRun({ id, mode: 'local-lab-general', modelId: 'rule-baseline', manifest: { runId: id },
    state: { id, status: 'queued', mode: 'local-lab-general', fixtureId: 'external-url',
      targetContacted: true, simulated: false, events: [] } });
  service.store.requestCancel(id);
  await service.clearRunHistory({ confirmed: true });
  assert.equal(service.listRuns().total, 0);
  assert.equal(service.store.pendingTargetResets()[0].targetContacted, true);
  const restarted = open({ experimentCleanupFactory: prepareExperimentCleanup });
  await assert.rejects(restarted.resetExperiment({ confirmed: true }), /외부 대상/);
  assert.equal(restarted.store.pendingTargetResets().length, 1);
});

test('file cleanup refuses links before deleting any other run-derived files', async t => {
  const { directory, storePath } = setup(t);
  const hash = digest('link-run'); const artifacts = join(directory, 'artifacts', hash);
  const outside = join(directory, 'operator-data'); mkdirSync(artifacts, { recursive: true }); mkdirSync(outside);
  const keep = join(outside, 'keep.txt'); writeFileSync(keep, 'never-delete');
  const normal = join(artifacts, 'owned.json'); writeFileSync(normal, 'run-data');
  symlinkSync(outside, join(artifacts, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(prepareRunFileCleanup({ runs: [{ id: 'link-run', artifacts: [] }], storePath,
    legacyReportsDir: join(directory, 'legacy-reports') }), { code: 'UNSAFE_EXPERIMENT_FILES' });
  assert.equal(readFileSync(keep, 'utf8'), 'never-delete'); assert.equal(existsSync(normal), true);
});

test('file cleanup refuses a junction in an ancestor of the configured store root', async t => {
  const { directory } = setup(t);
  const outside = join(directory, 'operator-owned'); const hash = digest('ancestor-run');
  const file = join(outside, 'runtime', 'reports', hash, 'report.json');
  mkdirSync(join(file, '..'), { recursive: true }); writeFileSync(file, 'never-delete');
  const linked = join(directory, 'linked-parent');
  symlinkSync(outside, linked, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(prepareRunFileCleanup({ runs: [{ id: 'ancestor-run', artifacts: [] }],
    storePath: join(linked, 'runtime', 'runs.sqlite'), legacyReportsDir: join(directory, 'legacy-reports') }), { code: 'UNSAFE_EXPERIMENT_FILES' });
  assert.equal(readFileSync(file, 'utf8'), 'never-delete');
});
