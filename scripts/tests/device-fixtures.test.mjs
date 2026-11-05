import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { activateFixtures, backupFixtures, prepareFixtures, restoreFixtures, rollbackFixtures, stopFixtures, VOLUME_COPY_SCRIPT } from '../device-fixtures.mjs';

const sha = 'a'.repeat(40), imageId = `sha256:${'b'.repeat(64)}`;
const services = ['daehan', 'wonchang'];
const composeModel = () => ({ services: Object.fromEntries(services.map((service, i) => [service, {
  volumes: [{ type: 'volume', source: `${service}-data`, target: '/app/data' }],
  ports: [{ host_ip: '127.0.0.1', published: String(4101 + i), target: 4101 + i }],
}])), volumes: Object.fromEntries(services.map(service => [`${service}-data`, { name: `ca3p-universities_${service}-data` }])) });

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ca3p-fixtures-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const config = { deployRoot: root, runtimeDir: join(root, 'runtime'),
    fixtures: { enabled: true, project: 'ca3p-universities', dockerPath: '/docker' } };
  await mkdir(config.runtimeDir, { mode: 0o700 });
  const calls = [], executions = [];
  const execute = async (command, args, options) => {
    assert.equal(command, '/docker'); calls.push(args); executions.push({ args, options });
    if (args[0] === 'info') return '"1"';
    if (args[0] === 'volume') return services.map(service => `ca3p-universities_${service}-data`).join('\n');
    if (args[0] === 'container') return args.some(arg => arg.startsWith('volume=')) ? '' : args.find(arg => arg.startsWith('label=com.docker.compose.service=')).split('=').at(-1);
    if (args[0] === 'inspect') {
      const service = args.at(-1);
      return JSON.stringify({ imageId, running: service === 'daehan', labels: {
        'com.docker.compose.project': 'ca3p-universities', 'com.docker.compose.service': service,
        'com.docker.compose.project.config_files': '/old/compose.yaml' },
      mounts: [{ Destination: '/app/data', Type: 'volume', Name: `ca3p-universities_${service}-data` }] });
    }
    if (args.includes('config')) return JSON.stringify(composeModel());
    if (args[0] === 'run') return '{"ok":true}';
    return '';
  };
  return { root, config, calls, executions, execute };
}

test('fixture transaction builds SHA images first and preserves project volumes and original restart state', async t => {
  const { root, config, calls, executions, execute } = await fixture(t);
  const state = await prepareFixtures(config, '/new/release', sha, { execute });
  assert.equal(state.images.daehan, `ca3p-daehan:${sha}`);
  assert.equal(state.envFile, join(config.runtimeDir, 'experiment-reset.env'));
  assert.deepEqual(state.composeFiles.map(path => path.split('/').at(-1)),
    ['compose.yaml', 'compose.reset.yaml', 'compose.reset.host.yaml', `${sha}.json`]);
  assert.ok(calls.some(args => args.includes('--env-file') && args.includes(state.envFile)));
  assert.match(await readFile(state.envFile, 'utf8'), /CA3P_DAEHAN_RESET_TOKEN=/);
  assert.equal(state.copyImage, imageId); assert.equal(state.original.length, 2);
  assert.deepEqual(state.volumes.map(item => item.name), ['ca3p-universities_daehan-data', 'ca3p-universities_wonchang-data']);
  assert.ok(calls.some(args => args.slice(0, 2).join(' ') === 'image tag'));
  assert.ok(calls.some(args => args.includes('build')));
  assert.equal(calls.some(args => args.includes('stop') || args.includes('up')), false);
  await stopFixtures(state, { execute });
  const snapshot = join(root, 'snapshot'); await mkdir(snapshot);
  await backupFixtures(snapshot, state, { execute });
  await activateFixtures(state, { execute }); await stopFixtures(state, { execute });
  await restoreFixtures(snapshot, state, { execute }); await rollbackFixtures(state, { execute });
  const containers = calls.filter(args => args[0] === 'run');
  assert.equal(containers.length, 4);
  assert.ok(containers.every(args => args.includes('none') && args.includes('--read-only') && args.includes('never')));
  assert.ok(containers.slice(0, 2).every(args => args.some(arg => arg.includes('target=/data,readonly'))));
  assert.ok(containers.slice(2).every(args => args.some(arg => arg.includes('target=/snapshot,readonly'))));
  assert.equal(calls.some(args => args.includes('down') || args.includes('prune') || args.includes('-v')), false);
  assert.equal(calls.at(-1).at(-1), 'daehan');
  assert.equal(calls.at(-1).includes('wonchang'), false);
  assert.ok(calls.some(args => args.includes('create') && args.slice(-2).join(',') === 'daehan,wonchang'));
  assert.deepEqual(JSON.parse(await readFile(state.overridePath, 'utf8')).services.daehan, { image: `ca3p-daehan:${sha}` });
  assert.equal(state.logDirectory, join(root, 'logs', sha, 'fixtures'));
  assert.equal((await stat(state.logDirectory)).mode & 0o777, 0o700);
  const logFiles = executions.map(item => item.options.logFile);
  assert.equal(new Set(logFiles).size, logFiles.length);
  assert.ok(executions.every(item => item.options.stdoutOnly === true));
  assert.ok(logFiles.every(path => path.startsWith(`${state.logDirectory}/`) && /^[a-z-]+-[a-f0-9-]+\.log$/.test(path.slice(state.logDirectory.length + 1))));
  for (const operation of ['inspect', 'compose-config', 'compose-build', 'compose-up', 'backup', 'restore']) {
    assert.ok(logFiles.some(path => path.includes(`/${operation}-`)), operation);
  }
});

test('failed candidate logs are captured before rollback and never replace the activation error', async t => {
  const { config, execute, executions } = await fixture(t);
  const state = await prepareFixtures(config, '/new', sha, { execute });
  const failure = new Error('candidate exited');
  const diagnosticsFailure = new Error('diagnostics unavailable');
  const failedExecute = async (command, args, options) => {
    executions.push({ args, options });
    if (args.includes('up')) throw failure;
    if (args.includes('logs')) throw diagnosticsFailure;
    throw new Error('Unexpected command');
  };
  await assert.rejects(activateFixtures(state, { execute: failedExecute }), error => error === failure);
  const diagnostics = executions.at(-1);
  assert.deepEqual(diagnostics.args.slice(-5), ['--no-color', '--tail', '150', 'daehan', 'wonchang']);
  assert.ok(diagnostics.options.logFile.includes('/compose-logs-'));
  assert.equal(diagnostics.options.stdoutOnly, true);
});

test('default fixture executor keeps stdout JSON clean and saves private output on success and failure', async t => {
  const { root, config } = await fixture(t);
  const executable = join(root, 'fake-docker.mjs'), failureFile = join(root, 'fail-build');
  await writeFile(executable, `#!${process.execPath}\nimport {existsSync} from 'node:fs';\nconst args=process.argv.slice(2);\nprocess.stderr.write('diagnostic warning ../outside\\n');\nif(args[0]==='info') console.log('"1"');\nelse if(args[0]==='compose'&&args.includes('config')) console.log(${JSON.stringify(JSON.stringify(composeModel()))});\nelse if(args[0]==='compose'&&args.includes('build')) {console.log('build output');if(existsSync(${JSON.stringify(failureFile)}))process.exitCode=1;}\n`);
  await chmod(executable, 0o700);
  config.fixtures.dockerPath = executable;
  const state = await prepareFixtures(config, '/new', sha);
  const successfulLogs = await readdir(state.logDirectory);
  assert.ok(successfulLogs.some(name => name.startsWith('compose-build-')));
  for (const name of successfulLogs) {
    assert.match(name, /^[a-z-]+-[a-f0-9-]+\.log$/);
    assert.equal((await stat(join(state.logDirectory, name))).mode & 0o777, 0o600);
    assert.match(await readFile(join(state.logDirectory, name), 'utf8'), /diagnostic warning/);
  }
  await writeFile(failureFile, '1');
  await assert.rejects(prepareFixtures(config, '/new', sha), /Command failed/);
  const afterFailure = await readdir(state.logDirectory);
  const failureLogs = afterFailure.filter(name => !successfulLogs.includes(name) && name.startsWith('compose-build-'));
  assert.equal(failureLogs.length, 1);
  assert.match(await readFile(join(state.logDirectory, failureLogs[0]), 'utf8'), /build output[\s\S]*diagnostic warning/);
  assert.equal((await stat(join(state.logDirectory, failureLogs[0]))).mode & 0o777, 0o600);
});

test('fixture compose may publish loopback reset management ports', async t => {
  const { config, execute } = await fixture(t);
  const withManagement = async (command, args, options) => {
    if (args.includes('config')) {
      const model = composeModel();
      for (const [index, service] of services.entries()) {
        model.services[service].ports.push({
          host_ip: '127.0.0.1', published: String(54101 + index), target: 54101 + index,
        });
      }
      return JSON.stringify(model);
    }
    return execute(command, args, options);
  };
  const state = await prepareFixtures(config, '/new/release', sha, { execute: withManagement });
  assert.equal(state.enabled, true);
});

test('disabled fixture configuration is a no-op, and mismatched project or data volumes fail closed', async t => {
  assert.deepEqual(await prepareFixtures({}, '/new', sha), { enabled: false });
  await stopFixtures({ enabled: false }); await activateFixtures({ enabled: false }); await rollbackFixtures({ enabled: false });
  const { config, execute } = await fixture(t);
  await assert.rejects(prepareFixtures({ ...config, fixtures: { ...config.fixtures, project: 'other' } }, '/new', sha, { execute }), /configuration/);
  const modified = async (command, args, options) => {
    if (args.includes('config')) { const model = composeModel(); model.volumes['daehan-data'].name = 'new-empty-volume'; return JSON.stringify(model); }
    return execute(command, args, options);
  };
  await assert.rejects(prepareFixtures(config, '/new', sha, { execute: modified }), /volume names/);
});

test('volume copying restores original data and verifies the entire backup before replacing live contents', async t => {
  const { root } = await fixture(t);
  const volume = join(root, 'volume'), snapshot = join(root, 'snapshot');
  await mkdir(join(volume, 'nested'), { recursive: true }); await mkdir(snapshot);
  await writeFile(join(volume, 'nested/cases.sqlite'), 'original database bytes');
  const run = mode => JSON.parse(execFileSync(process.execPath, ['-e', VOLUME_COPY_SCRIPT, mode, volume, snapshot], { encoding: 'utf8', stdio: 'pipe' }));
  assert.equal(run('backup').ok, true);
  await writeFile(join(volume, 'nested/cases.sqlite'), 'mutated'); await writeFile(join(volume, 'new.sqlite'), 'new');
  assert.equal(run('restore').ok, true);
  assert.equal(await readFile(join(volume, 'nested/cases.sqlite'), 'utf8'), 'original database bytes');
  await assert.rejects(readFile(join(volume, 'new.sqlite')), /ENOENT/);
  await writeFile(join(volume, 'keep.sqlite'), 'must remain on invalid backup');
  await writeFile(join(snapshot, 'files/nested/cases.sqlite'), 'tampered');
  assert.throws(() => run('restore'), /Command failed/);
  assert.equal(await readFile(join(volume, 'keep.sqlite'), 'utf8'), 'must remain on invalid backup');
});

test('volume copying rejects symbolic links rather than following data outside the managed volume', async t => {
  const { root } = await fixture(t);
  const volume = join(root, 'volume'), snapshot = join(root, 'snapshot');
  await mkdir(volume); await mkdir(snapshot); await writeFile(join(root, 'outside'), 'private');
  await symlink(join(root, 'outside'), join(volume, 'unsafe'));
  assert.throws(() => execFileSync(process.execPath, ['-e', VOLUME_COPY_SCRIPT, 'backup', volume, snapshot], { stdio: 'pipe' }), /Command failed/);
  await assert.rejects(readFile(join(snapshot, 'manifest.json')), /ENOENT/);
});
