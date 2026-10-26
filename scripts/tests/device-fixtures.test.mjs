import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
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
  const config = { deployRoot: root, fixtures: { enabled: true, project: 'ca3p-universities', dockerPath: '/docker' } };
  const calls = [];
  const execute = async (command, args) => {
    assert.equal(command, '/docker'); calls.push(args);
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
  return { root, config, calls, execute };
}

test('fixture transaction builds SHA images first and preserves project volumes and original restart state', async t => {
  const { root, config, calls, execute } = await fixture(t);
  const state = await prepareFixtures(config, '/new/release', sha, { execute });
  assert.equal(state.images.daehan, `ca3p-daehan:${sha}`);
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
