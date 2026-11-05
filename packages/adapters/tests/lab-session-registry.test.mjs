import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocalLab } from '../local-lab-gateway.mjs';
import { prepareLabSessionCleanup, registerLabSession } from '../lab-session-registry.mjs';

async function fixture(t, pid) {
  const state = await mkdtemp(join(tmpdir(), 'ca3p-session-registry-test-'));
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-local-lab-'));
  t.after(() => Promise.all([rm(state, { recursive: true, force: true }), rm(directory, { recursive: true, force: true })]));
  const registryPath = join(state, 'lab-sessions');
  const registration = await registerLabSession({ registryPath, directory, pid });
  const [name] = await readdir(registryPath);
  return { registryPath, directory, registration, entry: join(registryPath, name) };
}

test('only a dead registered lab with a matching token is removed', async t => {
  const exited = spawnSync(process.execPath, ['-e', '']);
  assert.equal(exited.status, 0);
  const value = await fixture(t, exited.pid);
  const plan = await prepareLabSessionCleanup(value.registryPath);
  assert.ok(await readFile(join(value.directory, '.ca3p-lab-owner.json')));
  assert.deepEqual(await plan.execute(), { removed: 1 });
  assert.deepEqual(await readdir(value.registryPath), []);
  await assert.rejects(readFile(join(value.directory, '.ca3p-lab-owner.json')), error => error.code === 'ENOENT');
});

test('an active process blocks cleanup and preserves its owned directory', async t => {
  const value = await fixture(t, process.pid);
  await assert.rejects(prepareLabSessionCleanup(value.registryPath), error => error.status === 409);
  assert.ok(await readFile(join(value.directory, '.ca3p-lab-owner.json')));
  await value.registration.unregister();
  assert.deepEqual(await readdir(value.registryPath), []);
});

test('owner mismatch or changed registry data is refused before deleting a directory', async t => {
  const exited = spawnSync(process.execPath, ['-e', '']);
  const value = await fixture(t, exited.pid);
  const plan = await prepareLabSessionCleanup(value.registryPath);
  await writeFile(join(value.directory, '.ca3p-lab-owner.json'), JSON.stringify({ id: 'different', token: 'different' }));
  await assert.rejects(plan.execute(), error => error.status === 409);
  assert.ok(await readFile(value.entry));
});

test('unregistered temporary directories are never swept', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-local-lab-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, 'keep.json'), 'unowned');
  assert.deepEqual(await (await prepareLabSessionCleanup()).execute(), { removed: 0 });
  assert.equal(await readFile(join(directory, 'keep.json'), 'utf8'), 'unowned');
});

test('registry paths and recorded directory boundaries are validated', async t => {
  await assert.rejects(prepareLabSessionCleanup('../lab-sessions'), error => error.status === 409);
  const exited = spawnSync(process.execPath, ['-e', '']);
  const value = await fixture(t, exited.pid);
  const record = JSON.parse(await readFile(value.entry, 'utf8'));
  await writeFile(value.entry, JSON.stringify({ ...record, directory: tmpdir() }));
  await assert.rejects(prepareLabSessionCleanup(value.registryPath), error => error.status === 409);
  assert.ok(await readFile(join(value.directory, '.ca3p-lab-owner.json')));
});

test('a managed private board registers its active process and unregisters after shutdown', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-session-gateway-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const registryPath = join(directory, 'lab-sessions');
  const lab = await startLocalLab({ cleanupRegistryPath: registryPath });
  t.after(() => lab.close());
  assert.equal((await readdir(registryPath)).length, 1);
  await assert.rejects(prepareLabSessionCleanup(registryPath), error => error.status === 409);
  await lab.close();
  assert.deepEqual(await readdir(registryPath), []);
});

test('a board exits when its worker IPC channel disappears and its owned residue is recoverable', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-session-disconnect-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const registryPath = join(directory, 'lab-sessions');
  const source = new URL('../local-lab-gateway.mjs', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e',
    `import { startLocalLab } from ${JSON.stringify(source)}; await startLocalLab({ cleanupRegistryPath: ${JSON.stringify(registryPath)} }); process.exit(0);`],
  { timeout: 15_000, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  let plan;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { plan = await prepareLabSessionCleanup(registryPath); break; }
    catch (error) { if (attempt === 99) throw error; await new Promise(resolve => setTimeout(resolve, 20)); }
  }
  assert.deepEqual(await plan.execute(), { removed: 1 });
});
