import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';
import { ensureExperimentResetTokens } from './experiment-reset-env.mjs';

const execFileAsync = promisify(execFile);
const SERVICES = ['daehan', 'wonchang'];
const PROJECT = 'ca3p-universities';
const INSPECT = '{"name":{{json .Name}},"imageId":{{json .Image}},"image":{{json .Config.Image}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}}}';
const json = value => JSON.stringify(value, null, 2) + '\n';
async function privateLog(path, result) {
  await writeFile(path, `${result.stdout ?? ''}${result.stderr ? `\n${result.stderr}` : ''}`, { mode: 0o600 });
  await chmod(path, 0o600);
}
const defaultExecute = async (command, args, { timeoutMs = 600_000, cwd, logFile } = {}) => {
  let result;
  try { result = await execFileAsync(command, args, { timeout: timeoutMs, cwd, maxBuffer: 8_000_000 }); }
  catch (error) { if (logFile) await privateLog(logFile, error); throw error; }
  if (logFile) await privateLog(logFile, result);
  return result.stdout.trim();
};
const text = result => typeof result === 'string' ? result : result.stdout ?? result.output ?? '';
function operationName(args) {
  if (args[0] === 'compose') {
    return `compose-${args.find(arg => ['config', 'build', 'stop', 'up', 'create', 'logs'].includes(arg)) ?? 'command'}`;
  }
  if (args[0] === 'run') {
    const operation = args.at(-3);
    return ['backup', 'restore'].includes(operation) ? operation : 'run';
  }
  return ({ info: 'info', volume: 'volume-list', container: 'container-list', inspect: 'inspect', image: 'image-tag' })[args[0]] ?? 'command';
}
const command = async (state, args, options = {}) => {
  // Old crash journals predate logDirectory; retain private diagnostics during their recovery too.
  const directory = state.logDirectory ?? join(dirname(state.overridePath), '..', 'logs', basename(state.overridePath, '.json'), 'fixtures');
  if (!isAbsolute(directory)) throw new Error('Fixture command logs require an absolute private directory.');
  await mkdir(directory, { recursive: true, mode: 0o700 }); await chmod(directory, 0o700);
  const logFile = join(directory, `${operationName(args)}-${randomUUID()}.log`);
  return text(await (options.execute ?? defaultExecute)(state.dockerPath, args,
    { timeoutMs: options.timeoutMs ?? 180_000, logFile, stdoutOnly: true }));
};
const compose = (state, files = state.composeFiles ?? [state.composePath, state.overridePath]) => [
  'compose',
  ...(state.envFile ? ['--env-file', state.envFile] : []),
  '-p', state.project, ...files.flatMap(path => ['-f', path]),
];
async function privateJson(path, value) { await writeFile(path, json(value), { mode: 0o600 }); await chmod(path, 0o600); }

/** The same bounded implementation is tested outside Docker against temporary trees. */
export const VOLUME_COPY_SCRIPT = String.raw`
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [mode, volume, snapshot] = process.argv.slice(1);
const LIMIT_FILES = 10000, LIMIT_BYTES = 536870912;
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const filesRoot = path.join(snapshot, 'files');
function scan(root) {
  const files = [], dirs = []; let bytes = 0;
  const rootInfo = fs.lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('Unsafe tree root');
  function visit(relative) {
    for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
      const p = relative ? relative + '/' + name : name;
      if (p.length > 4096) throw new Error('Path length limit');
      const info = fs.lstatSync(path.join(root, p));
      const meta = {path:p, mode:info.mode & 0o777, uid:info.uid, gid:info.gid};
      if (info.isSymbolicLink()) throw new Error('Symbolic links are not supported');
      if (info.isDirectory()) { dirs.push(meta); if (dirs.length + files.length > LIMIT_FILES) throw new Error('File count limit'); visit(p); }
      else if (info.isFile()) {
        bytes += info.size;
        if (bytes > LIMIT_BYTES || dirs.length + files.length >= LIMIT_FILES) throw new Error('Snapshot size limit');
        const data = fs.readFileSync(path.join(root,p));
        if (data.length !== info.size) throw new Error('File changed during snapshot');
        files.push({...meta,size:data.length,sha256:hash(data)});
      } else throw new Error('Special files are not supported');
    }
  }
  visit('');
  return {root:{mode:rootInfo.mode&0o777,uid:rootInfo.uid,gid:rootInfo.gid},files,dirs,bytes};
}
function safeEntry(entry) {
  if (!entry || typeof entry.path !== 'string' || !entry.path || entry.path.length > 4096 || entry.path.includes('\\')
    || entry.path.includes('\0') || path.isAbsolute(entry.path) || entry.path.split('/').some(x=>!x||x==='.'||x==='..')
    || ![entry.mode,entry.uid,entry.gid].every(Number.isSafeInteger) || entry.mode<0 || entry.mode>0o777 || entry.uid<0 || entry.gid<0) throw new Error('Invalid snapshot entry');
}
function validateSnapshot() {
  const manifestPath=path.join(snapshot,'manifest.json'), info=fs.lstatSync(manifestPath);
  if(!info.isFile()||info.isSymbolicLink()||info.size>8000000)throw new Error('Invalid snapshot manifest');
  const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  if(manifest.schemaVersion!==1||!Array.isArray(manifest.files)||!Array.isArray(manifest.dirs)
    ||manifest.files.length+manifest.dirs.length>LIMIT_FILES||!Number.isSafeInteger(manifest.bytes)||manifest.bytes<0||manifest.bytes>LIMIT_BYTES)throw new Error('Invalid snapshot limits');
  const seen=new Set();
  for(const entry of [...manifest.dirs,...manifest.files]) {safeEntry(entry);if(seen.has(entry.path))throw new Error('Duplicate snapshot entry');seen.add(entry.path);}
  const actual=scan(filesRoot);
  if(actual.files.length!==manifest.files.length||actual.dirs.length!==manifest.dirs.length||actual.bytes!==manifest.bytes)throw new Error('Snapshot contents changed');
  const byPath=new Map(actual.files.map(x=>[x.path,x]));
  for(const entry of manifest.files){const file=byPath.get(entry.path);if(!file||file.size!==entry.size||file.sha256!==entry.sha256)throw new Error('Snapshot hash mismatch');}
  if(actual.dirs.map(x=>x.path).sort().join('\n')!==manifest.dirs.map(x=>x.path).sort().join('\n'))throw new Error('Snapshot directory mismatch');
  if(!manifest.root||![manifest.root.mode,manifest.root.uid,manifest.root.gid].every(Number.isSafeInteger)
    ||manifest.root.mode<0||manifest.root.mode>0o777||manifest.root.uid<0||manifest.root.gid<0)throw new Error('Invalid snapshot root');
  return manifest;
}
if(mode==='backup'){
  if(fs.existsSync(path.join(snapshot,'manifest.json')))throw new Error('Refusing to overwrite a snapshot');
  const original=scan(volume);
  fs.mkdirSync(filesRoot,{recursive:true,mode:0o700});
  for(const dir of original.dirs)fs.mkdirSync(path.join(filesRoot,dir.path),{recursive:true,mode:0o700});
  for(const file of original.files){const source=path.join(volume,file.path),dest=path.join(filesRoot,file.path);fs.copyFileSync(source,dest,fs.constants.COPYFILE_EXCL);fs.chmodSync(dest,0o600);if(hash(fs.readFileSync(dest))!==file.sha256)throw new Error('Snapshot copy hash mismatch');}
  fs.writeFileSync(path.join(snapshot,'manifest.json'),JSON.stringify({schemaVersion:1,...original}),{mode:0o600,flag:'wx'});
  validateSnapshot();console.log(JSON.stringify({ok:true,files:original.files.length,bytes:original.bytes}));
}else if(mode==='restore'){
  const saved=validateSnapshot();
  const current=scan(volume);
  // The verified snapshot is fully checked before any volume content is removed.
  for(const file of current.files)fs.unlinkSync(path.join(volume,file.path));
  for(const dir of [...current.dirs].reverse())fs.rmdirSync(path.join(volume,dir.path));
  for(const dir of saved.dirs)fs.mkdirSync(path.join(volume,dir.path),{recursive:true,mode:0o700});
  for(const file of saved.files){const p=path.join(volume,file.path);fs.copyFileSync(path.join(filesRoot,file.path),p,fs.constants.COPYFILE_EXCL);fs.chownSync(p,file.uid,file.gid);fs.chmodSync(p,file.mode);}
  for(const dir of [...saved.dirs].reverse()){const p=path.join(volume,dir.path);fs.chownSync(p,dir.uid,dir.gid);fs.chmodSync(p,dir.mode);}
  fs.chownSync(volume,saved.root.uid,saved.root.gid);fs.chmodSync(volume,saved.root.mode);
  const restored=scan(volume);if(restored.files.length!==saved.files.length||restored.bytes!==saved.bytes)throw new Error('Restore verification failed');
  const byPath=new Map(restored.files.map(x=>[x.path,x]));for(const file of saved.files)if(byPath.get(file.path)?.sha256!==file.sha256)throw new Error('Restored hash mismatch');
  console.log(JSON.stringify({ok:true,files:saved.files.length,bytes:saved.bytes}));
}else throw new Error('Unsupported volume operation');
`;

function validateCompose(model, state) {
  if (!model || Object.keys(model.services ?? {}).sort().join(',') !== SERVICES.toSorted().join(',')) throw new Error('University Compose services have changed; update the deployment policy.');
  for (const service of SERVICES) {
    const name = `${service}-data`, volume = model.volumes?.[name];
    if (!volume || volume.name !== `${state.project}_${name}`) throw new Error('University data volume names must remain stable.');
    const mount = model.services[service].volumes?.filter(item => item.target === '/app/data');
    if (mount?.length !== 1 || mount[0].type !== 'volume' || mount[0].source !== name) throw new Error('University data mount has changed.');
    const expectedPort = service === 'daehan' ? 4101 : 4102;
    const managementPort = service === 'daehan' ? 54101 : 54102;
    const ports = model.services[service].ports ?? [];
    const published = (host, target) => ports.some(item => item.host_ip === '127.0.0.1'
      && Number(item.published) === host && item.target === target);
    if (!published(expectedPort, expectedPort)) throw new Error('University sites must retain their fixed loopback ports.');
    if (ports.length === 2 && !published(managementPort, managementPort)) {
      throw new Error('University reset management ports must stay on loopback.');
    }
    if (ports.length !== 1 && ports.length !== 2) throw new Error('University sites must retain their fixed loopback ports.');
  }
}

export async function prepareFixtures(config, release, sha, options = {}) {
  if (!config.fixtures?.enabled) return { enabled: false };
  if (config.fixtures.project !== PROJECT || !isAbsolute(config.fixtures.dockerPath ?? '')
    || !isAbsolute(config.deployRoot ?? '') || !isAbsolute(config.runtimeDir ?? '')
    || !isAbsolute(release ?? '') || !/^[a-f0-9]{40}$/.test(sha)) throw new Error('Invalid university fixture deployment configuration.');
  const directory = join(config.deployRoot, 'fixtures'); await mkdir(directory, { recursive: true, mode: 0o700 }); await chmod(directory, 0o700);
  const tokens = await ensureExperimentResetTokens(config.runtimeDir);
  const composePath = join(release, 'vul-web2/compose.yaml');
  const resetComposePath = join(release, 'vul-web2/compose.reset.yaml');
  const hostResetComposePath = join(release, 'vul-web2/compose.reset.host.yaml');
  const overridePath = join(directory, `${sha}.json`);
  const state = { enabled: true, dockerPath: config.fixtures.dockerPath, project: PROJECT,
    logDirectory: join(config.deployRoot, 'logs', sha, 'fixtures'),
    envFile: tokens.path, composePath, resetComposePath, hostResetComposePath, overridePath,
    composeFiles: [composePath, resetComposePath, hostResetComposePath, overridePath],
    rollbackComposePath: join(directory, `${sha}.previous-compose.json`), rollbackOverridePath: join(directory, `${sha}.previous-images.json`),
    images: Object.fromEntries(SERVICES.map(service => [service, `ca3p-${service}:${sha}`])), original: [], volumes: [] };
  await command(state, ['info', '--format', '{{json .ServerVersion}}'], options);
  const names = (await command(state, ['volume', 'ls', '--format', '{{.Name}}'], options)).split('\n');
  const composePaths = new Set();
  for (const service of SERVICES) {
    const container = (await command(state, ['container', 'ls', '--all', '--filter', `label=com.docker.compose.project=${PROJECT}`,
      '--filter', `label=com.docker.compose.service=${service}`, '--format', '{{.ID}}'], options)).split('\n').filter(Boolean);
    if (container.length > 1) throw new Error('University service has more than one container.');
    if (container[0]) {
      const record = JSON.parse(await command(state, ['inspect', '--format', INSPECT, container[0]], options));
      if (!/^sha256:[a-f0-9]{64}$/.test(record.imageId) || record.labels?.['com.docker.compose.project'] !== PROJECT
        || record.labels?.['com.docker.compose.service'] !== service || typeof record.running !== 'boolean'
        || record.mounts?.filter(mount => mount.Destination === '/app/data' && mount.Type === 'volume'
          && mount.Name === `${PROJECT}_${service}-data`).length !== 1) throw new Error('Existing university container ownership or data mount is unexpected.');
      const paths = record.labels['com.docker.compose.project.config_files']?.split(',');
      if (!paths?.length || paths.some(path => !isAbsolute(path))) throw new Error('Cannot determine previous university Compose configuration.');
      composePaths.add(JSON.stringify(paths));
      state.original.push({ service, containerId: container[0], imageId: record.imageId, running: record.running,
        rollbackImage: `ca3p-${service}:rollback-${sha}` });
      if (!names.includes(`${PROJECT}_${service}-data`)) throw new Error('Existing university container data volume cannot be found.');
    }
    state.volumes.push({ service, name: `${PROJECT}_${service}-data`, existed: names.includes(`${PROJECT}_${service}-data`) });
  }
  if (composePaths.size > 1) throw new Error('Existing university services use different Compose configurations.');
  if (state.original.length) {
    const files = JSON.parse([...composePaths][0]);
    const originalCompose = JSON.parse(await command(state, [...compose(state, files), 'config', '--format', 'json'], options));
    validateCompose(originalCompose, state); await privateJson(state.rollbackComposePath, originalCompose);
    for (const record of state.original) await command(state, ['image', 'tag', record.imageId, record.rollbackImage], options);
    await privateJson(state.rollbackOverridePath, { services: Object.fromEntries(state.original.map(record => [record.service, { image: record.rollbackImage }])) });
  }
  await privateJson(state.overridePath, { services: Object.fromEntries(SERVICES.map(service => [service, { image: state.images[service] }])) });
  validateCompose(JSON.parse(await command(state, [...compose(state), 'config', '--format', 'json'], options)), state);
  await command(state, [...compose(state), 'build', ...SERVICES], { ...options, timeoutMs: 1_200_000 });
  state.copyImage = state.original.find(record => record.service === 'daehan')?.imageId ?? state.images.daehan;
  return state;
}

async function assertStoppedVolumes(state, options) {
  for (const volume of state.volumes.filter(item => item.existed)) {
    if ((await command(state, ['container', 'ls', '--filter', `volume=${volume.name}`, '--format', '{{.ID}}'], options)).trim()) {
      throw new Error('University data volume is still mounted by a running container.');
    }
  }
}

export async function stopFixtures(state, options = {}) {
  if (!state?.enabled) return;
  await command(state, [...compose(state), 'stop', '--timeout', '30', ...SERVICES], options);
  await assertStoppedVolumes(state, options);
}

function copyArgs(state, volume, snapshot, operation) {
  return ['run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--user', '0:0', '--security-opt', 'no-new-privileges:true',
    '--entrypoint', 'node', '--mount', `type=volume,source=${volume.name},target=/data${operation === 'backup' ? ',readonly' : ''}`,
    '--mount', `type=bind,source=${snapshot},target=/snapshot${operation === 'restore' ? ',readonly' : ''}`,
    state.copyImage, '-e', VOLUME_COPY_SCRIPT, operation, '/data', '/snapshot'];
}

export async function backupFixtures(snapshotDir, state, options = {}) {
  if (!state?.enabled) return;
  await assertStoppedVolumes(state, options);
  const directory = join(snapshotDir, 'fixtures'); await mkdir(directory, { recursive: true, mode: 0o700 }); await chmod(directory, 0o700);
  for (const volume of state.volumes.filter(item => item.existed)) {
    const snapshot = join(directory, volume.service); await mkdir(snapshot, { mode: 0o700 });
    const result = JSON.parse(await command(state, copyArgs(state, volume, snapshot, 'backup'), options));
    if (result.ok !== true) throw new Error('University volume backup failed.');
  }
  await privateJson(join(directory, 'complete.json'), { schemaVersion: 1, volumes: state.volumes });
}

export async function activateFixtures(state, options = {}) {
  if (!state?.enabled) return;
  try {
    await command(state, [...compose(state), 'up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120', ...SERVICES], options);
  } catch (error) {
    // Capture the failed candidate before rollback replaces its containers. Diagnostics cannot replace the original failure.
    await command(state, [...compose(state), 'logs', '--no-color', '--tail', '150', ...SERVICES], options).catch(() => {});
    throw error;
  }
}

export async function restoreFixtures(snapshotDir, state, options = {}) {
  if (!state?.enabled) return;
  await assertStoppedVolumes(state, options);
  const directory = join(snapshotDir, 'fixtures');
  const complete = JSON.parse(await readFile(join(directory, 'complete.json'), 'utf8'));
  if (complete.schemaVersion !== 1 || JSON.stringify(complete.volumes) !== JSON.stringify(state.volumes)) throw new Error('University backup does not match the deployment.');
  for (const volume of state.volumes.filter(item => item.existed)) {
    const result = JSON.parse(await command(state, copyArgs(state, volume, join(directory, volume.service), 'restore'), options));
    if (result.ok !== true) throw new Error('University volume restore failed.');
  }
}

export async function rollbackFixtures(state, options = {}) {
  if (!state?.enabled) return;
  await stopFixtures(state, options);
  if (!state.original.length) return;
  const previous = compose(state, [state.rollbackComposePath, state.rollbackOverridePath]);
  await command(state, [...previous, 'create', '--no-build', '--pull', 'never', ...state.original.map(record => record.service)], options);
  const previouslyRunning = state.original.filter(record => record.running).map(record => record.service);
  if (previouslyRunning.length) await command(state, [...previous, 'up', '-d', '--no-build', '--pull', 'never',
    '--wait', '--wait-timeout', '120', ...previouslyRunning], options);
}
