import { randomBytes, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

const PREFIX = 'ca3p-local-lab-';
const MARKER = '.ca3p-lab-owner.json';
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const failure = () => Object.assign(new Error('실습 프로세스 또는 임시 데이터의 소유권을 확인할 수 없어 초기화를 중단했습니다.'), { status: 409 });
const exists = async path => {
  try { return await lstat(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
};

async function plainPath(path, trustedRoot) {
  if (!isAbsolute(path)) throw failure();
  for (let entry = resolve(path); ; entry = dirname(entry)) {
    if (entry === trustedRoot) break;
    const info = await exists(entry);
    if (info?.isSymbolicLink()) throw failure();
    if (dirname(entry) === entry) break;
  }
}

async function registryDirectory(path, create = false) {
  if (typeof path !== 'string' || !isAbsolute(path) || basename(path) !== 'lab-sessions') throw failure();
  await plainPath(path, resolve(tmpdir()));
  if (create) await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await exists(path);
  if (!info) return null;
  if (!info.isDirectory() || info.isSymbolicLink()) throw failure();
  return realpath(path);
}

async function privateJson(path) {
  const info = await exists(path);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > 2048) throw failure();
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { throw failure(); }
}

async function tempDirectory(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw failure();
  const lexical = relative(resolve(tmpdir()), resolve(path));
  if (!lexical.startsWith(PREFIX) || lexical.length <= PREFIX.length || lexical.includes(sep)
    || lexical.startsWith('..') || isAbsolute(lexical)) throw failure();
  // tmpdir itself is a trusted system location and may be an OS alias (for
  // example /var on macOS); reject links below it and verify canonical bounds.
  await plainPath(path, resolve(tmpdir()));
  const info = await exists(path);
  if (!info) return null;
  if (!info.isDirectory() || info.isSymbolicLink()) throw failure();
  const actual = await realpath(path); const root = await realpath(tmpdir());
  if (dirname(actual) !== root || !basename(actual).startsWith(PREFIX)) throw failure();
  return actual;
}

function alive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; return true; }
}

async function inspect(path, expected) {
  const record = await privateJson(path);
  if (record.schemaVersion !== 1 || !UUID.test(record.id ?? '') || basename(path) !== `${record.id}.json`
    || !/^[a-f0-9]{64}$/.test(record.token ?? '') || !Number.isSafeInteger(record.pid) || record.pid < 1
    || expected && (record.id !== expected.id || record.token !== expected.token || record.directory !== expected.directory
      || record.pid !== expected.pid)) throw failure();
  if (alive(record.pid)) throw failure();
  const directory = await tempDirectory(record.directory);
  if (directory) {
    const marker = await privateJson(join(directory, MARKER));
    if (marker.id !== record.id || marker.token !== record.token) throw failure();
  }
  return { ...record, directory: record.directory, actualDirectory: directory };
}

/** Record only a newly created private lab directory, with a matching random owner marker. */
export async function registerLabSession({ registryPath, directory, pid }) {
  const root = await registryDirectory(registryPath, true);
  const actual = await tempDirectory(directory);
  if (!actual || !Number.isSafeInteger(pid) || pid < 1) throw failure();
  const id = randomUUID(); const token = randomBytes(32).toString('hex');
  const record = { schemaVersion: 1, id, token, pid, directory: resolve(directory) };
  const path = join(root, `${id}.json`);
  await writeFile(join(actual, MARKER), JSON.stringify({ id, token }), { flag: 'wx', mode: 0o600 });
  await writeFile(path, JSON.stringify(record), { flag: 'wx', mode: 0o600 });
  return { async unregister() {
    if (!await exists(path)) return;
    const current = await privateJson(path);
    if (current.id !== id || current.token !== token) throw failure();
    await unlink(path);
  } };
}

/** Delete only dead, registered labs with matching ownership markers; never sweep tmp by prefix. */
export async function prepareLabSessionCleanup(registryPath) {
  if (registryPath === undefined) return { execute: async () => ({ removed: 0 }) };
  const root = await registryDirectory(registryPath);
  if (!root) return { execute: async () => ({ removed: 0 }) };
  const entries = await readdir(root, { withFileTypes: true }); const plans = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !UUID.test(entry.name.slice(0, -5)) || !entry.name.endsWith('.json')) throw failure();
    const path = join(root, entry.name);
    plans.push({ path, record: await inspect(path) });
  }
  return { async execute() {
    let removed = 0;
    for (const plan of plans) {
      if (await registryDirectory(registryPath) !== root) throw failure();
      const current = await inspect(plan.path, plan.record);
      if (current.actualDirectory) {
        // inspect verifies this resolved absolute path is one direct child of
        // the system temporary directory and has our matching ownership token.
        await rm(current.actualDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
      await unlink(plan.path); removed += 1;
    }
    return { removed };
  } };
}
