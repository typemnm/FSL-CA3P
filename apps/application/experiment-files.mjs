import { lstat, readdir, realpath, rm } from 'node:fs/promises';
import { dirname, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertIdentifier, digest } from '../../packages/contracts/index.mjs';

const legacyRoot = fileURLToPath(new URL('../../reports/pentest-db-runs/', import.meta.url));
const fault = () => Object.assign(new Error('실험 파일 경로에 링크 또는 지원하지 않는 파일이 있어 초기화를 중단했습니다.'), { status: 409, code: 'UNSAFE_EXPERIMENT_FILES' });

async function info(path) {
  try { return await lstat(path); }
  catch (failure) { if (failure.code === 'ENOENT') return null; throw failure; }
}

async function inspect(root, components) {
  const base = resolve(root);
  let ancestor = parse(base).root;
  for (const component of base.slice(ancestor.length).split(/[\\/]/).filter(Boolean)) {
    ancestor = join(ancestor, component);
    const entry = await info(ancestor);
    if (!entry) return null;
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw fault();
  }
  const parent = await info(base);
  if (!parent) return null;
  if (parent.isSymbolicLink() || !parent.isDirectory()) throw fault();
  const actualRoot = await realpath(base);
  let path = base;
  for (const component of components) {
    path = join(path, component);
    const entry = await info(path);
    if (!entry) return null;
    if (entry.isSymbolicLink()) throw fault();
    const actual = await realpath(path);
    const nested = relative(actualRoot, actual);
    if (!nested || nested.startsWith(`..${sep}`) || nested === '..' || resolve(actualRoot, nested) !== actual) throw fault();
    const expected = relative(base, path);
    if ((process.platform === 'win32' ? nested.toLowerCase() : nested) !== (process.platform === 'win32' ? expected.toLowerCase() : expected)) throw fault();
  }
  let files = 0; let directories = 0;
  async function visit(target) {
    const entry = await info(target);
    if (!entry) return;
    if (entry.isSymbolicLink()) throw fault();
    if (entry.isFile()) { files += 1; return; }
    if (!entry.isDirectory()) throw fault();
    directories += 1;
    for (const child of await readdir(target)) await visit(join(target, child));
  }
  await visit(path);
  return { root: base, components, path, files, directories };
}

/** Only run-derived hash paths are eligible; credentials and arbitrary metadata paths never are. */
export async function prepareRunFileCleanup({ runs, storePath, legacyReportsDir = legacyRoot } = {}) {
  if (!Array.isArray(runs) || typeof storePath !== 'string' || storePath === ':memory:') throw fault();
  const runtimeRoot = dirname(resolve(storePath)); const entries = [];
  const seen = new Set();
  for (const run of runs) {
    assertIdentifier(run.id, 'runId');
    const artifactDirectory = join(runtimeRoot, 'artifacts', digest(run.id));
    for (const artifact of run.artifacts ?? []) {
      if (typeof artifact.path !== 'string' || dirname(resolve(artifact.path)) !== artifactDirectory) throw fault();
    }
    const identities = [...new Set([run.id, run.coreRunId, run.report?.runId, run.manifest?.legacyUiRunId].filter(value => value !== undefined && value !== null))];
    for (const identity of identities) {
      assertIdentifier(identity, 'linked runId');
      const hash = digest(identity);
      for (const [root, components] of [
        [runtimeRoot, ['artifacts', hash]], [runtimeRoot, ['reports', hash]],
        ...['', '-wal', '-shm', '-journal'].map(suffix => [runtimeRoot, ['case-snapshots', `${hash}.sqlite${suffix}`]]),
        [resolve(legacyReportsDir), [hash]],
      ]) {
        const key = join(root, ...components); if (seen.has(key)) continue; seen.add(key);
        const entry = await inspect(root, components); if (entry) entries.push(entry);
      }
    }
  }
  return { async execute() {
    // Validate the complete plan once more before the first filesystem mutation.
    const current = [];
    for (const entry of entries) { const checked = await inspect(entry.root, entry.components); if (checked) current.push(checked); }
    let files = 0; let directories = 0;
    for (const entry of current) {
      await inspect(entry.root, entry.components);
      await rm(entry.path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      files += entry.files; directories += entry.directories;
    }
    return { files, directories };
  } };
}
