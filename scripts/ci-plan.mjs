import { readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

export async function testFiles(directory) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const found = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isSymbolicLink() || ['node_modules', '.git', '.runtime', '.venv'].includes(entry.name)) continue;
    const file = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await testFiles(file));
    else if (/\.test\.(?:mjs|cjs|js)$/.test(entry.name)) found.push(file);
  }
  return found;
}

/** A test has exactly one reporting owner, even when it exercises other modules. */
export async function createSuitePlan({ root, manifest, nodeOnly = false, selection = null,
  nodeExecutable = process.execPath, pythonExecutable = process.env.CASPER_DB_PYTHON || 'python3' }) {
  const active = manifest.modules.filter(item => item.status === 'active');
  const byId = new Map(active.map(item => [item.id, item]));
  const discovered = new Map();
  const problems = [];
  for (const module of active.filter(item => item.id !== 'casper-db')) {
    for (const file of [...await testFiles(resolve(root, module.path, 'test')),
      ...await testFiles(resolve(root, module.path, 'tests'))]) {
      const name = relative(root, file).split('\\').join('/');
      if (discovered.has(name)) problems.push(`Test belongs to multiple modules: ${name}`);
      else discovered.set(name, { file, owner: module.id });
    }
  }
  const assigned = new Map();
  for (const [id, files] of Object.entries(manifest.ci?.suiteAssignments ?? {})) {
    if (!byId.has(id) || id === 'casper-db') {
      problems.push(`Suite assignment names an unknown or Python-only active module: ${id}`);
      continue;
    }
    if (!Array.isArray(files) || files.length === 0) {
      problems.push(`Suite assignment for ${id} must list discovered test files.`);
      continue;
    }
    for (const name of files) {
      if (typeof name !== 'string' || !discovered.has(name)) {
        problems.push(`Suite assignment for ${id} references an undiscovered test: ${String(name)}`);
      } else if (assigned.has(name)) {
        problems.push(`Test is assigned more than once: ${name}`);
      } else assigned.set(name, id);
    }
  }
  const suites = [];
  for (const module of active.filter(item => item.id !== 'casper-db')) {
    const files = [...discovered.entries()].filter(([name, entry]) =>
      (assigned.get(name) ?? entry.owner) === module.id).map(([, entry]) => entry.file);
    if (files.length === 0) problems.push(`Active module has no test suite: ${module.id}`);
    else if (!selection || selection.includes(module.id)) suites.push({
      id: module.id, cwd: resolve(root, module.path), command: nodeExecutable,
      args: ['--test', '--test-reporter=tap', ...files],
    });
  }
  const scriptTests = await testFiles(resolve(root, 'scripts/tests'));
  if (scriptTests.length && !selection) suites.push({ id: 'ci-tools', cwd: root, command: nodeExecutable,
    args: ['--test', '--test-reporter=tap', ...scriptTests] });
  if (!nodeOnly && (!selection || selection.includes('casper-db')) && byId.has('casper-db')) {
    suites.push({ id: 'casper-db', cwd: resolve(root, 'casper-db'), command: pythonExecutable,
      args: ['-m', 'pytest', '--junitxml=../reports/ci/casper-db.xml'] });
  }
  if (selection) for (const id of selection) {
    if (!byId.has(id)) problems.push(`Selected module is not active: ${id}`);
    else if (nodeOnly && id === 'casper-db') problems.push('casper-db requires Python; omit --node-only.');
    else if (!suites.some(suite => suite.id === id)) problems.push(`Selected module has no discovered test suite: ${id}`);
  }
  return { suites, problems, activeIds: active.map(item => item.id) };
}
