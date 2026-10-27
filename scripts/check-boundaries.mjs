import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, relative, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(await readFile(resolve(root, 'integration-manifest.json'), 'utf8'));
const modules = manifest.modules.filter(module => module.status === 'active').sort((a, b) => b.path.length - a.path.length);
const boundaries = [...manifest.boundaries].sort((a, b) => b.path.length - a.path.length);
const ignored = new Set(['node_modules', '.git', '.venv', '.runtime', '.pytest_cache', 'tests', 'test', 'test-support', 'data', 'reports', '__pycache__']);
const owner = path => modules.find(module => path === module.path || path.startsWith(`${module.path}/`));
async function files(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name) || entry.isSymbolicLink()) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) output.push(...await files(path));
    else if (['.js', '.mjs', '.cjs'].includes(extname(path))) output.push(path);
  }
  return output;
}
const failures = [];
let checked = 0;
for (const module of modules) {
  const directory = resolve(root, module.path);
  try { await stat(directory); } catch { continue; }
  for (const file of await files(directory)) {
    const source = relative(root, file).split('\\').join('/');
    // A parent module also contains any nested module. Check each file once.
    if (owner(source)?.id !== module.id) continue;
    checked += 1;
    const boundary = boundaries.find(item => source === item.path || source.startsWith(`${item.path}/`));
    const allowed = new Set(boundary?.allow || [module.id, ...module.dependencies]);
    const code = await readFile(file, 'utf8');
    const imports = code.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s*)['"]([^'"]+)['"]/g);
    for (const match of imports) {
      if (!match[1].startsWith('.')) continue;
      const target = relative(root, resolve(dirname(file), match[1])).split('\\').join('/');
      const destination = owner(target);
      if (!destination || !allowed.has(destination.id)) failures.push(`${source} -> ${match[1]} (${destination?.id || 'outside registered modules'})`);
    }
  }
}
if (failures.length) {
  console.error(`Module boundary violations:\n${failures.join('\n')}`);
  process.exitCode = 1;
} else console.log(`Module boundaries passed (${checked} production files).`);
