import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunEvidenceStore } from '../../packages/adapters/integrations/run-evidence.mjs';

/** Trusted operator import; readRun validates each stored runId before insertion. */
export async function importLegacyRuns(store, { reportsDir = fileURLToPath(new URL('../../reports/pentest-db-runs/', import.meta.url)) } = {}) {
  const root = resolve(reportsDir);
  let directories;
  try { directories = await readdir(root, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return { imported: 0, errors: [] }; throw error; }
  const adapter = createRunEvidenceStore({ reportsDir: root });
  const { readFile } = await import('node:fs/promises');
  let imported = 0; const errors = [];
  for (const entry of directories) {
    if (!entry.isDirectory() || !/^[a-f0-9]{64}$/u.test(entry.name)) continue;
    try {
      const final = JSON.parse(await readFile(join(root, entry.name, 'report.json'), 'utf8'));
      const run = await adapter.readRun(final.runId);
      if (!run) continue;
      const existed = store.getRun(run.runId);
      store.importLegacyRun(run);
      if (!existed) imported += 1;
    } catch (error) { errors.push({ directory: entry.name, code: error.code ?? 'LEGACY_IMPORT_FAILED' }); }
  }
  return { imported, errors };
}
