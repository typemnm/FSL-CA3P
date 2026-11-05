import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readKnowledgeCatalog, readKnowledgeCatalogReadOnly } from '../integrations/knowledge-db.mjs';

test('read-only catalog listing requires an existing snapshot and leaves it unchanged', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'knowledge-catalog-readonly-'));
  const databasePath = join(directory, 'frozen.sqlite3');
  try {
    await assert.rejects(readKnowledgeCatalogReadOnly(), /databasePath must be an absolute path/u);
    await assert.rejects(readKnowledgeCatalogReadOnly({ databasePath }), /database not found/u);
    assert.equal(existsSync(databasePath), false);

    const seeded = await readKnowledgeCatalog({ databasePath });
    assert.equal(seeded.status, 'ok');
    assert.ok(seeded.patterns.length > 0);
    const before = await readFile(databasePath);
    const listed = await readKnowledgeCatalogReadOnly({ databasePath });
    assert.deepEqual(listed, seeded);
    assert.deepEqual(await readFile(databasePath), before);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
