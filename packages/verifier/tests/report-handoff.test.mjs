import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeReportHandoff, readReportHandoff } from '../report-handoff.mjs';

const PNG_LIKE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

function sha(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function fixture() {
  const outDir = await mkdtemp(join(tmpdir(), 'verifier-handoff-'));
  await mkdir(join(outDir, 'images'));
  await writeFile(join(outDir, 'images', 'shot.png'), PNG_LIKE);
  const result = {
    schemaVersion: 'verifier/1',
    attackId: 'atk-1',
    artifacts: [{ id: 'atk-1-art-0', kind: 'screenshot', label: 'viewport', file: 'images/shot.png', sha256: sha(PNG_LIKE), bytes: PNG_LIKE.length }],
  };
  return { outDir, result };
}

test('handoff write and read round trip with a real image', async () => {
  const { outDir, result } = await fixture();
  const written = await writeReportHandoff(result, { outDir });
  assert.deepEqual(written.files, ['images/shot.png']);
  const handoff = await readReportHandoff(outDir);
  assert.equal(handoff.schemaVersion, 'verification-handoff/1');
  assert.deepEqual(handoff.result, result);
  assert.deepEqual(handoff.images, [{ file: 'images/shot.png', sha256: sha(PNG_LIKE), bytes: PNG_LIKE.length, label: 'viewport' }]);
});

test('a tampered image fails with HANDOFF_INTEGRITY', async () => {
  const { outDir, result } = await fixture();
  await writeReportHandoff(result, { outDir });
  await writeFile(join(outDir, 'images', 'shot.png'), Buffer.from('tampered'));
  await assert.rejects(readReportHandoff(outDir), { code: 'HANDOFF_INTEGRITY' });
  await assert.rejects(writeReportHandoff(result, { outDir }), { code: 'HANDOFF_INTEGRITY' });
});

test('a ../ artifact path fails with HANDOFF_INTEGRITY', async () => {
  const { outDir, result } = await fixture();
  await writeFile(join(outDir, 'outside.png'), PNG_LIKE);
  result.artifacts[0].file = '../outside.png';
  await assert.rejects(writeReportHandoff(result, { outDir }), { code: 'HANDOFF_INTEGRITY' });
});
