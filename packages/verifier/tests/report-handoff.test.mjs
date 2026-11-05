import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeReportHandoff, readReportHandoff } from '../report-handoff.mjs';
import { verifyAttack } from '../index.mjs';

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

test('verification.json carries the judged attack for the report collector', async () => {
  const outDir = await mkdtemp(join(tmpdir(), 'verifier-handoff-'));
  const model = { completeJson: async () => ({ value: { verdict: 'valid', reason: 'the row leaked' }, metadata: { model: 'scripted' } }) };
  const result = await verifyAttack({
    schemaVersion: 'attack-record/1',
    id: 'atk-2',
    kind: 'sqli',
    target: { origin: 'http://127.0.0.1:4174' },
    info: { session: 'bob', relatedEvidence: [{ id: 'ev-1' }] },
    request: { method: 'GET', url: 'http://127.0.0.1:4174/api/items?q=1', headers: { Cookie: 'sid=HANDOFF-SECRET' } },
    response: { status: 200, headers: {}, bodyText: 'row', bodyJson: null, error: null, elapsedMs: 2 },
  }, { outDir, model, browserFactory: async () => { throw new Error('no browser in this test'); } });
  await writeReportHandoff(result, { outDir });
  const written = JSON.parse(await readFile(join(outDir, 'verification.json'), 'utf8'));
  assert.deepEqual(written.result.attack, {
    kind: 'sqli',
    request: { method: 'GET', url: 'http://127.0.0.1:4174/api/items?q=1', headers: { Cookie: '[redacted]' } },
    response: { status: 200, headers: {}, bodyText: 'row', bodyJson: null, error: null, elapsedMs: 2 },
  });
  assert.doesNotMatch(JSON.stringify(written), /HANDOFF-SECRET|relatedEvidence/u);
});
