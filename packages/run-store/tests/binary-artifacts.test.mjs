import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRunRepository, readArtifactBytes } from '../index.mjs';

function run(store, id) {
  store.createRun({ id, mode: 'core-fixture', modelId: 'rule-baseline', manifest: { runId: id },
    state: { id, status: 'queued', events: [] }, options: {} });
}

test('HWPX bytes, Korean filename, identity and digest survive reopening without JSON conversion', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-hwpx-store-'));
  const path = join(directory, 'runs.sqlite');
  let store = createRunRepository({ path });
  try {
    run(store, 'run-hwpx');
    // Binary ZIP bytes must never pass through the JSON serializer or redactor.
    const bytes = Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4, 0, 255]), Buffer.from('authorization: synthetic-test')]);
    const metadata = { filename: '저장형 XSS 보고서.hwpx', contentType: 'application/hwp+zip', provenance: 'generated-report' };
    const artifact = store.writeBinaryArtifact('run-hwpx', 'hwpx-report', bytes, metadata);
    assert.deepEqual(readArtifactBytes(artifact), bytes);
    assert.equal(store.writeBinaryArtifact('run-hwpx', 'hwpx-report', bytes, metadata).id, artifact.id);
    assert.equal(store.getRun('run-hwpx').artifacts.length, 1);
    store.close();
    store = createRunRepository({ path });
    const stored = store.getArtifact(artifact.id);
    assert.equal(stored.runId, 'run-hwpx');
    assert.equal(stored.filename, metadata.filename);
    assert.equal(stored.contentType, metadata.contentType);
    assert.deepEqual(readArtifactBytes(stored), bytes);
    writeFileSync(stored.path, Buffer.from('changed'));
    assert.throws(() => readArtifactBytes(stored), { code: 'ARTIFACT_CHANGED' });
    assert.throws(() => store.writeBinaryArtifact('run-hwpx', 'hwpx-report', bytes, metadata), { code: 'ARTIFACT_CHANGED' });
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('binary storage rejects unknown runs, empty data, unsafe filenames and metadata identity overrides', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-hwpx-invalid-'));
  const store = createRunRepository({ path: join(directory, 'runs.sqlite') });
  try {
    run(store, 'run-hwpx');
    const bytes = Buffer.from('PK\u0003\u0004');
    assert.throws(() => store.writeBinaryArtifact('unknown', 'hwpx-report', bytes, { filename: 'report.hwpx' }), { code: 'RUN_NOT_FOUND' });
    assert.throws(() => store.writeBinaryArtifact('run-hwpx', 'hwpx-report', Buffer.alloc(0), { filename: 'report.hwpx' }), { code: 'INVALID_ARTIFACT' });
    for (const filename of ['../report.hwpx', '..\\report.hwpx', 'bad\nreport.hwpx', 'report.json', '']) {
      assert.throws(() => store.writeBinaryArtifact('run-hwpx', 'hwpx-report', bytes, { filename }), { code: 'INVALID_ARTIFACT' });
    }
    for (const key of ['id', 'runId', 'kind', 'path', 'sha256', 'size']) {
      assert.throws(() => store.writeBinaryArtifact('run-hwpx', 'hwpx-report', bytes, { filename: 'report.hwpx', [key]: 'override' }), { code: 'INVALID_ARTIFACT' });
    }
    assert.deepEqual(store.getRun('run-hwpx').artifacts, []);
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});
