import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { matchCasperHistory, observationsFromParser } from '../integrations/casper-db.mjs';

const origin = 'http://127.0.0.1:32123';
const report = {
  schemaVersion: '3.4',
  pages: [{
    behaviors: [{
      api: [{ method: 'POST', url: `${origin}/api/posts`, bodyKeys: ['title', 'content'] }],
    }],
  }],
};

test('xss-parser API hints become location observations without asserting a vulnerability', () => {
  const rows = observationsFromParser(report, { targetId: 'vul-web-1', origin });
  assert.deepEqual(rows, [
    { target_id: 'vul-web-1', endpoint: '/api/posts', method: 'POST', parameter: 'title', parameter_location: 'body' },
    { target_id: 'vul-web-1', endpoint: '/api/posts', method: 'POST', parameter: 'content', parameter_location: 'body' },
  ]);
  assert.deepEqual(observationsFromParser({ pages: [{ behaviors: [{ api: [
    { method: 'POST', url: 'https://other.invalid/api/posts', bodyKeys: ['content'] },
  ] }] }] }, { origin }), []);
});

test('real casper-db assesses parser locations against an isolated empty SQLite database', async t => {
  const databasePath = join(tmpdir(), `ca3p-casper-integration-${randomUUID()}.sqlite3`);
  t.after(async () => { await unlink(databasePath).catch(error => { if (error.code !== 'ENOENT') throw error; }); });
  const result = await matchCasperHistory({ report, origin, databasePath });
  assert.equal(result.source, 'casper-db');
  assert.equal(result.readyCaseCount, 0);
  assert.equal(result.assessments.length, 2);
  assert.ok(result.assessments.every(item => item.decision === 'no_match' && item.matches.length === 0));
});
