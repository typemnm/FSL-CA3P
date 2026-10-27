import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeForComparison, compareRunRecords, evaluateCases } from '../index.mjs';

test('only diff normalizes bound markers and loopback ports while keeping meaningful IDs', () => {
  const marker = 'a'.repeat(32);
  const original = { timestamp: 'now', post: { id: 4 }, marker, url: 'http://127.0.0.1:34001/', body: `probe ${marker}` };
  const normalized = normalizeForComparison(original, { markers: [marker] });
  assert.equal(normalized.post.id, 4); assert.equal(normalized.marker, '<marker>');
  assert.equal(normalized.url, 'http://127.0.0.1:<port>/'); assert.equal(original.marker, marker);
});
test('unknown legacy conditions prevent an asserted controlled comparison', () => {
  const comparison = compareRunRecords({ id: 'a', manifest: null, report: { finding: { status: 'confirmed' } } },
    { id: 'b', manifest: null, report: { finding: { status: 'not_reproduced' } } });
  assert.equal(comparison.comparable, false);
  assert.equal(comparison.findingTransition.after, 'not_reproduced');
  assert.equal(comparison.causalAttribution, 'not-established');
});

test('matching retained traces do not qualify as a clean experimental comparison', () => {
  const run = (id, previousRunCount, lastResetAt = '2026-10-26T09:00:00Z') => ({ id,
    manifest: { experiment: { epoch: 1, lastResetAt, previousRunCount } } });
  const condition = (a, b) => compareRunRecords(a, b, { kind: 'model' }).conditions.find(row => row.name === 'experimentIsolation');
  assert.equal(condition(run('a', 2), run('b', 2)).equal, false);
  assert.equal(condition(run('a', 0), run('b', 0)).equal, true);
  assert.equal(condition(run('a', 0, null), run('b', 0)).equal, false);
  assert.equal(condition(run('a', 0), { id: 'legacy', manifest: {} }).available, false);
});
test('end-to-end recall includes inconclusive positive cases rather than inflating recall', () => {
  const result = evaluateCases([{ vulnerable: true, result: 'confirmed' }, { vulnerable: true, result: 'inconclusive' },
    { vulnerable: false, result: 'not_reproduced' }]);
  assert.equal(result.endToEndRecall, 0.5); assert.equal(result.conditionalRecall, 1);
  assert.equal(result.coverage, 2 / 3); assert.equal(result.inconclusiveRate, 1 / 3);
});
