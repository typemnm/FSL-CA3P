import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTap, parseJUnit, suitePassed } from '../ci-results.mjs';

test('the gate rejects skipped, pending and cancelled Node tests even with exit zero', () => {
  const base = '# tests 4\n# pass 4\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
  assert.ok(suitePassed(0, parseTap(base)));
  for (const label of ['skipped', 'todo', 'cancelled']) assert.equal(suitePassed(0, parseTap(base.replace(`# ${label} 0`, `# ${label} 1`))), false);
  assert.equal(suitePassed(1, parseTap(base)), false);
  assert.equal(suitePassed(0, parseTap('')), false);
});

test('pytest JUnit totals include errors and skips across suites', () => {
  const totals = parseJUnit('<testsuites><testsuite tests="5" failures="1" errors="1" skipped="1"/><testsuite tests="3" failures="0" errors="0" skipped="0"/></testsuites>');
  assert.deepEqual(totals, { tests: 8, passed: 5, failed: 2, skipped: 1 });
  assert.equal(suitePassed(0, totals), false);
  assert.equal(suitePassed(0, parseJUnit('')), false);
});
