import test from 'node:test';
import assert from 'node:assert/strict';
import { redact, validateDisplayTarget } from '../index.mjs';
import { treeDigest } from '../manifest.mjs';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('redaction preserves verified URL bytes and token usage while removing credentials', () => {
  const input = { origin: 'http://127.0.0.1:3000', headers: { authorization: 'private' }, usage: { total_tokens: 4 },
    target: 'https://example.invalid/?api_key=private' };
  const output = redact(input);
  assert.equal(output.origin, input.origin); assert.equal(output.usage.total_tokens, 4);
  assert.equal(output.headers.authorization, '[REDACTED]'); assert.ok(!output.target.includes('private'));
  assert.equal(validateDisplayTarget('https://user:secret@example.invalid').ok, false);
});
test('manifest tree hashing detects source changes without hashing runtime secrets or dependency caches', t => {
  const path = mkdtempSync(join(tmpdir(), 'ca3p-manifest-'));
  t.after(() => rmSync(path, { recursive: true, force: true }));
  mkdirSync(join(path, 'node_modules')); writeFileSync(join(path, 'source.js'), 'initial');
  const first = treeDigest(path);
  writeFileSync(join(path, '.env'), 'private'); writeFileSync(join(path, 'node_modules/cache.js'), 'dependency');
  assert.equal(treeDigest(path), first);
  writeFileSync(join(path, 'source.js'), 'changed'); assert.notEqual(treeDigest(path), first);
});
