import test from 'node:test';
import assert from 'node:assert/strict';
import { redact, validateDisplayTarget, RUN_MODES } from '../index.mjs';
import { createRunManifest, PROJECT_ROOT, treeDigest } from '../manifest.mjs';
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

test('university manifests identify the real fixture and omit unused XSS, history and model conditions', () => {
  const manifests = ['vul-web2-daehan', 'vul-web2-wonchang'].map(fixtureId => createRunManifest({
    runId: `manifest-${fixtureId}`, mode: 'local-lab-rule', modelId: 'rule-baseline',
    options: { fixtureId, testProfile: 'known_record_idor_read' },
  }));
  for (const [index, manifest] of manifests.entries()) {
    assert.equal(manifest.target.fixtureId, ['vul-web2-daehan', 'vul-web2-wonchang'][index]);
    assert.equal(manifest.target.origin, `http://127.0.0.1:${4101 + index}`);
    assert.equal(manifest.target.testProfile, 'known_record_idor_read');
    assert.equal(manifest.target.initialStateDigest, null);
    assert.equal(manifest.target.stateCapture, 'running-fixture-not-snapshotted');
    assert.equal(manifest.modules['vul-web2'].contentDigest, treeDigest(join(PROJECT_ROOT, 'vul-web2')));
    assert.ok(manifest.modules['attack-module'].contentDigest);
    for (const name of ['agent', 'xss-parser', 'casper-db', 'pentest-db', 'packages/report']) assert.equal(manifest.modules[name], undefined);
    assert.equal(manifest.shared.lockDigest, null);
    assert.equal(manifest.shared.modelRegistryDigest, null);
    assert.equal(manifest.model.adapterDigest, null);
    assert.equal(manifest.model.promptTemplateDigest, null);
    assert.equal(manifest.model.executionRole, 'not-used-fixed-probe');
    assert.equal(manifest.data.catalogDigest, null);
    assert.equal(manifest.data.caseSnapshotDigest, null);
    assert.equal(manifest.environment.browserVersion, 'not-applicable');
    assert.equal(manifest.environment.pythonVersion, 'not-applicable');
    assert.equal(manifest.environment.playwrightVersion, 'not-applicable');
  }
  assert.notEqual(manifests[0].data.logicalInputDigest, manifests[1].data.logicalInputDigest);
  const privateHost = createRunManifest({ runId: 'manifest-private-host', mode: 'local-lab-rule', modelId: 'rule-baseline',
    options: { fixtureId: 'vul-web2-daehan', testProfile: 'known_record_idor_read', target: 'http://192.168.0.20:4101' } });
  assert.equal(privateHost.target.origin, 'http://192.168.0.20:4101');
  assert.notEqual(privateHost.data.logicalInputDigest, manifests[0].data.logicalInputDigest);
});

test('the existing local board manifest keeps its browser and agent execution conditions', () => {
  const manifest = createRunManifest({ runId: 'manifest-vul-web-1', mode: 'local-lab-rule', modelId: 'rule-baseline',
    options: { fixtureId: 'vul-web-1', testProfile: 'stored_xss_canary' }, env: { CASPER_DB_PYTHON: 'unavailable-python-for-manifest' } });
  assert.equal(manifest.target.fixtureId, 'vul-web-1');
  assert.equal(manifest.target.testProfile, 'stored_xss_canary');
  assert.ok(manifest.modules.agent.contentDigest);
  assert.ok(manifest.modules['xss-parser'].contentDigest);
  assert.ok(manifest.shared.lockDigest);
  assert.ok(manifest.model.adapterDigest);
  assert.equal(manifest.modules['vul-web2'], undefined);
});

test('general university manifests record model execution and omit deferred XSS browser conditions', () => {
  assert.ok(RUN_MODES.includes('local-lab-general'));
  const manifest = createRunManifest({ runId: 'general-university', mode: 'local-lab-general',
    modelId: 'deepseek-flash', model: { provider: 'deepseek' },
    options: { fixtureId: 'vul-web2-daehan', testProfile: 'general', target: 'http://192.168.0.20:4101' } });
  assert.equal(manifest.target.fixtureId, 'vul-web2-daehan');
  assert.equal(manifest.target.origin, 'http://192.168.0.20:4101');
  assert.equal(manifest.target.testProfile, 'general');
  assert.equal(manifest.execution.maxIterations, 6);
  assert.equal(manifest.model.provider, 'deepseek');
  assert.equal(manifest.model.executionRole, undefined);
  assert.ok(manifest.model.promptTemplateDigest);
  assert.ok(manifest.modules.agent.contentDigest);
  assert.equal(manifest.modules['xss-parser'], undefined);
  assert.equal(manifest.environment.browserVersion, 'not-applicable');
});
