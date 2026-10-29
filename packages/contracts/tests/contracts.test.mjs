import test from 'node:test';
import assert from 'node:assert/strict';
import { redact, validateDisplayTarget, RUN_MODES } from '../index.mjs';
import { createRunManifest, PROJECT_ROOT, treeDigest } from '../manifest.mjs';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

test('redaction preserves verified URL bytes and token usage while removing credentials', () => {
  const input = { origin: 'http://127.0.0.1:3000', headers: { authorization: 'private' }, usage: { total_tokens: 4 },
    target: 'https://example.invalid/?api_key=private' };
  const output = redact(input);
  assert.equal(output.origin, input.origin); assert.equal(output.usage.total_tokens, 4);
  assert.equal(output.headers.authorization, '[REDACTED]'); assert.ok(!output.target.includes('private'));
  const signed = redact({ target: 'https://example.invalid/?X-Amz-Credential=ACCESS&X-Amz-Signature=SECRET&sig=AZURE',
    credential: 'ACCESS', signature: 'SECRET' });
  assert.doesNotMatch(JSON.stringify(signed), /ACCESS|SECRET|AZURE/);
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

test('external manifests distinguish passive observation from the bounded model loop', () => {
  const scope = { origin: 'https://8.8.8.8', pathPrefix: '/', methods: ['GET', 'HEAD'],
    maxRequests: 8, maxResponseBytes: 65536, requestTimeoutMs: 5000, maxDurationMs: 30000 };
  const options = { target: 'https://8.8.8.8/', scope };
  const passive = createRunManifest({ runId: 'external-passive', mode: 'external-general',
    modelId: 'rule-baseline', options });
  assert.equal(passive.execution.inspectionMode, 'external-read-only');
  assert.equal(passive.execution.maxIterations, 1);
  assert.equal(passive.model.executionRole, 'not-used-read-only-observation');
  assert.equal(passive.shared.modelRegistryDigest, null);

  const loopBudget = { maxIterations: 6, maxProbes: 7, maxEvidenceItems: 128 };
  const modelLoop = createRunManifest({ runId: 'external-model', mode: 'external-general',
    modelId: 'deepseek-flash', model: { provider: 'deepseek' },
    options: { ...options, testProfile: 'external-general-read-only', loopBudget } });
  assert.equal(modelLoop.execution.inspectionMode, 'external-general-read-only');
  assert.deepEqual(modelLoop.execution.loopBudget, loopBudget);
  assert.equal(modelLoop.model.provider, 'deepseek');
  assert.equal(modelLoop.model.requestedModel, 'deepseek-flash');
  assert.ok(modelLoop.model.promptTemplateDigest);
  assert.ok(modelLoop.shared.modelRegistryDigest);
  assert.ok(modelLoop.modules.agent.contentDigest);
  assert.equal(modelLoop.target.testProfile, 'external-general-read-only');
  assert.throws(() => createRunManifest({ runId: 'external-unbounded', mode: 'external-general',
    modelId: 'deepseek-flash', options: { ...options,
      loopBudget: { maxIterations: 6, maxProbes: 8, maxEvidenceItems: 128 } } }), TypeError);
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

test('general manifests bind the unified catalog snapshot and actual execution dependencies', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-general-catalog-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'catalog.sqlite');
  const database = new DatabaseSync(path);
  database.exec("CREATE TABLE attack_catalog_metadata(key TEXT PRIMARY KEY, value TEXT); INSERT INTO attack_catalog_metadata VALUES ('schema', 'casper-attack-catalog-1'); CREATE TABLE attack_patterns(pattern_id TEXT, revision INTEGER, content_sha256 TEXT); INSERT INTO attack_patterns VALUES ('known-access', 1, 'alpha'); CREATE TABLE attack_templates(template_id TEXT, version TEXT, content_sha256 TEXT);");
  database.close();
  const snapshot = { path, contentDigest: 'case-content-digest' };
  const env = { CASPER_DB_PYTHON: 'missing-python-for-contract-test' };
  const university = createRunManifest({ runId: 'general-university-catalog', mode: 'local-lab-general',
    modelId: 'deepseek-flash', options: { fixtureId: 'vul-web2-daehan', caseSnapshot: snapshot }, env });
  assert.equal(university.target.testProfile, 'general');
  assert.equal(university.data.caseSnapshotDigest, snapshot.contentDigest);
  assert.match(university.data.catalogDigest, /^[a-f0-9]{64}$/u);
  assert.equal(university.data.catalogSeedDigest, treeDigest(join(PROJECT_ROOT, 'casper-db/src/casper_db/catalog_seed')));
  for (const name of ['agent', 'vul-web2', 'casper-db', 'attack-module', 'guardrail', 'packages/models', 'packages/report', 'packages/run-store']) {
    assert.ok(university.modules[name]?.contentDigest, `${name} must be frozen for general university runs`);
  }
  assert.ok(university.policy.rulesetDigest);
  assert.equal(university.environment.pythonVersion, null, 'the unavailable Python dependency is not inapplicable');
  assert.equal(university.environment.browserVersion, 'not-applicable');
  assert.equal(university.modules['xss-parser'], undefined);

  const changed = new DatabaseSync(path);
  changed.exec("UPDATE attack_patterns SET content_sha256='beta'");
  changed.close();
  const changedManifest = createRunManifest({ runId: 'general-university-catalog-changed', mode: 'local-lab-general',
    modelId: 'deepseek-flash', options: { fixtureId: 'vul-web2-daehan', caseSnapshot: snapshot }, env });
  assert.notEqual(changedManifest.data.catalogDigest, university.data.catalogDigest);

  const board = createRunManifest({ runId: 'general-board-catalog', mode: 'local-lab-general',
    modelId: 'deepseek-flash', options: { fixtureId: 'vul-web-1', caseSnapshot: snapshot }, env });
  assert.equal(board.target.testProfile, 'general');
  assert.ok(board.modules['casper-db']?.contentDigest);
  for (const name of ['attack-module', 'guardrail', 'packages/run-store']) {
    assert.ok(board.modules[name]?.contentDigest, `${name} must be frozen for general board runs`);
  }
  assert.equal(board.policy.rulesetDigest, null);
  const unavailable = createRunManifest({ runId: 'general-board-unavailable', mode: 'local-lab-general',
    modelId: 'deepseek-flash', options: { fixtureId: 'vul-web-1', unavailableInputs: ['casper-db'] }, env });
  assert.equal(unavailable.data.catalogDigest, null);
  assert.deepEqual(unavailable.data.unavailableInputs, ['casper-db']);
});
