import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseDependencyManifest } from '../dependency-parser.mjs';
import { scanUniversityFixture } from '../university-fixtures.mjs';
import { createUniversityParserGateway } from '../../packages/adapters/integrations/university-parser.mjs';
import protocol from '../../agent/src/protocol.js';

const { createEnvelope, invokeJson } = protocol;
const manifest = async file => readFile(new URL(file, import.meta.url), 'utf8');

test('Daehan package-lock matches exactly three declared direct dependency advisories', async () => {
  const result = parseDependencyManifest(await manifest('../../vul-web2/package-lock.json'), {
    ecosystem: 'npm', sourceFile: 'vul-web2/package-lock.json',
  });
  assert.deepEqual(result.findings.map(x => x.id).sort(),
    ['CVE-2020-8203', 'CVE-2022-21670', 'CVE-2022-46175']);
  assert.equal(result.summary.isCompleteSCA, false);
  assert.ok(result.findings.every(x => x.status === 'affected_version' && x.validation === 'not_executed'));
});

test('Wonchang pom.xml matches exactly three declared direct dependency advisories', async () => {
  const result = parseDependencyManifest(await manifest('../../vul-web2/wonchang/pom.xml'), {
    ecosystem: 'maven', sourceFile: 'vul-web2/wonchang/pom.xml',
  });
  assert.deepEqual(result.findings.map(x => x.id).sort(),
    ['CVE-2022-1471', 'CVE-2022-42889', 'CVE-2023-42503']);
  assert.ok(result.unresolved.some(name => name.includes('spring-boot-starter')));
  assert.equal(result.summary.runtimeExploitabilityVerified, false);
});

test('fixed versions are not marked affected; inherited Maven versions are not invented', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    '': { dependencies: { lodash: '4.17.21' } },
    'node_modules/lodash': { version: '4.17.21' },
  } });
  assert.equal(parseDependencyManifest(lock, { ecosystem: 'npm', sourceFile: 'test-lock' }).findings.length, 0);
  const pom = '<project><dependencies><dependency><groupId>org.yaml</groupId>'
    + '<artifactId>snakeyaml</artifactId></dependency></dependencies></project>';
  const result = parseDependencyManifest(pom, { ecosystem: 'maven', sourceFile: 'test-pom' });
  assert.deepEqual(result.unresolved, ['org.yaml:snakeyaml']);
  assert.deepEqual(result.findings, []);
});

test('university scan rejects unknown names and untrusted cross-origin browser results', async () => {
  await assert.rejects(scanUniversityFixture('external'), /Unknown university fixture/);
  const fake = { schemaVersion: '3.4', startUrl: 'http://127.0.0.1:4101/', pages: [
    { id: 'page-1', url: 'http://127.0.0.1:9999/' },
  ], summary: { scope: 'visited-client-pages', truncated: false } };
  await assert.rejects(scanUniversityFixture('daehan', {
    readImpl: async () => JSON.stringify({ packages: { '': { dependencies: {} } } }),
    scanImpl: async () => fake,
  }), /outside the selected fixture/);
});

test('university adapter exchanges validated CA3P parser.result without changing old gateway', async () => {
  const origin = 'http://127.0.0.1:4102';
  const gateway = createUniversityParserGateway({ scanFixture: async site => ({
    site, origin, dependencies: { findings: [], summary: { isCompleteSCA: false } },
    report: {
      schemaVersion: '3.4', startUrl: origin + '/', pages: [{ id: 'page-1', url: origin + '/',
        title: 'Wonchang', posts: [] }],
      summary: { scope: 'visited-client-pages', truncated: false, errors: 0 },
    },
  }) });
  const request = createEnvelope({
    runId: 'university-read-only', iteration: 0, sender: 'agent', receiver: 'xss-parser',
    type: 'module.request', payload: { operation: 'parse_site', site: 'wonchang',
      origin, phase: 'before' },
    policyContext: { targetMode: 'isolated_local_lab', targetOrigin: origin },
  });
  const result = await invokeJson(gateway, request);
  assert.equal(result.type, 'parser.result');
  assert.equal(result.payload.site, 'wonchang');
  assert.deepEqual(result.payload.dependencies.findings, []);
  await assert.rejects(gateway.exchange(JSON.stringify({
    ...request, payload: { ...request.payload, origin: 'http://127.0.0.1:4101' },
  })), /not the approved loopback/);
});
