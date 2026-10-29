import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { promisify } from 'node:util';
import wt from 'node:worker_threads';
import { fingerprint, fingerprintWithin, LIBRARY_CATEGORIES, MATCH_SAMPLE_LENGTH } from '../fingerprint.mjs';

// Counts Worker constructions: reuse is checked by spawn counts, not by timing.
let spawned = 0;
wt.Worker = class extends wt.Worker { constructor(...args) { super(...args); spawned++; } };
syncBuiltinESMExports(); // fingerprint.mjs's `Worker` import binding now points at the counter

// Browser-free adapter tests: fingerprint() on crafted matcher input.
const T = { timeout: 60_000 };
const EMPTY = { url: '', headers: [], cookies: [], meta: [], html: '', scriptSrc: [], scripts: [], xhr: [], js: {}, dom: {} };
const run = (input) => Object.fromEntries(fingerprint({ ...EMPTY, ...input }).technologies.map((t) => [t.name, t]));
const generator = (...contents) => contents.map((content) => ({ name: 'generator', content }));
// ~1 s to match (MATCH_SAMPLE_LENGTH unclosed '<'): a deadline far below that always fires, on any hardware.
const SLOW = { ...EMPTY, html: '<'.repeat(MATCH_SAMPLE_LENGTH) };

test('dom: attribute version and exists patterns carry the selector as evidence key', T, () => {
  const tech = run({ dom: { '[ng-version]': { text: '', attributes: { 'ng-version': '17.3.1' } } } });
  assert.equal(tech.Angular.version, '17.3.1');
  assert.deepEqual(tech.Angular.evidence, [{ field: 'dom', key: '[ng-version]', match: '17.3.1' }]);
  assert.deepEqual(tech.TypeScript.evidence, [{ field: 'implies', match: 'Angular' }]);
});

test('xhr: matched on host + path, a host-like query parameter does not match', T, () => {
  assert.deepEqual(Object.keys(run({ xhr: ['http://127.0.0.1:1/log?u=cdn.ampproject.org'] })), []);
  const tech = run({ xhr: ['https://www.facebook.com/tr/?id=1'] });
  assert.deepEqual(tech['Facebook Pixel Advanced Matching'].evidence, [{ field: 'xhr', match: 'facebook.com/tr/' }]);
});

test('requires: a 3-level chain unlocks pass by pass (WordPress -> WooCommerce -> FiboSearch)', T, () => {
  const tech = run({ meta: generator('WordPress 6.5', 'WooCommerce 8.0'), js: { 'dgwt_wcas.ajax_search_endpoint': '/x' } });
  assert.ok(tech.WooCommerce && tech.FiboSearch, Object.keys(tech).join());
  assert.deepEqual(tech.FiboSearch.evidence, [{ field: 'js', key: 'dgwt_wcas.ajax_search_endpoint', match: '' }]);
  assert.ok(!run({ js: { 'dgwt_wcas.ajax_search_endpoint': '/x' } }).FiboSearch, 'gated without its requirement');
});

test('requiresCategory unlocks from a category found in a later pass (WooCommerce -> Afterpay)', T, () => {
  assert.ok(run({ meta: generator('WordPress 6.5', 'WooCommerce 8.0'), js: { AfterPay: 'true' } }).Afterpay);
  assert.ok(!run({ js: { AfterPay: 'true' } }).Afterpay);
});

test('a requirement met only through implies unlocks (WordPress implies PHP -> Croogo)', T, () => {
  const tech = run({ meta: generator('WordPress', 'Croogo') });
  assert.ok(tech.Croogo);
  assert.deepEqual(tech.PHP.evidence, [{ field: 'implies', match: 'WordPress' }]);
});

test('excludes removes the excluded technology', T, () => {
  const tech = run({ headers: [{ name: 'X-Arastta', value: '' }], cookies: [{ name: 'OCSESSID', value: '1' }] });
  assert.ok(tech.Arastta);
  assert.ok(!tech.OpenCart, 'Arastta excludes OpenCart');
  assert.ok(run({ cookies: [{ name: 'OCSESSID', value: '1' }] }).OpenCart);
});

test('confidence: one pattern matching several values counts once', T, () => {
  const tech = run({ scriptSrc: ['/js/Chart.min.js', '/vendor/Chart.min.js'] });
  assert.equal(tech['Chart.js'].confidence, 75);
});

test('header/cookie/meta names are normalized; prototype-like names are ordinary keys', T, () => {
  const tech = run({
    headers: [{ name: 'X-Powered-By', value: 'Express' }, { name: 'Constructor', value: 'v' }],
    cookies: [{ name: '__proto__', value: '1' }],
    meta: [{ name: 'constructor', content: 'x' }, { property: 'og:site_name', content: 'GitLab' }],
  });
  assert.deepEqual(tech.Express.evidence, [{ field: 'headers', key: 'x-powered-by', match: 'Express' }]);
  assert.deepEqual(tech.GitLab.evidence, [{ field: 'meta', key: 'og:site_name', match: 'GitLab' }], 'meta via property');
  assert.ok(tech['Vue.js']);
});

test('a public Spring Boot header identifies the framework without source access', T, () => {
  const input = { headers: [{ name: 'X-Powered-By', value: 'Spring Boot' }] };
  assert.deepEqual(run(input)['Spring Boot'], {
    name: 'Spring Boot', categories: ['Web frameworks'], version: null, confidence: 75,
    evidence: [{ field: 'headers', key: 'x-powered-by', match: 'Spring Boot' }],
  });
  assert.deepEqual(fingerprint({ ...EMPTY, ...input }).libraries.find(item => item.name === 'Spring Boot'), {
    name: 'Spring Boot', version: null, source: 'fingerprint',
    evidence: [{ field: 'headers', key: 'x-powered-by', match: 'Spring Boot' }],
  });
  assert.equal(run({ headers: [{ name: 'X-Powered-By', value: 'Spring Boot; token=secret' }] })['Spring Boot'], undefined);
});

test('html matcher input is sampled to a bounded head + tail', T, () => {
  const pad = 'x'.repeat(MATCH_SAMPLE_LENGTH);
  assert.ok(!run({ html: `${pad}<link rel="amphtml">${pad}` }).AMP, 'the dropped middle is not matched');
  assert.ok(run({ html: `${pad}${pad}<link rel="amphtml">` }).AMP, 'the tail is matched');
  assert.equal(MATCH_SAMPLE_LENGTH, 50_000);
});

test('fingerprintWithin runs in a worker and is terminated at its deadline', T, async () => {
  const { technologies } = await fingerprintWithin({ ...EMPTY, meta: generator('WordPress 6.5') }, 30_000);
  assert.ok(technologies.some((t) => t.name === 'WordPress'));
  await assert.rejects(fingerprintWithin(SLOW, 50), /^Error: timeout$/);
});

test('fingerprintWithin keeps a warm worker: reused after success, replaced after a timeout, concurrent calls isolated', T, async () => {
  const wp = { ...EMPTY, meta: generator('WordPress 6.5') };
  const has = ({ technologies }) => technologies.some((t) => t.name === 'WordPress');
  assert.ok(has(await fingerprintWithin(wp, 30_000)));
  let n = spawned;
  assert.ok(has(await fingerprintWithin(wp, 30_000)));
  assert.equal(spawned - n, 0, 'warm worker reused');
  await assert.rejects(fingerprintWithin(SLOW, 50), /^Error: timeout$/);
  assert.equal(spawned - n, 0, 'the timed-out call still ran on the warm worker');
  assert.ok(has(await fingerprintWithin(wp, 30_000)), 'a fresh worker after the terminate');
  assert.equal(spawned - n, 1);
  n = spawned;
  const both = await Promise.all([fingerprintWithin(wp, 30_000), fingerprintWithin(wp, 30_000)]);
  assert.ok(both.every(has));
  assert.equal(spawned - n, 1, 'a concurrent call gets its own worker');
});

test('no mixing between assets: each call on reused workers reports only its own input', T, async () => {
  const assets = [
    [{ ...EMPTY, url: 'http://asset-a.test/', meta: generator('WordPress 6.5') }, ['MySQL', 'PHP', 'WordPress']],
    [{ ...EMPTY, url: 'http://asset-b.test/', headers: [{ name: 'X-Powered-By', value: 'Express' }] }, ['Express', 'Node.js']],
    [{ ...EMPTY, url: 'http://asset-c.test/' }, []],
  ];
  const names = ({ technologies }) => technologies.map((t) => t.name).sort();
  await fingerprintWithin(EMPTY, 30_000); // warm
  const n = spawned;
  for (const [input, want] of [...assets, ...assets]) assert.deepEqual(names(await fingerprintWithin(input, 30_000)), want, input.url);
  assert.equal(spawned - n, 0, 'all sequential calls shared one worker');
  for (let round = 0; round < 2; round++) {
    const got = await Promise.all(assets.map(([input]) => fingerprintWithin(input, 30_000)));
    assert.deepEqual(got.map(names), assets.map(([, want]) => want), `concurrent round ${round}`);
  }
});

test('the idle worker is unref\'d: a process that used it exits on its own', T, async () => {
  const mod = new URL('../fingerprint.mjs', import.meta.url).href;
  // No --input-type flag: the Worker would inherit it from execArgv and fail.
  const child = `import(${JSON.stringify(mod)}).then((m) => m.fingerprintWithin(${JSON.stringify(EMPTY)}, 30000));`;
  await promisify(execFile)(process.execPath, ['-e', child], { timeout: 15_000 });
});

test('dataset guards: library category names, and every implies/excludes/requires target exists', T, () => {
  const data = new URL('../data/webappanalyzer/', import.meta.url);
  const categories = JSON.parse(readFileSync(new URL('categories.json', data), 'utf8'));
  assert.deepEqual([...LIBRARY_CATEGORIES].map((id) => categories[id].name), ['JavaScript frameworks', 'Web frameworks',
    'JavaScript graphics', 'Mobile frameworks', 'JavaScript libraries', 'UI frameworks']);
  const techs = Object.assign({}, ...'_abcdefghijklmnopqrstuvwxyz'.split('').map((c) => JSON.parse(readFileSync(new URL(`technologies/${c}.json`, data), 'utf8'))));
  const names = (v) => (v == null ? [] : [v].flat()).map((s) => String(s).split('\\;')[0]);
  const dangling = Object.values(techs).flatMap((t) => [...names(t.implies), ...names(t.excludes), ...names(t.requires)]).filter((n) => !techs[n]);
  assert.deepEqual(dangling, []);
});
