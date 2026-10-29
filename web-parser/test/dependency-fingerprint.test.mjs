import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fingerprint } from '../fingerprint.mjs';

const ORIGIN = 'https://example.test';
const EMPTY = { url: `${ORIGIN}/`, headers: [], cookies: [], meta: [], html: '',
  scriptSrc: [], stylesheetHref: [], scripts: [], resourceBodies: [], xhr: [], js: {}, dom: {} };
const detect = input => fingerprint({ ...EMPTY, ...input });
const named = (items, name) => items.find(item => item.name.toLowerCase() === name.toLowerCase());

test('URL filename indicators identify ReactDOM, axios, and moment with resource graph links', () => {
  const scriptSrc = [
    `${ORIGIN}/assets/react-dom-18.2.0.production.min.js`,
    `${ORIGIN}/assets/axios-1.6.8.min.js`,
    `${ORIGIN}/assets/moment-2.30.1.min.js`,
  ];
  const result = detect({ scriptSrc });
  for (const [name, displayName, version] of [
    ['react-dom', 'ReactDOM', '18.2.0'], ['axios', 'Axios', '1.6.8'],
    ['moment', 'Moment.js', '2.30.1'],
  ]) {
    assert.equal(named(result.libraries, displayName)?.version, version, name);
    const indicator = named(result.dependencies.libraries, name);
    assert.equal(indicator?.version, version, name);
    assert.ok(indicator.evidence.some(item => item.kind === 'url-name-hint'), name);
    const asset = result.dependencies.assets.find(item => item.id === indicator.assetId);
    assert.ok(asset && scriptSrc.includes(asset.url), name);
    assert.ok(result.dependencies.relations.some(item => item.from === asset.id
      && item.to === indicator.id && item.kind === 'library-indicator'), name);
  }
  assert.equal(result.dependencies.mode, 'url-observation');
  assert.equal(result.dependencies.complete, false);
  assert.equal(result.dependencies.serverDependencies, 'unknown');
});

test('observed JS and CSS comments identify lodash and Bootstrap versions', () => {
  const result = detect({
    scriptSrc: [`${ORIGIN}/assets/bundle.js`],
    stylesheetHref: [`${ORIGIN}/css/site.css`],
    resourceBodies: [
      { url: `${ORIGIN}/assets/bundle.js`, kind: 'script', status: 200,
        body: '/*! lodash v4.17.21 */\nvoid 0;' },
      { url: `${ORIGIN}/css/site.css`, kind: 'stylesheet', status: 200,
        body: '/*! Bootstrap v5.3.3 */ body { margin: 0; }' },
    ],
  });
  assert.equal(named(result.libraries, 'lodash')?.version, '4.17.21');
  assert.equal(named(result.libraries, 'bootstrap')?.version, '5.3.3');
  for (const name of ['lodash', 'bootstrap']) {
    const indicator = named(result.dependencies.libraries, name);
    assert.equal(indicator?.identification, 'indicator-only');
    assert.ok(indicator.evidence.some(item => item.kind === 'source-comment'));
    assert.equal(result.dependencies.assets.find(item => item.id === indicator.assetId)?.state, 'response-observed');
  }
});

test('only a JS comment identifies jQuery; a library-like string does not override its version', () => {
  const result = detect({ resourceBodies: [{ url: `${ORIGIN}/assets/bundle.js`, kind: 'script', status: 200,
    body: '/*! jQuery v3.6.0 */\nconst message = "jQuery v9.9.9";' }] });
  assert.equal(named(result.libraries, 'jquery')?.version, '3.6.0');
  assert.equal(named(result.dependencies.libraries, 'jquery')?.version, '3.6.0');
  assert.equal(result.dependencies.libraries.some(item => item.version === '9.9.9'), false);
});

test('conflicting filename and content versions remain unresolved', () => {
  const url = `${ORIGIN}/assets/jquery-3.7.1.min.js`;
  const result = detect({ scriptSrc: [url], resourceBodies: [{ url, kind: 'script', status: 200,
    body: '/*! jQuery v3.6.0 */\nvoid 0;' }] });
  const indicator = named(result.dependencies.libraries, 'jquery');
  assert.equal(indicator?.version, null);
  assert.equal(indicator?.versionStatus, 'conflicting-indicators');
  assert.deepEqual(indicator?.versionCandidates, ['3.6.0', '3.7.1']);
  assert.equal(named(result.libraries, 'jquery')?.version, null);
});

test('Wappalyzer and filename evidence merge into one jQuery result', () => {
  const url = `${ORIGIN}/assets/jquery-3.6.0.min.js`;
  const result = detect({ scriptSrc: [url], resourceBodies: [{ url, kind: 'script', status: 200,
    body: '/*! jQuery v3.6.0 */\nvoid 0;' }] });
  assert.equal(result.libraries.filter(item => item.name.toLowerCase() === 'jquery').length, 1);
  assert.equal(named(result.libraries, 'jquery')?.version, '3.6.0');
  assert.ok(named(result.dependencies.libraries, 'jquery'));
});

test('an unrelated bundle does not become a library from a JS string literal', () => {
  const result = detect({ scriptSrc: [`${ORIGIN}/assets/bundle.js`], resourceBodies: [{
    url: `${ORIGIN}/assets/bundle.js`, kind: 'script', status: 200,
    body: 'const label = "jQuery v9.9.9, lodash v4.17.21";',
  }] });
  assert.equal(named(result.libraries, 'jquery'), undefined);
  assert.equal(named(result.libraries, 'lodash'), undefined);
  assert.deepEqual(result.dependencies.libraries, []);
});

test('dependency graph connects its page node and redacts opaque URL segments', () => {
  const secret = 'abcdefghijklmnopqrstuvwxyz123456';
  const result = detect({ url: `${ORIGIN}/account/${secret}/?token=PAGE-SECRET`,
    scriptSrc: [`${ORIGIN}/assets/${secret}/react-dom-18.2.0.min.js?token=ASSET-SECRET`] });
  const graph = result.dependencies;
  assert.deepEqual(graph.pages, [{ id: 'page-1', url: `${ORIGIN}/account/{token}/?redacted` }]);
  assert.ok(graph.relations.some(item => item.from === 'page-1' && item.kind === 'script-src'));
  assert.doesNotMatch(JSON.stringify(graph), /ASSET-SECRET|PAGE-SECRET|abcdefghijklmnopqrstuvwxyz123456/u);
});

test('inline module imports use the document base URL', () => {
  const result = detect({ inlineBaseUrl: `${ORIGIN}/assets/`,
    inlineScripts: [{ body: "import './module.js';", type: 'module' }] });
  assert.ok(result.dependencies.assets.some(item => item.url === `${ORIGIN}/assets/module.js`));
  assert.ok(result.dependencies.relations.some(item => item.kind === 'js-import'));
});

test('dependency limits are explicit when later references or sources are not inspected', () => {
  const references = detect({ scriptSrc: Array.from({ length: 201 }, (_, index) =>
    `${ORIGIN}/assets/${index}.js`) });
  assert.equal(references.dependencies.assets.length, 200);
  assert.ok(references.dependencies.coverage.reasons.includes('dom-reference-limit'));

  const resources = detect({ resourceBodies: Array.from({ length: 33 }, (_, index) => ({
    url: `${ORIGIN}/assets/${index}.js`, kind: 'script', status: 200,
    body: index === 32 ? '/* axios v1.6.8 */' : 'void 0;',
  })) });
  assert.equal(named(resources.libraries, 'Axios'), undefined);
  assert.ok(resources.dependencies.coverage.reasons.includes('resource-response-limit'));

  const inline = detect({ inlineScripts: Array.from({ length: 33 }, (_, index) => ({
    body: index === 32 ? '/* axios v1.6.8 */' : 'void 0;', type: 'module',
  })) });
  assert.equal(named(inline.libraries, 'Axios'), undefined);
  assert.ok(inline.dependencies.coverage.reasons.includes('inline-script-limit'));
});
