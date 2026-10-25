import test from 'node:test';
import assert from 'node:assert/strict';
import { toStructure } from '../structure-output.mjs';
import { parseNpmLock, parsePom } from '../dependency-inventory.mjs';

const base = 'http://127.0.0.1:4101';

const fixture = () => ({
  schemaVersion: '3.4',
  startUrl: base + '/',
  pages: [
    {
      id: 'page-1', url: base + '/', title: 'Home',
      areas: [{
        id: 'a', parent: null, kind: 'nav', name: 'Menu',
        links: [
          {
            url: base + '/post/{number}',
            targetPageId: 'page-2',
            visited: true
          },
          {
            url: base + '/post/{number}',
            targetPageId: null,
            visited: false
          }
        ]
      }]
    },
    {
      id: 'page-2',
      url: base + '/post/{number}',
      title: 'Post',
      areas: []
    }
  ],
  summary: {
    truncated: true,
    truncationReasons: ['max-pages']
  }
});

test('visited IDs remain connected; masked unknowns are not merged', () => {
  const data = fixture();
  data.pages[0].areas[0].links.push({
    ...data.pages[0].areas[0].links[1]
  });

  const out = toStructure(data);

  assert.equal(out.targets.length, 4);
  assert.equal(
    out.targets.filter(target => target.pageId === 'page-2').length,
    1
  );
  assert.equal(out.coverage.ambiguousTargetOccurrences, 2);
});

test('raw target identity is retained without exposing raw URLs', () => {
  const data = fixture();
  const pageUrls = new Map([
    ['page-1', base + '/'],
    ['page-2', base + '/post/42']
  ]);
  const targetUrls = new WeakMap();
  const links = data.pages[0].areas[0].links;

  links.push({ ...links[1] });
  links.forEach((link, i) => {
    targetUrls.set(link, base + '/post/' + (i === 0 ? 42 : 43));
  });

  const out = toStructure(data, { pageUrls, targetUrls });

  assert.equal(out.targets.length, 3);
  assert.equal(out.coverage.targetIdentity, 'raw-url');
  assert.equal(JSON.stringify(out).includes('/post/42'), false);
  assert.equal(out.dependencies.status, 'not-provided');
});

test('common structures are shared without claiming JS execution', () => {
  const data = fixture();

  const area = {
    id: 'first', parent: null, kind: 'section', name: 'Search',
    forms: [{
      selector: '#form',
      htmlMethod: 'GET',
      htmlAction: base + '/search',
      fields: [{ name: 'q', visible: false }]
    }]
  };

  data.pages.forEach((page, i) => {
    page.areas = [{ ...structuredClone(area), id: 'area-' + i }];
    page.renderRules = [{
      id: 'r' + i,
      selector: '#results',
      operation: 'append',
      evidence: 'static-js'
    }];
    page.behaviors = [{
      trigger: { event: 'submit', selector: '#form' },
      api: [{ method: 'GET', url: base + '/api?q={value}' }],
      script: base + '/js/site.js',
      evidence: 'static-js',
      renderRefs: ['r' + i]
    }];
  });

  const out = toStructure(data);

  assert.equal(out.components.length, 1);
  assert.equal(out.forms.length, 1);
  assert.equal(out.behaviors.length, 1);
  assert.equal(out.behaviors[0].evidence, 'static-js');
  assert.equal(out.forms[0].fields[0].visible, false);
  assert.equal(out.pages[0].observedRequests, undefined);
});

test('missing references and area cycles are rejected', () => {
  const data = fixture();

  data.pages[0].behaviors = [{ renderRefs: ['unknown'] }];
  assert.throws(() => toStructure(data), /Missing render/);

  delete data.pages[0].behaviors;
  data.pages[0].areas[0].parent = 'a';
  assert.throws(() => toStructure(data), /Cyclic|cyclic/);
});

test('npm retains nested versions and relation origins', () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', dependencies: { a: '1', b: '1' } },
      'node_modules/a': {
        version: '1.0.0', dependencies: { x: '1' }
      },
      'node_modules/b': {
        version: '1.0.0', dependencies: { x: '2' }
      },
      'node_modules/x': { version: '1.0.0' },
      'node_modules/b/node_modules/x': { version: '2.0.0' }
    }
  };

  const result = parseNpmLock(JSON.stringify(lock));
  const packages = new Map(result.packages.map(pkg => [pkg.id, pkg]));
  const edges = result.edges.filter(edge => edge.name === 'x');

  assert.equal(edges.length, 2);
  assert.deepEqual(
    edges.map(edge => packages.get(edge.to).version),
    ['1.0.0', '2.0.0']
  );
});

test('npm optional declarations and unresolved relations are explicit', () => {
  const result = parseNpmLock(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'app',
        dependencies: { x: '1' },
        optionalDependencies: { x: '2' }
      }
    }
  }));

  assert.equal(result.edges.length, 1);
  assert.equal(result.edges[0].kind, 'optionalDependencies');
  assert.equal(result.edges[0].to, null);

  assert.throws(() => parseNpmLock(
    '{"lockfileVersion":3,"packages":{"":{},"/":{}}}'
  ), /location/);
});

const pom = dependencies =>
  '<project xmlns="http://maven.apache.org/POM/4.0.0">' +
  '<groupId>lab</groupId><artifactId>app</artifactId>' +
  '<version>1.0</version>' + dependencies + '</project>';

test('Maven reads local declarations and leaves managed versions unknown', () => {
  const result = parsePom(pom(
    '<properties><yaml.version>1.33</yaml.version></properties>' +
    '<dependencies>' +
    '<dependency><groupId>org.yaml</groupId>' +
    '<artifactId>snakeyaml</artifactId>' +
    '<version>${yaml.version}</version></dependency>' +
    '<dependency><groupId>spring</groupId>' +
    '<artifactId>starter</artifactId><scope>test</scope></dependency>' +
    '</dependencies>'
  ));

  assert.equal(result.packages[1].version, '1.33');
  assert.equal(result.packages[2].version, null);
  assert.equal(result.unresolved, 1);
  assert.equal(result.edges[1].scope, 'test');
  assert.equal(result.coverage, 'direct-declarations-only');
});

test('Maven plugin dependencies are not application dependencies', () => {
  const result = parsePom(pom(
    '<build><plugins><plugin><dependencies><dependency>' +
    '<groupId>wrong</groupId><artifactId>wrong</artifactId>' +
    '</dependency></dependencies></plugin></plugins></build>'
  ));

  assert.equal(result.packages.length, 1);
  assert.equal(result.edges.length, 0);
});

test('unsupported XML is rejected and version ranges remain unresolved', () => {
  for (const input of [
    '<!DOCTYPE project><project/>',
    '<project><broken></project>'
  ]) {
    assert.throws(() => parsePom(input));
  }

  const result = parsePom(pom(
    '<dependencies><dependency><groupId>a</groupId>' +
    '<artifactId>b</artifactId><version>[1,2)</version>' +
    '</dependency></dependencies>'
  ));

  assert.equal(result.packages[1].version, null);
  assert.equal(result.packages[1].requested, '[1,2)');
});
