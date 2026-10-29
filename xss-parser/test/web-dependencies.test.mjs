import test from 'node:test';
import assert from 'node:assert/strict';
import { createWebInventory, readResourceReferences, LIMITS } from '../web-dependencies.mjs';
import { scan } from '../parser.mjs';

const origin = 'http://127.0.0.1:4101';
const inventory = () => createWebInventory(origin, raw => {
  const url = new URL(raw);
  return url.origin + url.pathname + (url.search ? '?redacted' : '') + (url.hash ? '#inline' : '');
});

test('URL alone inventory is partial, and never claims a server package inventory', () => {
  const data = inventory().snapshot();
  assert.equal(data.mode, 'url-observation');
  assert.equal(data.complete, false);
  assert.equal(data.serverDependencies, 'unknown');
  assert.equal(data.vulnerabilityMatching, 'not-performed');
  assert.deepEqual(data.libraries, []);
});

test('filename and actual content produce distinct evidence; conflicts stay unresolved', () => {
  const data = inventory();
  data.references('page-1', { items: [
    { url: origin + '/jquery-3.7.1.min.js', kind: 'script', relation: 'script-src' }
  ] });
  let result = data.snapshot();
  assert.equal(result.assets[0].state, 'referenced');
  assert.equal(result.libraries[0].evidence[0].kind, 'url-name-hint');
  data.response('page-1', origin + '/jquery-3.7.1.min.js', 'script', 200, '/*! jQuery v3.6.0 */\nvoid 0;');
  result = data.snapshot();
  assert.equal(result.assets[0].state, 'response-observed');
  assert.equal(result.libraries[0].version, null);
  assert.deepEqual(result.libraries[0].versionCandidates, ['3.6.0', '3.7.1']);
  assert.equal(result.libraries[0].versionStatus, 'conflicting-indicators');
});

test('bundle name is irrelevant to comment identification; string literals are not banners', () => {
  const data = inventory();
  data.response('page-1', origin + '/bundle.js', 'script', 200,
    '/*! lodash v4.17.21 */\nconst x="jQuery v9.9.9";');
  assert.deepEqual(data.snapshot().libraries.map(x => [x.name,x.version]), [['lodash','4.17.21']]);
});

test('known library with an unknown version stays null; numeric query values do not become versions', () => {
  const data = inventory();
  data.references('page-1', { items: [{ url: origin + '/vue.global.js?token=secret123', kind: 'script', relation: 'script-src' }] });
  const result = data.snapshot();
  assert.equal(result.libraries[0].version, null);
  assert.equal(JSON.stringify(result).includes('secret123'), false);
});

test('two resources with different library versions are not collapsed by library name', () => {
  const data = inventory();
  for (const [i, version] of ['3.6.0','3.7.1'].entries()) {
    data.response('page-1', origin + '/bundle' + i + '.js', 'script', 200, `/*! jQuery v${version} */`);
  }
  assert.equal(data.snapshot().libraries.length, 2);
});

test('JS import relations are literal static observations, not npm transitive resolution', () => {
  const data = inventory();
  data.response('page-1', origin + '/js/main.js', 'script', 200,
    "import x from './child.js'; export * from './more.js'; import('react'); const x2='z'; import(x2);");
  const result = data.snapshot();
  assert.equal(result.assets.length, 3);
  assert.equal(result.moduleReferences[0].specifier, 'react');
  assert.equal(result.moduleReferences[0].resolution, 'unresolved');
  assert.equal(result.relations.filter(edge => edge.kind === 'js-import').length, 3);
  assert.ok(result.coverage.reasons.includes('dynamic-import-unresolved'));
  assert.equal(result.libraries.length, 0);
});

test('CSS @import ignores strings and comments; Bootstrap comment is only a claim', () => {
  const data = inventory();
  data.response('page-1', origin + '/css/app.css', 'stylesheet', 200,
    '/*! Bootstrap v5.3.3 */ @import "base.css"; /* @import "hidden.css"; */ .x{content:"@import fake.css"}');
  const result = data.snapshot();
  assert.equal(result.libraries[0].name, 'bootstrap');
  assert.equal(result.libraries[0].identification, 'indicator-only');
  assert.equal(result.assets.length, 2);
  assert.ok(result.assets.some(x => x.url.endsWith('/css/base.css')));
});

test('external URL declarations remain blocked without content fingerprinting', () => {
  const data = inventory();
  data.references('page-1', { items: [{ url: 'https://cdn.example/jquery-3.7.1.min.js', kind: 'script', relation: 'script-src' }] });
  const result = data.snapshot();
  assert.equal(result.assets[0].state, 'blocked-origin');
  assert.deepEqual(result.libraries[0].evidence.map(x => x.kind), ['url-name-hint']);
  assert.equal(result.assets[0].inspectedContentSha256, undefined);
});

test('HTTP failures are not parsed; header claims exclude cookies and raw header values', () => {
  const data = inventory();
  data.response('page-1', origin + '/error.js', 'script', 404, '/*! lodash v4.17.15 */');
  data.headers('page-1', { 'x-powered-by': 'Express', 'set-cookie': 'session=secret123', 'server': 'hidden-sensitive-data' });
  const result = data.snapshot();
  assert.equal(result.libraries.length, 0);
  assert.equal(result.assets[0].state, 'http-error');
  assert.equal(result.technologies[0].name, 'Express');
  assert.equal(result.technologies[0].version, null);
  assert.equal(JSON.stringify(result).includes('secret123'), false);
  assert.equal(JSON.stringify(result).includes('hidden-sensitive-data'), false);
});

test('Spring Boot response header is reported as an observed technology', () => {
  const data = inventory();
  data.headers('page-1', { 'x-powered-by': 'Spring Boot' });
  assert.deepEqual(data.snapshot().technologies, [{
    name: 'Spring Boot', version: null, evidence: 'response-header-claim',
    header: 'x-powered-by', pageIds: ['page-1']
  }]);
});

test('malformed imports and unsupported syntax do not crash a scan', () => {
  const data = inventory();
  assert.doesNotThrow(() => data.response('page-1',origin + '/one.js','script',200,"import 'https://[';"));
  assert.doesNotThrow(() => data.response('page-1',origin + '/two.js','script',200,'function {'));
  assert.ok(data.snapshot().coverage.reasons.includes('unsupported-resource-url'));
  assert.ok(data.snapshot().coverage.reasons.includes('script-syntax-not-interpreted'));
});

test('inspection is bounded and duplicate responses do not repeat body interpretation', () => {
  const data = inventory();
  const body = '/*! jQuery v3.7.1 */';
  data.response('page-1',origin + '/bundle.js','script',200,body);
  data.response('page-2',origin + '/bundle.js','script',200,body);
  assert.equal(data.snapshot().coverage.inspectedBytes, Buffer.byteLength(body));
  data.response('page-1',origin + '/huge.js','script',200,' '.repeat(LIMITS.sourceBytes+1));
  assert.ok(data.snapshot().coverage.reasons.includes('source-byte-limit'));
  for (let i=0; i<LIMITS.assets+10; i++) data.references('page-1',{items:[{url:origin+'/a'+i+'.js',kind:'script',relation:'script-src'}]});
  assert.equal(data.snapshot().assets.length, LIMITS.assets);
  assert.ok(data.snapshot().coverage.reasons.includes('asset-limit'));
});


import { chromium } from 'playwright';
import { parseArgs } from '../cli.mjs';

test('CLI requires only URL; optional evidence arguments do not become mandatory', () => {
  const args=parseArgs(['--url',origin]);
  assert.deepEqual(args.inputs,[]);
  assert.equal(args.options.structure,false);
  assert.throws(()=>parseArgs(['--url',origin,'--out']),/Invalid option/);
  assert.throws(()=>parseArgs(['--url',origin,'--structure','--structure']),/Duplicate option/);
});

test('real Chromium DOM resource extraction uses resolved URLs without network access', async () => {
  const browser=await chromium.launch({headless:true,executablePath:process.env.WEB_PARSER_BROWSER_PATH});
  try {
    const page=await browser.newPage();
    await page.route('**/*',route=>route.abort());
    await page.setContent(`<base href="${origin}/base/"><script src="jquery-3.7.1.min.js"></script><link rel="stylesheet" href="site.css"><link rel="modulepreload" href="module.js">`,{waitUntil:'domcontentloaded'});
    const data=await page.evaluate(readResourceReferences);
    assert.equal(data.items.length,3);
    assert.deepEqual(data.items.map(x=>x.url),[origin+'/base/jquery-3.7.1.min.js',origin+'/base/site.css',origin+'/base/module.js']);
    assert.equal(data.truncated,false);
  } finally {await browser.close();}
});

test('scan wires response, DOM and inline evidence into both output contracts (browser double)', async t => {
  let handler;
  const emptyDom={title:'Fixture',areas:[],posts:[],events:[],counts:{areas:0,forms:0,fields:0,buttons:0,links:0,outputs:0,posts:0,events:0}};
  const response=(url)=>({ status:()=>200,headers:()=>({'x-powered-by':'Express'}),body:async()=>Buffer.from('/*! jQuery v3.7.1 */ void 0;') });
  const page={ setDefaultNavigationTimeout(){},on(){},url:()=>origin+'/',close:async()=>{},
    goto:async()=>{
      for(const kind of ['document','script']) {
        const url=origin+(kind==='document'?'/':'/app.js');
        await handler({request:()=>({url:()=>url,method:()=> 'GET',resourceType:()=>kind}),
          fetch:async()=>response(url), fulfill:async()=>{},abort:async()=>{}});
      }
      return response(origin);
    },
    evaluate:async fn=>fn.name==='readDom'?structuredClone(emptyDom):fn.name==='readResourceReferences'?{items:[{url:origin+'/app.js',kind:'script',relation:'script-src'}]}:[],
    waitForTimeout:async()=>{}
  };
  const context={setDefaultTimeout(){},routeWebSocket:async()=>{},route:async(_glob,fn)=>{handler=fn;},newPage:async()=>page,close:async()=>{}};
  t.mock.method(chromium,'launch',async()=>({newContext:async()=>context,close:async()=>{}}));
  for(const structure of [false,true]) {
    const result=await scan(origin+'/?q=web-parser',{maxPages:1,waitMs:0,structure});
    assert.equal(result.moduleId,'web-parser');
    assert.equal(result.schemaVersion,structure?'structure-1.0':'3.4');
    assert.equal(result.dependencies.libraries[0].name,'jquery');
    assert.equal(result.dependencies.libraries[0].version,'3.7.1');
    assert.equal(result.dependencies.technologies[0].name,'Express');
    assert.equal(result.pages.length,1);
  }
});
