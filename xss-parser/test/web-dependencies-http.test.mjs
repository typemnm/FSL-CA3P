import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { scan } from '../parser.mjs';

async function server(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}

function runCli(args) {
  return new Promise((resolve,reject) => {
    const child = spawn(process.execPath, ['cli.mjs', ...args], { cwd: new URL('..', import.meta.url), env: process.env });
    let stdout='', stderr='';
    child.stdout.on('data',x=>stdout+=x); child.stderr.on('data',x=>stderr+=x);
    child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));
  });
}

test('real Chromium: URL-only structured scan keeps isolation, IDs and libraries', async () => {
  let outsideHits = 0, writes = 0;
  const outside = await server((_req,res) => { outsideHits++;res.end('no'); });
  const site = await server((req,res) => {
    if (req.method !== 'GET') { writes++;res.statusCode=405;res.end();return; }
    res.setHeader('X-Powered-By','Express');
    if (req.url === '/') { res.setHeader('Content-Type','text/html');res.end(`<title>Fixture</title><main><a href="/next">Next</a></main><link rel="stylesheet" href="/style.css"><script type="module" src="/app.js"></script><script src="${outside.url}/jquery-9.9.9.min.js"></script><script>fetch('/write', {method:'POST'});fetch('${outside.url}/api');</script>`); }
    else if (req.url === '/app.js') { res.setHeader('Content-Type','application/javascript');res.end("/*! jQuery v3.7.1 */\nimport './child.js';"); }
    else if (req.url === '/child.js') { res.setHeader('Content-Type','application/javascript');res.end('/*! lodash v4.17.21 */\nvoid 0;'); }
    else if (req.url === '/style.css') { res.setHeader('Content-Type','text/css');res.end('/*! Bootstrap v5.3.3 */ @import "./base.css";'); }
    else if (req.url === '/base.css') { res.setHeader('Content-Type','text/css');res.end('body { margin:0 }'); }
    else if (req.url === '/next') { res.setHeader('Content-Type','text/html');res.end('<title>Next</title><main><a href="/">Home</a></main>'); }
    else { res.statusCode=404;res.end('not found'); }
  });
  try {
    const result = await scan(site.url, { structure:true, maxPages:2, waitMs:100 });
    assert.equal(result.moduleId,'web-parser');
    assert.equal(result.schemaVersion,'structure-1.0');
    assert.equal(result.pages.length,2,JSON.stringify(result));
    assert.equal(outsideHits,0);assert.equal(writes,0);
    const dep=result.dependencies;
    assert.equal(dep.scope,'web-exposed-resources');
    assert.ok(dep.libraries.some(x=>x.name==='jquery' && x.version==='3.7.1'));
    assert.ok(dep.libraries.some(x=>x.name==='bootstrap' && x.version==='5.3.3'));
    assert.ok(dep.libraries.some(x=>x.name==='lodash' && x.version==='4.17.21'));
    assert.ok(dep.assets.some(x=>x.state==='blocked-origin'));
    const ids = new Set([...result.pages,...dep.assets,...dep.libraries,...dep.moduleReferences].map(x=>x.id));
    for (const edge of dep.relations) { assert.ok(ids.has(edge.from)); assert.ok(ids.has(edge.to)); }
    assert.ok(dep.relations.some(x=>x.kind==='js-import'));
    assert.ok(dep.relations.some(x=>x.kind==='css-import'));
    const detail=await scan(site.url,{maxPages:1,waitMs:50});
    assert.equal(detail.schemaVersion,'3.4');assert.ok(detail.pages[0].areas);
    assert.equal(detail.moduleId,'web-parser');assert.ok(detail.dependencies.libraries.length);
  } finally { await site.close();await outside.close(); }
});

test('inline module imports resolve against the document base URI', async () => {
  let expectedRequests = 0;
  let wrongRequests = 0;
  const site = await server((req, res) => {
    if (req.url === '/') {
      res.setHeader('Content-Type', 'text/html');
      res.end('<base href="/static/"><script type="module">import "./child.js";</script>');
    } else if (req.url === '/static/child.js') {
      expectedRequests++;
      res.setHeader('Content-Type', 'application/javascript');
      res.end('export const loaded = true;');
    } else if (req.url === '/child.js') {
      wrongRequests++;
      res.statusCode = 404;
      res.end('wrong path');
    } else {
      res.statusCode = 404;
      res.end('not found');
    }
  });
  try {
    const result = await scan(site.url, { maxPages: 1, waitMs: 100 });
    const { assets, relations } = result.dependencies;
    const inline = assets.find(asset => asset.state === 'inline');
    const child = assets.find(asset => asset.url === `${site.url}/static/child.js`);
    assert.equal(expectedRequests, 1);
    assert.equal(wrongRequests, 0);
    assert.ok(inline);
    assert.ok(inline.url.startsWith(`${site.url}/#`));
    assert.ok(child);
    assert.ok(relations.some(edge => edge.from === inline.id && edge.to === child.id && edge.kind === 'js-import'));
    assert.equal(assets.some(asset => asset.url === `${site.url}/child.js`), false);
  } finally { await site.close(); }
});

test('CLI accepts URL alone, keeps optional inventory separate and never auto-reads local files', async () => {
  const site=await server((_req,res)=>{res.setHeader('Content-Type','text/html');res.end('<title>Plain</title><p>hello</p>');});
  const dir=await mkdtemp(join(tmpdir(),'web-parser-test-'));
  try {
    let result=await runCli(['--url',site.url,'--max-pages','1','--wait-ms','0','--structure']);
    assert.equal(result.code,0,result.stderr+result.stdout);
    let data=JSON.parse(result.stdout);
    assert.equal(data.coverage.failedPages,0,JSON.stringify(data));
    assert.equal(data.moduleId,'web-parser');assert.deepEqual(data.dependencies.sources,[]);
    const lock=join(dir,'package-lock.json');
    await writeFile(lock,JSON.stringify({lockfileVersion:3,packages:{'':{name:'app',version:'1.0.0'}}}));
    const out=join(dir,'out.json');
    result=await runCli(['--url',site.url,'--max-pages','1','--wait-ms','0','--structure','--npm-lock',lock,'--out',out]);
    assert.equal(result.code,0,result.stderr+result.stdout);
    data=JSON.parse(await readFile(out,'utf8'));
    assert.equal(data.dependencies.mode,'url-observation');
    assert.equal(data.dependencies.sources[0].ecosystem,'npm');
    result=await runCli(['--url',site.url,'--out']);assert.equal(result.code,1);
    result=await runCli(['--url','https://example.com']);assert.equal(result.code,1);
  } finally { await site.close();await rm(dir,{recursive:true,force:true}); }
});
