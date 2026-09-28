import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fuzz, validate } from '../fuzzer.mjs';
import { analyze } from '../analyze.mjs';

const html = '<form><input id="q"><button>Go</button></form><div id="out"></div>';
const code = sink => `document.querySelector('form').addEventListener('submit', e => {e.preventDefault(); document.querySelector('#out').${sink} = document.querySelector('#q').value;});`;
const config = { maxCases: 10, settleMs: 100, queryParams: [] };
test('AST ignores comments and strings, flags computed and direct sinks', () => {
  const result = analyze('// a.innerHTML=x\nconst s="a.innerHTML=x"; a["innerHTML"]=x; a.insertAdjacentHTML("beforeend", x);', '/app.js');
  assert.equal(result.candidates.length, 2);
  assert.equal(result.candidates[0].line, 2);
});
test('invalid inputs are rejected before launching a browser', () => {
  for (const input of [{}, { html: '', js: '', maxCases: 0 }, { html: '', js: '', profile: 'other' }, { html: '', js: '', actions: [{}] }]) assert.throws(() => validate(input));
});
test('actual form-to-innerHTML execution is confirmed; nonexecuting probes remain unconfirmed', async () => {
  const r = await fuzz({ html, js: code('innerHTML'), ...config });
  assert.ok(r.findings.some(f => f.payloadId === 'img-error'));
  assert.ok(r.findings.every(f => f.evidence.executions > 0));
  assert.ok(r.cases.some(c => c.status === 'not_observed'));
  assert.equal(r.summary.truncated, true);
});
test('textContent negative control never confirms execution', async () => {
  const r = await fuzz({ html, js: code('textContent'), ...config });
  assert.equal(r.findings.length, 0);
  assert.equal(r.candidates.length, 0);
  assert.equal(r.summary.errorCases, 0);
});
test('escaping at a dangerous sink remains a candidate without confirmation', async () => {
  const safe = code('innerHTML').replace("document.querySelector('#q').value", "document.querySelector('#q').value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')");
  const r = await fuzz({ html, js: safe, ...config });
  assert.equal(r.findings.length, 0);
  assert.equal(r.candidates.length, 1);
});
test('URL query source executes and external requests are intercepted', async () => {
  const r = await fuzz({ html: '<div id="out"></div>', js: `fetch('https://example.com/probe');document.querySelector('#out').innerHTML = new URLSearchParams(location.search).get('q') || '';`, ...config, maxCases: 1, queryParams: ['q'] });
  assert.equal(r.findings.length, 1);
  assert.ok(r.diagnostics.blockedRequests.includes('https://example.com/probe'));
});
test('JSON fixture injection supports frontend API data', async () => {
  const r = await fuzz({ html: '<div id="out"></div>', js: `fetch('/data').then(r=>r.json()).then(d=>document.querySelector('#out').innerHTML=d.body);`,
    fixtures: [{ path: '/data', body: { body: '{{PAYLOAD}}' } }], ...config, maxCases: 11 });
  assert.ok(r.findings.some(f => f.source.kind === 'fixture'));
});
test('FSL-CA3P content is vulnerable while title is safe', async () => {
  const root = new URL('../../vul-web-1/public/', import.meta.url);
  const r = await fuzz({ html: await readFile(new URL('index.html', root), 'utf8'), js: await readFile(new URL('app.js', root), 'utf8'), profile: 'fsl-ca3p', ...config, maxCases: 20 });
  assert.ok(r.findings.some(f => f.source.id === 'post-content'));
  assert.ok(!r.findings.some(f => f.source.id === 'post-title'));
  assert.ok(r.candidates.some(c => c.line === 120 && c.sink === 'innerHTML'));
  assert.ok(r.findings.every(f => f.type === 'stored-xss-client-with-modeled-api' && !f.realServerVerified));
  assert.equal(r.summary.errorCases, 0);
});
test('inline scripts retain their HTML source line and execute without a supplied JS file', async () => {
  const r = await fuzz({ html: '<div id="out"></div>\n<script>document.querySelector("#out").innerHTML=new URLSearchParams(location.search).get("q") || "";</script>', js: [], ...config, maxCases: 1, queryParams: ['q'] });
  assert.equal(r.findings.length, 1);
  assert.equal(r.candidates[0].file, 'input.html');
  assert.equal(r.candidates[0].line, 2);
});
