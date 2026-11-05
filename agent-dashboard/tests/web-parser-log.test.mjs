import test from 'node:test';
import assert from 'node:assert/strict';
import { createWebInfoLoader, renderWebParserLog, renderWebParserLogBody } from '../dist/web-info-view.js';

const ARTIFACT = 'b'.repeat(64);
const RUN_A = 'general-11111111-2222-3333-4444-aaaaaaaaaaaa';
const RUN_B = 'general-11111111-2222-3333-4444-bbbbbbbbbbbb';

// The shape apps/api/module-management.mjs returns for a web_info.collected event.
function log(overrides = {}) {
  return { id: 'log-1', runId: RUN_A, sequence: 1, module: 'web-parser', stage: 'web_info.collected', status: 200,
    title: '웹 정보 수집', createdAt: '2026-11-01T06:01:05Z', detail: 'GET /board → HTTP 200', asset: '/board?page=2',
    sessionRole: 'member', probeId: 'p-web-1', iteration: 1, ok: true, httpStatus: 200, artifactId: ARTIFACT,
    counts: { technologies: 3, paths: 34, forms: 1, errors: 0 }, truncated: false, ...overrides };
}

function logs() {
  return [
    log({ id: 'log-old', createdAt: '2026-11-01T06:00:05Z', asset: '/', probeId: 'p-web-0' }),
    log({ id: 'log-fail', runId: RUN_B, createdAt: '2026-11-01T06:03:05Z', asset: '/admin', ok: false, httpStatus: null,
      status: null, detail: '웹 정보 수집 실패', probeId: 'p-web-9', counts: { technologies: 0, paths: 0, forms: 0, errors: 1 } }),
    log({ id: 'log-new', createdAt: '2026-11-01T06:02:05Z', httpStatus: 403, status: 403, truncated: true, artifactId: undefined }),
    { id: 'legacy-1', runId: 'run-legacy', module: 'xss-parser', stage: 'observe', status: 'completed',
      title: 'xss-parser 관측', detail: 'legacy detail', createdAt: '2026-10-01T00:00:00Z' },
  ];
}

const facts = html => [...html.matchAll(/<small>([^<]+)<\/small><strong>([^<]+)<\/strong>/g)].map(match => [match[1], match[2]]);

test('the summary strip counts collections only and the rows are newest first', () => {
  const html = renderWebParserLog(logs(), { total: 4 });
  assert.deepEqual(facts(html), [['수집 횟수', '3'], ['성공 / 실패', '2 / 1'], ['수집 페이지', '3'], ['포함된 실행', '2'],
    ['마지막 수집', new Date('2026-11-01T06:03:05Z').toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' })]]);
  assert.match(html, /<div class="panel-heading">[\s\S]*<div class="web-parser-log-actions"><span class="local-chip">3건<\/span><button type="button" class="button secondary" data-action="refresh-module">새로고침<\/button><\/div><\/div><div class="web-parser-log-content">/);
  const order = ['log-fail', 'log-new', 'log-old'].map(id => html.indexOf(`data-log-id="${id}"`));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.ok(order[0] > 0);
  assert.match(html, new RegExp(`<span class="web-parser-log-run mono" title="${RUN_B}">…bbbbbbbb</span>`));
  assert.match(html, /<span class="ci-state ci-incomplete">HTTP 403<\/span>[\s\S]*일부 생략/);
  assert.match(html, /기술 3 · 경로 34 · 폼 1 · 오류 0/);
  assert.doesNotMatch(html, /최근 \d+건만/);
  assert.match(renderWebParserLog(logs(), { total: 240 }), /최근 4건만 표시합니다 \(전체 로그 240건\)/);
  assert.doesNotMatch(html, /취약|위험/);
});

test('only rows with a 64-hex artifact id get the fetch hook; others say 상세 정보 없음', () => {
  const html = renderWebParserLogBody([log({ id: 'a' }), log({ id: 'b', artifactId: undefined }),
    log({ id: 'c', artifactId: '../../api/runs' })]);
  assert.equal(html.match(/data-web-info-artifact="/g).length, 1);
  assert.match(html, new RegExp(`data-log-id="a" data-web-info-artifact="${ARTIFACT}"`));
  assert.equal(html.match(/상세 정보 없음/g).length, 4);
  assert.doesNotMatch(html, /<details[^>]* open/);
});

test('search covers asset, run, probe and status; the failed-only toggle keeps failed rows', () => {
  const ids = html => [...html.matchAll(/data-log-id="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { failedOnly: true })), ['log-fail']);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { query: '/ADMIN' })), ['log-fail']);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { query: 'bbbbbbbb' })), ['log-fail']);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { query: 'p-web-0' })), ['log-old']);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { query: 'HTTP 403' })), ['log-new']);
  assert.deepEqual(ids(renderWebParserLogBody(logs(), { query: '수집 실패' })), ['log-fail']);
  assert.match(renderWebParserLogBody(logs(), { query: 'nothing-matches' }), /조건에 맞는 수집 기록이 없습니다/);
  assert.match(renderWebParserLogBody([]), /수집 기록이 없습니다/);
});

test('non-collection web-parser events stay in a folded 기타 로그 list', () => {
  const html = renderWebParserLogBody(logs());
  assert.match(html, /<details class="web-info-fold web-parser-other-logs"><summary>기타 로그 <span class="mono">1<\/span>/);
  assert.match(html, /xss-parser 관측 <span class="ci-state">observe<\/span> · legacy detail/);
  assert.doesNotMatch(renderWebParserLogBody(logs(), { query: 'p-web-0' }), /기타 로그/);
  assert.doesNotMatch(renderWebParserLogBody(logs().slice(0, 3)), /기타 로그/);
});

test('every log string is escaped, including attributes', () => {
  const payload = '<script>alert(1)</script>"\'';
  const html = renderWebParserLog([log({ id: payload, runId: payload, asset: payload, probeId: payload, detail: payload,
    sessionRole: payload }), { id: payload, stage: payload, title: payload, detail: payload, createdAt: payload }],
  { query: payload });
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /title="[^"]*"[^ >]/);
  assert.match(html, /data-log-id="&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&#39;"/);
  assert.match(html, /value="&lt;script&gt;/);
  assert.match(html, /시각 미기록/);
});

test('the artifact loader requests each id once and retries after a failure', async () => {
  const calls = [];
  let fail = true;
  const loader = createWebInfoLoader(async path => {
    calls.push(path);
    if (fail) throw Object.assign(new Error('Artifact not found.'), { status: 404 });
    return { schemaVersion: 'web-parser-1', technologies: [{ name: 'jQuery' }] };
  });
  assert.match(await loader(ARTIFACT), /저장된 상세 정보를 찾을 수 없습니다/);
  fail = false;
  assert.match(await loader(ARTIFACT), new RegExp(`jQuery[\\s\\S]*href="/api/artifacts/${ARTIFACT}"|href="/api/artifacts/${ARTIFACT}"[\\s\\S]*jQuery`));
  assert.match(await loader(ARTIFACT), /jQuery/);
  assert.deepEqual(calls, [`/api/artifacts/${ARTIFACT}`, `/api/artifacts/${ARTIFACT}`]);
  assert.match(await loader('../runs'), /상세 정보 없음/);
  assert.equal(calls.length, 2);
  const conflict = createWebInfoLoader(async () => { throw Object.assign(new Error('x'), { status: 409 }); });
  assert.match(await conflict(ARTIFACT), /민감 정보 검사를 통과하지 못해/);
  const offline = createWebInfoLoader(async () => { throw new TypeError('Failed to fetch'); });
  assert.match(await offline(ARTIFACT), /연결을 확인한 뒤 다시 펼치세요/);
});
