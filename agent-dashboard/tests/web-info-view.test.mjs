import test from 'node:test';
import assert from 'node:assert/strict';
import { renderWebInfoDetail, renderWebInfoSection, webInfoEvents } from '../dist/web-info-view.js';
import { renderGeneralLiveResults } from '../dist/general-results.js';

const ARTIFACT = 'c'.repeat(64);

function event(overrides = {}) {
  return { stage: 'web_info.collected', module: 'web-parser', source: 'web-parser', type: 'info',
    title: '웹 정보 수집', detail: 'GET /board → HTTP 200', probeId: 'p-web-1', iteration: 1, asset: '/board?page=2',
    sessionRole: 'member', ok: true, status: 200, artifactId: ARTIFACT,
    counts: { technologies: 2, paths: 3, forms: 1, errors: 1 }, truncated: false, ...overrides };
}

function view() {
  return {
    schemaVersion: 'web-info-view/1', probeId: 'p-web-1', iteration: 1, sessionRole: 'member',
    target: { requestedUrl: 'http://app.test/board?page=2', finalUrl: 'https://app.test/board?page=2', origin: 'https://app.test' },
    response: { status: 200, contentType: 'text/html; charset=utf-8', loadTimingMs: 411.6, title: '게시판 목록',
      tls: { protocol: 'TLS 1.3', issuer: 'Test CA', subjectName: 'app.test', validFrom: 1767225600, validTo: 1798761600 } },
    redirectChain: [{ from: 'http://app.test/board?page=2', to: 'https://app.test/board?page=2', status: 301, kind: 'http' }],
    technologies: [
      { name: 'jQuery', version: '3.6.0', categories: ['JavaScript libraries'], confidence: 100, library: true,
        evidence: [{ field: 'scriptSrc', match: 'jquery-3.6.0.min.js' }, { field: 'js', name: 'jQuery.fn.jquery', match: '3.6.0' }] },
      { name: 'nginx', version: null, categories: ['Web servers'], confidence: 100, library: false,
        evidence: [{ field: 'headers', name: 'server', match: 'nginx' }] },
    ],
    paths: { total: 640, items: [
      { url: 'https://app.test/board/view', sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['id'] },
      { url: 'https://app.test/private/*.php$', sources: ['robots:disallow'], methods: [], sameOrigin: true, params: [], wildcard: true },
      { url: 'https://cdn.example.net/lib.js', sources: ['script', 'request:script'], methods: ['GET'], sameOrigin: false, params: [] },
    ] },
    forms: { total: 1, items: [{ action: 'https://app.test/login', method: 'post',
      fields: [{ name: 'username', type: 'text' }, { name: 'password', type: 'password' }] }] },
    frames: [{ tag: 'iframe', src: 'https://app.test/embed', sandbox: null }],
    headers: [{ name: 'Content-Type', value: 'text/html' }, { name: 'X-Frame-Options', value: 'DENY' }, { name: 'Set-Cookie' }],
    cookies: [{ name: 'SESSIONID', domain: 'app.test', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'pref', domain: 'app.test', path: '/', expires: 1798761600, httpOnly: false, secure: false, sameSite: 'None' }],
    hosts: [{ host: 'app.test', sameOrigin: true, requests: 12, kinds: ['script', 'xhr'] },
      { host: 'cdn.example.net', sameOrigin: false, requests: 1, kinds: ['script'] }],
    errors: [{ stage: 'load', message: 'https://app.test/board?page=2: timeout' }],
    truncated: { source: false, sections: ['paths'] },
  };
}

/** Replace every string (except the schema/stage discriminators) with a markup payload. */
function poison(value, payload) {
  if (Array.isArray(value)) return value.map(entry => poison(entry, payload));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .map(([key, entry]) => [key, key === 'schemaVersion' || key === 'stage' ? entry : poison(entry, payload)]));
  return typeof value === 'string' ? payload : value;
}

test('a web-info-view/1 artifact renders every observed section without verdicts', () => {
  const html = renderWebInfoDetail(view());
  for (const heading of ['기술', '경로', '폼', '응답 헤더', '쿠키', '리다이렉트 경로', '호스트별 리소스', '프레임', '수집 오류']) {
    assert.match(html, new RegExp(`>${heading} <span class="mono">`), heading);
  }
  assert.match(html, /요청 <span class="mono">http:\/\/app\.test\/board\?page=2<\/span> → 최종 <span class="mono">https:\/\/app\.test/);
  assert.match(html, /<small>로드 시간<\/small><strong>412 ms<\/strong>/);
  assert.match(html, /<small>리다이렉트<\/small><strong>1회<\/strong>/);
  assert.match(html, /Test CA · 만료 2027-01-01/);
  assert.match(html, /수집 오류 1건/);
  assert.match(html, /표시 상한으로 일부 생략: paths/);
  assert.match(html, /jQuery[\s\S]*3\.6\.0[\s\S]*라이브러리[\s\S]*근거 2건/);
  assert.match(html, /jQuery\.fn\.jquery/);
  assert.match(html, /전체 640개 중 3개를 받았습니다/);
  assert.match(html, /<span class="ci-state">패턴<\/span>/);
  assert.match(html, /<span class="ci-state">POST<\/span> <span class="mono">https:\/\/app\.test\/login/);
  assert.match(html, /X-Frame-Options<\/span> <span class="ci-state">있음/);
  assert.match(html, /Content-Security-Policy<\/span> <span class="ci-state web-info-absent">없음/);
  assert.match(html, /Set-Cookie<\/td><td class="mono"><em class="muted">값 숨김/);
  assert.match(html, /SESSIONID[\s\S]*세션[\s\S]*예/);
  assert.match(html, /2027-01-01/);
  assert.match(html, /301 · http/);
  assert.match(html, /sandbox 없음/);
  assert.match(html, /<span class="ci-state ci-incomplete">load<\/span>/);
  assert.doesNotMatch(html, /취약|위험|<a\b|<img\b/);
});

test('every string field of the view and the event is escaped', () => {
  const payload = '<script>alert(1)</script>"\'';
  const html = renderWebInfoDetail(poison(view(), payload));
  assert.doesNotMatch(html, /<script/i);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&#39;/);
  const section = renderWebInfoSection({ events: [poison(event(), payload)] });
  assert.doesNotMatch(section, /<script/i);
  assert.match(section, /&lt;script&gt;/);
  // A non-hex artifact id never reaches the fetch hook.
  assert.doesNotMatch(section, /data-web-info-artifact/);
});

test('an unknown schemaVersion renders a clear note instead of guessing', () => {
  assert.match(renderWebInfoDetail({ ...view(), schemaVersion: 'web-info-view/2' }), /지원하지 않는 웹 정보 형식입니다 \(web-info-view\/2\)/);
  assert.match(renderWebInfoDetail(null), /지원하지 않는 웹 정보 형식입니다\./);
  assert.match(renderWebInfoDetail({ ...view(), schemaVersion: '<b>x</b>' }), /\(&lt;b&gt;x&lt;\/b&gt;\)/);
});

test('cards are collapsed, and a failed event without an artifact shows no fetch hook', () => {
  const html = renderWebInfoSection({ events: [
    { stage: 'probe.observe' },
    event(),
    event({ probeId: 'p-web-2', ok: false, status: null, artifactId: null, type: 'warning', detail: '웹 정보 수집 실패',
      counts: { technologies: 0, paths: 0, forms: 0, errors: 0 } }),
  ] });
  assert.match(html, /웹 정보 · web-parser 수집 결과/);
  assert.doesNotMatch(html, /취약|위험/);
  assert.match(html, /<span class="local-chip">2건<\/span>/);
  assert.equal(html.match(/data-web-info-artifact="/g).length, 1);
  assert.match(html, new RegExp(`<details class="web-info-card" data-web-info-artifact="${ARTIFACT}">`));
  assert.doesNotMatch(html, /<details[^>]* open/);
  assert.match(html, /기술 2 · 경로 3 · 폼 1 · 오류 1/);
  assert.match(html, /<span class="ci-state ci-passed">HTTP 200<\/span>/);
  assert.match(html, /p-web-2[\s\S]*상세 정보 없음/);
  assert.match(html, /<span class="ci-state ci-failed">수집 실패<\/span>/);
  assert.match(html, /<span class="ci-state ci-unknown">응답 없음<\/span>/);
  assert.equal(renderWebInfoSection({ events: [{ stage: 'probe.observe' }] }), '');
  assert.equal(renderWebInfoSection(null), '');
});

test('events with missing fields fall back to neutral defaults', () => {
  assert.deepEqual(webInfoEvents({ events: [{ stage: 'web_info.collected', status: 999, artifactId: 'A'.repeat(64) }, null, 'x'] }), [{
    probeId: '', iteration: null, asset: '', sessionRole: null, ok: false, status: null, artifactId: null,
    counts: { technologies: 0, paths: 0, forms: 0, errors: 0 }, truncated: false,
  }]);
});

test('paths show same-origin rows first and keep external rows behind a closed toggle', () => {
  const html = renderWebInfoDetail(view());
  const external = html.indexOf('<details class="web-info-fold web-info-external">');
  assert.ok(external > 0);
  assert.ok(html.indexOf('https://app.test/board/view') < external);
  assert.ok(html.indexOf('https://cdn.example.net/lib.js') > external);
  assert.match(html, /같은 출처 2개를 표시하고 외부 출처 1개는 접어 둡니다/);
  const many = view();
  many.paths.items = Array.from({ length: 30 }, (_, index) => ({ url: `https://app.test/p${index}`, sources: ['link'],
    methods: ['GET'], sameOrigin: true, params: [] }));
  const long = renderWebInfoDetail(many);
  assert.match(long, /더 보기 \(5개\)/);
  assert.ok(long.indexOf('https://app.test/p24<') < long.indexOf('더 보기 (5개)'));
  assert.ok(long.indexOf('https://app.test/p25<') > long.indexOf('더 보기 (5개)'));
  assert.doesNotMatch(long, /web-info-external/);
});

test('live results show a one-line web-info count only when such events exist', () => {
  const running = { mode: 'local-lab-general', status: 'running', events: [event(), event({ probeId: 'p-web-2' })] };
  assert.match(renderGeneralLiveResults(running), /웹 정보 수집 <strong>2<\/strong>건/);
  assert.doesNotMatch(renderGeneralLiveResults({ mode: 'local-lab-general', status: 'running', events: [] }), /웹 정보 수집/);
  const done = { ...running, status: 'completed', report: { schemaVersion: 'general-assessment/1', findings: [] } };
  assert.match(renderGeneralLiveResults(done), /웹 정보 수집 <strong>2<\/strong>건/);
});
