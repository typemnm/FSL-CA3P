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

/** A raw TargetInfo (web-parser-1) exactly as collect() returns it, secrets included. */
function info() {
  return {
    schemaVersion: 'web-parser-1',
    target: { requestedUrl: 'http://app.test/board?page=2', finalUrl: 'https://app.test/board?page=2', origin: 'https://app.test' },
    navigation: { status: 200, contentType: 'text/html; charset=utf-8', loadTimingMs: 411.6,
      redirectChain: [{ from: 'http://app.test/board?page=2', to: 'https://app.test/board?page=2', status: 301, kind: 'http',
        headers: [{ name: 'Location', value: 'https://app.test/board?page=2' }, { name: 'Set-Cookie', value: 'hop=hop-cookie-value' }] },
      { from: 'https://app.test/board?page=2', to: 'https://app.test/board?page=2#top', status: null, headers: null, kind: 'client' }],
      securityDetails: { protocol: 'TLS 1.3', issuer: 'Test CA', subjectName: 'app.test', validFrom: 1767225600, validTo: 1798761600 } },
    headers: [{ name: 'Content-Type', value: 'text/html' }, { name: 'X-Frame-Options', value: 'DENY' },
      { name: 'Set-Cookie', value: 'SESSIONID=set-cookie-secret; HttpOnly' }, { name: 'Authorization', value: 'Bearer auth-header-token' }],
    cookies: [{ name: 'SESSIONID', value: 'cookie-value-123', domain: 'app.test', path: '/', expires: -1, httpOnly: true, secure: true,
      sameSite: 'Lax' }, { name: 'pref', value: '', domain: 'app.test', path: '/', expires: 1798761600, httpOnly: false, secure: false,
      sameSite: 'None', partitionKey: 'https://app.test' }],
    meta: [{ name: 'generator', content: 'TestCMS 1.0' }],
    html: '<html><head><title>게시판 &amp; 목록 &#8212; Q&amp;A</title></head><body><p>html-body-text</p><script>alert(1)</script></body></html>',
    body: null,
    technologies: [
      { name: 'jQuery', version: '3.6.0', categories: ['JavaScript libraries'], confidence: 100,
        evidence: [{ field: 'scriptSrc', match: 'jquery-3.6.0.min.js' }, { field: 'js', key: 'jQuery.fn.jquery', match: '3.6.0' }] },
      { name: 'nginx', version: null, categories: ['Web servers'], confidence: 100,
        evidence: [{ field: 'headers', key: 'server', match: 'nginx' }] },
    ],
    libraries: [{ name: 'jQuery', version: '3.6.0', source: 'fingerprint', evidence: [] },
      { name: 'OnlyInLibraries', version: '1.0', source: 'fingerprint', evidence: [] }],
    structure: {
      forms: [{ selector: 'form#login', action: 'https://app.test/login', raw: '/login', method: 'post',
        fields: [{ name: 'username', type: 'text' }, { name: 'password', type: 'password' }] }],
      links: [{ href: 'https://app.test/board/view?id=1', raw: '/board/view?id=1', text: '첫 글' }],
      scripts: [{ src: 'https://cdn.example.net/jquery.min.js', type: null }, { inline: 'var token = "inline-script-token";', type: null }],
      iframes: [{ src: 'https://app.test/embed', sandbox: null }],
      inputs: [{ selector: 'input[name=q]', tag: 'input', name: 'q', type: 'search', form: null }],
      linkTags: [], areas: [], formActions: [], frames: [], embeds: [], objects: [], metaRefresh: [],
      media: [{ tag: 'img', src: 'https://app.test/logo.png', srcset: [{ url: 'https://app.test/logo@2x.png' }] }],
    },
    resources: [{ kind: 'document', method: 'GET', url: 'https://app.test/board?page=2', status: 200 },
      { kind: 'script', method: 'GET', url: 'https://cdn.example.net/jquery.min.js', status: 200 }],
    paths: [
      { url: 'https://app.test/board/view?id=1', sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['id'] },
      { url: 'https://app.test/private/*.php$', sources: ['robots:disallow'], methods: [], sameOrigin: true, params: [], wildcard: true },
      { url: 'https://cdn.example.net/jquery.min.js', sources: ['script', 'request:script'], methods: ['GET'], sameOrigin: false, params: [] },
    ],
    errors: [{ stage: 'load', message: 'https://app.test/board?page=2: timeout' }],
    truncated: true,
  };
}

/** Replace every string (except the schema/stage discriminators) with a markup payload. */
function poison(value, payload) {
  if (Array.isArray(value)) return value.map(entry => poison(entry, payload));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .map(([key, entry]) => [key, key === 'schemaVersion' || key === 'stage' ? entry : poison(entry, payload)]));
  return typeof value === 'string' ? payload : value;
}

test('a raw TargetInfo renders every collected section with values unmasked', () => {
  const html = renderWebInfoDetail(info(), { artifactId: ARTIFACT });
  for (const heading of ['기술', '경로', '폼']) assert.match(html, new RegExp(`<h3>${heading} <span class="mono">`), heading);
  for (const fold of ['응답 헤더', '쿠키', '리다이렉트 경로', '리소스', 'meta', '구조 · links', '구조 · scripts', '구조 · iframes',
    '구조 · inputs', '구조 · linkTags', '구조 · areas', '구조 · formActions', '구조 · frames', '구조 · embeds', '구조 · objects',
    '구조 · metaRefresh', '구조 · media', 'HTML 원문 · 문자 수', '본문 원문 (body) · 문자 수', '수집 오류']) {
    assert.match(html, new RegExp(`<summary>${fold.replace(/[()]/g, '\\$&')} <span class="mono">`), fold);
  }
  // Secrets stay visible (escaped), exactly as collected.
  assert.match(html, /cookie-value-123/);
  assert.match(html, /SESSIONID=set-cookie-secret; HttpOnly/);
  assert.match(html, /Bearer auth-header-token/);
  assert.match(html, /hop=hop-cookie-value/);
  assert.match(html, /inline-script-token/);
  assert.match(html, /jQuery\.fn\.jquery<\/span> · <span class="mono">3\.6\.0/);
  assert.match(html, /<span class="mono">headers<\/span> · <span class="mono">server<\/span> · <span class="mono">nginx/);
  assert.match(html, /&lt;p&gt;html-body-text&lt;\/p&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script|<p>html-body-text/);
  // Summary: title from html with entities decoded, every securityDetails field, truncated.
  assert.match(html, /<small>문서 제목<\/small><strong>게시판 &amp; 목록 — Q&amp;A<\/strong>/);
  for (const key of ['protocol', 'issuer', 'subjectName', 'validFrom', 'validTo']) assert.match(html, new RegExp(`<small>TLS ${key}</small>`));
  assert.match(html, /<small>TLS validTo<\/small><strong>2027-01-01 \(1798761600\)/);
  assert.match(html, /<small>로드 시간<\/small><strong>411\.6 ms/);
  assert.match(html, /<small>truncated<\/small><strong>true/);
  assert.match(html, /수집 상한으로 일부 생략/);
  assert.match(html, /수집 오류 1건/);
  // Every cookie field, library markers (including a library missing from technologies), hop headers, hosts.
  assert.match(html, /<th scope="col">partitionKey<\/th>/);
  assert.match(html, /<span class="muted">""<\/span>/);
  assert.match(html, /OnlyInLibraries[\s\S]*?라이브러리/);
  assert.match(html, /이 홉의 응답 헤더 <span class="mono">2/);
  assert.match(html, /client[\s\S]*?헤더 없음 \(null\)/);
  assert.match(html, /<td class="mono">cdn\.example\.net<\/td><td>아니오<\/td><td class="mono">1<\/td>/);
  assert.match(html, /X-Frame-Options<\/span> <span class="ci-state">있음/);
  assert.match(html, /Content-Security-Policy<\/span> <span class="ci-state web-info-absent">없음/);
  assert.match(html, /logo@2x\.png/);
  assert.match(html, new RegExp(`<a class="button secondary web-info-download" href="/api/artifacts/${ARTIFACT}" download="web-info-cccccccccccc.json">원본 JSON 내려받기</a>`));
  assert.doesNotMatch(html, /\[REDACTED\]|값 숨김|취약|위험/);
});

test('every string field of the TargetInfo and the event is escaped', () => {
  const payload = '<script>alert(1)</script>"\'';
  const html = renderWebInfoDetail(poison(info(), payload));
  assert.doesNotMatch(html, /<script/i);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&#39;/);
  const keys = info();
  keys.structure['<img src=x onerror=alert(1)>'] = [{ '<b>key</b>': 'value' }];
  keys['<i>extra</i>'] = '<svg onload=alert(1)>';
  const extra = renderWebInfoDetail(keys);
  assert.doesNotMatch(extra, /<img|<b>|<i>|<svg/);
  assert.match(extra, /구조 · &lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(extra, /기타 필드/);
  const section = renderWebInfoSection({ events: [poison(event(), payload)] });
  assert.doesNotMatch(section, /<script/i);
  assert.match(section, /&lt;script&gt;/);
  // A non-hex artifact id never reaches the fetch hook.
  assert.doesNotMatch(section, /data-web-info-artifact/);
});

test('전체 표시 holds the rest of a long body so nothing is dropped', () => {
  const long = info();
  long.body = `${'a'.repeat(20000)}<script>tail-marker</script>${'b'.repeat(50)}`;
  const html = renderWebInfoDetail(long);
  const summary = html.indexOf('<summary>전체 표시 (나머지 78자)</summary>');
  assert.ok(summary > 0);
  assert.ok(html.indexOf('&lt;script&gt;tail-marker&lt;/script&gt;') > summary);
  const shown = html.slice(0, summary).match(/<pre class="web-info-raw">(a+)<\/pre>/u);
  assert.equal(shown[1].length, 20000);
  const longCell = info();
  longCell.headers.push({ name: 'Content-Security-Policy', value: `default-src 'self'; ${'x'.repeat(600)}` });
  assert.match(renderWebInfoDetail(longCell), /<summary>전체 표시 \(나머지 \d+자\)<\/summary>/);
});

test('an unknown schemaVersion renders a clear note instead of guessing', () => {
  assert.match(renderWebInfoDetail({ ...info(), schemaVersion: 'web-info-view/1' }), /지원하지 않는 웹 정보 형식입니다 \(web-info-view\/1\)/);
  assert.match(renderWebInfoDetail(null), /지원하지 않는 웹 정보 형식입니다\./);
  assert.match(renderWebInfoDetail({ ...info(), schemaVersion: '<b>x</b>' }), /\(&lt;b&gt;x&lt;\/b&gt;\)/);
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
  const html = renderWebInfoDetail(info());
  const external = html.indexOf('<details class="web-info-fold web-info-external">');
  assert.ok(external > 0);
  const pathsBlock = html.slice(html.indexOf('<h3>경로'), html.indexOf('<h3>폼'));
  assert.ok(pathsBlock.indexOf('https://app.test/board/view?id=1') < pathsBlock.indexOf('web-info-external'));
  assert.ok(pathsBlock.indexOf('https://cdn.example.net/jquery.min.js') > pathsBlock.indexOf('web-info-external'));
  assert.match(html, /경로 3개 중 같은 출처 2개를 표시하고 외부 출처 1개는 접어 둡니다/);
  const many = info();
  many.paths = Array.from({ length: 30 }, (_, index) => ({ url: `https://app.test/p${index}`, sources: ['link'],
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
