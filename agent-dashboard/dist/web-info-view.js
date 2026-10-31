/** web-parser 수집 결과: `web_info.collected` run events → cards, `web-info-view/1` artifact → detail. Pure; no DOM. */
const VIEW_SCHEMA = 'web-info-view/1';
const ARTIFACT_ID = /^[a-f0-9]{64}$/;
const FIRST = 25;
const SECURITY_HEADERS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options',
  'X-Content-Type-Options', 'Referrer-Policy'];

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' ? value : '';
const list = value => Array.isArray(value) ? value : [];
const objects = value => list(value).filter(object);
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const httpStatus = value => Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);
const mono = value => `<span class="mono">${escape(value)}</span>`;
const chip = (label, tone = '') => `<span class="ci-state${tone ? ` ${tone}` : ''}">${escape(label)}</span>`;
const chips = values => list(values).map(text).filter(Boolean).map(value => chip(value)).join('') || '—';
const yesNo = value => value === true ? '예' : value === false ? '아니오' : '—';
const note = message => `<p class="web-info-note">${escape(message)}</p>`;
const table = (head, rows) => `<div class="comparison-table-wrap"><table class="comparison-table web-info-table"><thead><tr>${
  head.map(cell => `<th scope="col">${cell}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;

/** Epoch seconds (CDP/Playwright) as a UTC date; other values as text. */
function date(value) {
  if (typeof value === 'number' && value > 0 && value < 8.64e12) return new Date(value * 1000).toISOString().slice(0, 10);
  return text(value) || '미기록';
}

function statusChip(status) {
  if (status === null) return chip('응답 없음', 'ci-unknown');
  return chip(`HTTP ${status}`, status < 300 ? 'ci-passed' : status >= 400 ? 'ci-incomplete' : '');
}

/** The first FIRST rows stay visible; the rest sit behind a native "더 보기" disclosure. */
function limited(rows, render) {
  return render(rows.slice(0, FIRST)) + (rows.length > FIRST
    ? `<details class="web-info-more"><summary>더 보기 (${rows.length - FIRST}개)</summary>${render(rows.slice(FIRST))}</details>` : '');
}

const block = (title, size, body) => `<section class="web-info-block"><h3>${title} ${mono(size)}</h3>${body}</section>`;
const fold = (title, size, body, empty) => `<details class="web-info-fold"><summary>${title} ${mono(size)}</summary>${
  size ? body : note(empty)}</details>`;

function normalize(entry, status) {
  const counts = object(entry.counts) ? entry.counts : {};
  return {
    probeId: text(entry.probeId), iteration: count(entry.iteration), asset: text(entry.asset),
    sessionRole: text(entry.sessionRole) || null, ok: entry.ok === true, status: httpStatus(status),
    artifactId: ARTIFACT_ID.test(text(entry.artifactId)) ? entry.artifactId : null,
    counts: Object.fromEntries(['technologies', 'paths', 'forms', 'errors'].map(key => [key, count(counts[key]) ?? 0])),
    truncated: entry.truncated === true,
  };
}

function summaryChips(entry) {
  const { technologies, paths, forms, errors } = entry.counts;
  return `<span class="web-info-asset mono">${escape(entry.asset || '자산 미기록')}</span>`
    + chip(entry.sessionRole ? `세션 ${entry.sessionRole}` : '세션 없음')
    + statusChip(entry.status)
    + `<span class="web-info-counts">기술 ${technologies} · 경로 ${paths} · 폼 ${forms} · 오류 ${errors}</span>`
    + (entry.ok ? chip('수집 완료', 'ci-passed') : chip('수집 실패', 'ci-failed'))
    + (entry.truncated ? chip('일부 생략', 'ci-incomplete') : '');
}

export function webInfoEvents(item) {
  return objects(item?.events).filter(event => event.stage === 'web_info.collected').map(event => normalize(event, event.status));
}

export function renderWebInfoSection(item) {
  const events = webInfoEvents(item);
  if (!events.length) return '';
  const cards = events.map(event => {
    const summary = summaryChips(event)
      + `<small>반복 ${event.iteration ?? '?'} · 검사 ${escape(event.probeId || 'ID 미기록')}</small>`;
    return event.artifactId
      ? `<details class="web-info-card" data-web-info-artifact="${event.artifactId}"><summary>${summary}</summary><div class="web-info-detail">${note('상세 정보를 불러오는 중입니다.')}</div></details>`
      : `<div class="web-info-card"><div class="web-info-summary">${summary}${chip('상세 정보 없음', 'web-info-absent')}</div></div>`;
  }).join('');
  return `<section class="panel web-info-section" aria-labelledby="web-info-title"><div class="panel-heading"><div><div class="eyebrow">WEB-PARSER / OBSERVED</div><h2 id="web-info-title">웹 정보 · web-parser 수집 결과</h2><span class="panel-subtitle">web_info 검사마다 수집한 응답 정보입니다. 관측 기록이며 판정을 포함하지 않습니다.</span></div><span class="local-chip">${events.length}건</span></div><div class="web-info-cards">${cards}</div></section>`;
}

function head(view) {
  const target = object(view.target) ? view.target : {};
  const response = object(view.response) ? view.response : {};
  const tls = object(response.tls) ? response.tls : null;
  const truncated = object(view.truncated) ? view.truncated : {};
  const sections = list(truncated.sections).map(text).filter(Boolean);
  const errors = objects(view.errors).length;
  const requested = text(target.requestedUrl);
  const final = text(target.finalUrl);
  const loadMs = typeof response.loadTimingMs === 'number' && response.loadTimingMs >= 0 ? `${Math.round(response.loadTimingMs)} ms` : '미기록';
  const facts = [
    ['HTTP 상태', httpStatus(response.status) ?? '응답 없음'], ['응답 형식', text(response.contentType) || '미기록'],
    ['문서 제목', text(response.title) || '제목 없음'], ['로드 시간', loadMs],
    ['리다이렉트', `${objects(view.redirectChain).length}회`],
    ['TLS', tls ? `${text(tls.issuer) || '발급자 미기록'} · 만료 ${date(tls.validTo)}` : 'TLS 정보 없음'],
  ];
  const badges = (errors ? chip(`수집 오류 ${errors}건`, 'ci-incomplete') : '')
    + (truncated.source === true ? chip('원본 수집 상한으로 일부 생략', 'ci-incomplete') : '')
    + (sections.length ? chip(`표시 상한으로 일부 생략: ${sections.join(', ')}`, 'ci-incomplete') : '');
  return `<section class="web-info-head"><div class="eyebrow">WEB-PARSER / OBSERVED</div><p class="web-info-url">${
    !final || final === requested ? mono(requested || 'URL 미기록') : `요청 ${mono(requested || 'URL 미기록')} → 최종 ${mono(final)}`
  }</p><div class="ops-module-facts">${facts.map(([label, value]) => `<span><small>${label}</small><strong>${escape(value)}</strong></span>`).join('')}</div>${
    badges ? `<div class="web-info-badges">${badges}</div>` : ''}</section>`;
}

function technologies(view) {
  const rows = objects(view.technologies).map(item => {
    const evidence = objects(item.evidence);
    return `<tr><td>${escape(text(item.name) || '이름 미기록')}</td><td class="mono">${escape(text(item.version) || '—')}</td><td>${
      escape(list(item.categories).map(text).filter(Boolean).join(', ') || '—')}</td><td class="mono">${escape(count(item.confidence) ?? '—')}</td><td>${
      item.library === true ? chip('라이브러리') : '—'}</td><td>${evidence.length ? `<details class="web-info-evidence"><summary>근거 ${evidence.length}건</summary><ul>${
      evidence.map(entry => `<li>${mono(text(entry.field) || '—')}${text(entry.name) ? ` · ${mono(entry.name)}` : ''} · ${mono(text(entry.match) || '—')}</li>`).join('')
    }</ul></details>` : '—'}</td></tr>`;
  });
  return block('기술', rows.length, rows.length
    ? limited(rows, part => table(['이름', '버전', '분류', '신뢰도', '라이브러리', '근거'], part)) : note('식별된 기술이 없습니다.'));
}

function paths(view) {
  const section = object(view.paths) ? view.paths : {};
  const items = objects(section.items);
  const total = count(section.total) ?? items.length;
  const same = items.filter(item => item.sameOrigin === true);
  const external = items.filter(item => item.sameOrigin !== true);
  const render = part => table(['URL', '발견 위치', '메서드', '파라미터', '비고'], part);
  const row = item => `<tr><td class="mono">${escape(text(item.url) || '—')}</td><td>${chips(item.sources)}</td><td class="mono">${
    escape(list(item.methods).map(text).filter(Boolean).join(' ') || '—')}</td><td class="mono">${
    escape(list(item.params).map(text).filter(Boolean).join(', ') || '—')}</td><td>${item.wildcard === true ? chip('패턴') : '—'}</td></tr>`;
  return block('경로', total, note(`전체 ${total}개 중 ${items.length}개를 받았습니다. 같은 출처 ${same.length}개를 표시하고 외부 출처 ${external.length}개는 접어 둡니다.`)
    + (same.length ? limited(same.map(row), render) : note('같은 출처 경로가 없습니다.'))
    + (external.length ? `<details class="web-info-fold web-info-external"><summary>외부 출처 경로 ${mono(external.length)}</summary>${limited(external.map(row), render)}</details>` : ''));
}

function forms(view) {
  const section = object(view.forms) ? view.forms : {};
  const items = objects(section.items);
  const total = count(section.total) ?? items.length;
  const rows = items.map(form => {
    const fields = objects(form.fields);
    return `<li>${chip(text(form.method).toUpperCase() || 'GET')} ${mono(text(form.action) || '—')}${fields.length
      ? table(['이름', '형식'], fields.map(field => `<tr><td class="mono">${escape(text(field.name) || '—')}</td><td class="mono">${escape(text(field.type) || '—')}</td></tr>`))
      : note('입력 필드가 없습니다.')}</li>`;
  });
  return block('폼', total, (total > items.length ? note(`전체 ${total}개 중 ${items.length}개를 받았습니다.`) : '')
    + (rows.length ? limited(rows, part => `<ul class="web-info-forms">${part.join('')}</ul>`) : note('수집된 폼이 없습니다.')));
}

function folds(view) {
  const headers = objects(view.headers);
  const names = new Set(headers.map(header => text(header.name).toLowerCase()));
  const presence = `<p class="web-info-security">보안 관련 헤더 (유무만 표시) ${SECURITY_HEADERS.map(name => `<span>${mono(name)} ${
    names.has(name.toLowerCase()) ? chip('있음') : chip('없음', 'web-info-absent')}</span>`).join('')}</p>`;
  const headerRows = headers.map(header => `<tr><td class="mono">${escape(text(header.name) || '—')}</td><td class="mono">${
    typeof header.value === 'string' ? escape(header.value) : '<em class="muted">값 숨김</em>'}</td></tr>`);
  const cookies = objects(view.cookies).map(cookie => `<tr><td class="mono">${escape(text(cookie.name) || '—')}</td><td class="mono">${
    escape(text(cookie.domain) || '—')}</td><td class="mono">${escape(text(cookie.path) || '—')}</td><td class="mono">${
    cookie.expires === -1 ? '세션' : escape(date(cookie.expires))}</td><td>${yesNo(cookie.httpOnly)}</td><td>${yesNo(cookie.secure)}</td><td>${
    escape(text(cookie.sameSite) || '—')}</td></tr>`);
  const hops = objects(view.redirectChain).map(hop => `<li>${chip(`${httpStatus(hop.status) ?? '—'} · ${text(hop.kind) || 'http'}`)} ${
    mono(text(hop.from) || '—')} → ${mono(text(hop.to) || '—')}</li>`);
  const hosts = objects(view.hosts).map(host => `<tr><td class="mono">${escape(text(host.host) || '—')}</td><td>${yesNo(host.sameOrigin)}</td><td class="mono">${
    escape(count(host.requests) ?? '—')}</td><td>${chips(host.kinds)}</td></tr>`);
  const frames = objects(view.frames).map(frame => `<li>${chip(text(frame.tag) || 'iframe')} ${mono(text(frame.src) || '—')} · sandbox ${
    typeof frame.sandbox === 'string' ? mono(frame.sandbox || '""') : '없음'}</li>`);
  const errors = objects(view.errors).map(error => `<li>${chip(text(error.stage) || 'unknown', 'ci-incomplete')} ${mono(text(error.message) || '—')}</li>`);
  return fold('응답 헤더', headerRows.length, presence + limited(headerRows, part => table(['이름', '값'], part)), '기록된 응답 헤더가 없습니다.')
    + fold('쿠키', cookies.length, limited(cookies, part => table(['이름', '도메인', '경로', '만료', 'HttpOnly', 'Secure', 'SameSite'], part))
      + note('쿠키 값은 표시하지 않습니다.'), '기록된 쿠키가 없습니다.')
    + fold('리다이렉트 경로', hops.length, `<ol class="web-info-list">${hops.join('')}</ol>`, '리다이렉트 없이 응답을 받았습니다.')
    + fold('호스트별 리소스', hosts.length, limited(hosts, part => table(['호스트', '같은 출처', '요청 수', '종류'], part)), '기록된 리소스 호스트가 없습니다.')
    + fold('프레임', frames.length, `<ul class="web-info-list">${frames.join('')}</ul>`, '기록된 프레임이 없습니다.')
    + fold('수집 오류', errors.length, `<ul class="web-info-list">${errors.join('')}</ul>`, '기록된 수집 오류가 없습니다.');
}

export function renderWebInfoDetail(view) {
  if (!object(view) || view.schemaVersion !== VIEW_SCHEMA) {
    const version = object(view) ? text(view.schemaVersion) : '';
    return note(`지원하지 않는 웹 정보 형식입니다${version ? ` (${version})` : ''}. 대시보드 버전을 확인하세요.`);
  }
  return head(view) + technologies(view) + paths(view) + forms(view) + folds(view);
}

/** Resolve an artifact id to detail markup: one request per id; failures are retried on the next open. */
export function createWebInfoLoader(api, prepare = view => view) {
  const views = new Map();
  return async id => {
    if (!ARTIFACT_ID.test(text(id))) return note('상세 정보 없음');
    if (!views.has(id)) views.set(id, api(`/api/artifacts/${id}`).then(view => renderWebInfoDetail(prepare(view))));
    try { return await views.get(id); }
    catch (error) {
      views.delete(id);
      const message = error?.status === 404 ? '저장된 상세 정보를 찾을 수 없습니다.'
        : error?.status === 409 ? '저장된 상세 정보가 무결성 또는 민감 정보 검사를 통과하지 못해 표시하지 않습니다.'
          : '상세 정보를 불러오지 못했습니다. 연결을 확인한 뒤 다시 펼치세요.';
      return `<p class="web-info-note web-info-error" role="alert">${escape(message)}</p>`;
    }
  };
}

/* web-parser module page: `/api/modules/web-parser/logs` entries (newest first). */
const logTime = value => Number.isFinite(Date.parse(value))
  ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '시각 미기록';

function collectionLogs(logs) {
  return objects(logs).filter(log => log.stage === 'web_info.collected')
    .map(log => ({ ...normalize(log, log.httpStatus), id: text(log.id), runId: text(log.runId),
      createdAt: log.createdAt, detail: text(log.detail) }))
    .sort((a, b) => (Date.parse(b.createdAt) || 0) - (Date.parse(a.createdAt) || 0));
}

function logRow(entry) {
  // Run ids share a mode prefix (general-, external-general-); the UUID tail tells them apart.
  const run = entry.runId.length > 12 ? `…${entry.runId.slice(-8)}` : entry.runId || '실행 ID 미기록';
  const meta = [`검사 ${entry.probeId || 'ID 미기록'}`, `반복 ${entry.iteration ?? '?'}`, entry.detail].filter(Boolean).join(' · ');
  return `<details class="web-parser-log-row" data-log-id="${escape(entry.id)}"${entry.artifactId ? ` data-web-info-artifact="${entry.artifactId}"` : ''}><summary><span class="web-parser-log-time mono">${
    escape(logTime(entry.createdAt))}</span><span class="web-parser-log-run mono" title="${escape(entry.runId)}">${escape(run)}</span>${summaryChips(entry)}${
    entry.artifactId ? '' : chip('상세 정보 없음', 'web-info-absent')}</summary><div class="web-parser-log-body">${note(meta)}${
    entry.artifactId ? `<div class="web-info-detail">${note('상세 정보를 불러오는 중입니다.')}</div>` : note('상세 정보 없음')}</div></details>`;
}

/** Rows plus the folded legacy list; re-rendered alone when the search or the failed-only toggle changes. */
export function renderWebParserLogBody(logs, { query = '', failedOnly = false } = {}) {
  const needle = text(query).trim().toLowerCase();
  const matches = values => !needle || values.filter(value => value !== null && value !== undefined && value !== '')
    .join(' ').toLowerCase().includes(needle);
  const rows = collectionLogs(logs).filter(entry => (!failedOnly || !entry.ok) && matches([entry.asset, entry.runId,
    entry.probeId, entry.status === null ? '응답 없음' : `HTTP ${entry.status}`, entry.ok ? '수집 완료' : '수집 실패',
    entry.sessionRole, entry.detail]));
  const others = objects(logs).filter(log => log.stage !== 'web_info.collected')
    .filter(log => matches([text(log.title), text(log.stage), text(log.detail), text(log.runId), text(log.status)]));
  return (rows.length ? `<div class="web-parser-log-rows">${rows.map(logRow).join('')}</div>`
    : note(needle || failedOnly ? '조건에 맞는 수집 기록이 없습니다.' : '수집 기록이 없습니다.'))
    + (others.length ? `<details class="web-info-fold web-parser-other-logs"><summary>기타 로그 ${mono(others.length)}</summary><ul class="web-info-list">${
      others.map(log => `<li>${mono(logTime(log.createdAt))} ${escape(text(log.title) || '제목 없음')} ${chip(text(log.stage) || '단계 미기록')}${
        text(log.detail) ? ` · ${escape(log.detail)}` : ''}</li>`).join('')}</ul></details>` : '');
}

export function renderWebParserLog(logs, { query = '', failedOnly = false, total = null } = {}) {
  const entries = collectionLogs(logs);
  const succeeded = entries.filter(entry => entry.ok).length;
  const loaded = objects(logs).length;
  const facts = [
    ['수집 횟수', entries.length], ['성공 / 실패', `${succeeded} / ${entries.length - succeeded}`],
    ['수집 페이지', new Set(entries.map(entry => entry.asset).filter(Boolean)).size],
    ['포함된 실행', new Set(entries.map(entry => entry.runId).filter(Boolean)).size],
    ['마지막 수집', entries.length ? logTime(entries[0].createdAt) : '—'],
  ];
  return `<section class="panel web-parser-log" aria-labelledby="web-parser-log-title"><div class="panel-heading"><div><div class="eyebrow">WEB-PARSER / COLLECTION LOG</div><h2 id="web-parser-log-title">웹 정보 수집 로그</h2><span class="panel-subtitle">web_info 검사마다 web-parser가 수집한 응답 기록입니다. 관측 기록이며 판정을 포함하지 않습니다. 행을 펼치면 수집 상세를 불러옵니다.</span></div><span class="local-chip">${entries.length}건</span></div><div class="web-parser-log-content"><div class="ops-module-facts web-parser-log-strip">${
    facts.map(([label, value]) => `<span><small>${label}</small><strong>${escape(value)}</strong></span>`).join('')}</div><div class="web-parser-log-toolbar"><label>검색<input id="web-parser-log-search" type="search" value="${
    escape(query)}" placeholder="자산, 실행 ID, 검사 ID, 상태"></label><label class="web-parser-log-failed"><input id="web-parser-failed-only" type="checkbox"${failedOnly ? ' checked' : ''}> 실패만 보기</label></div>${
    count(total) !== null && total > loaded ? note(`최근 ${loaded}건만 표시합니다 (전체 로그 ${total}건). 요약도 불러온 기록 기준입니다.`) : ''
  }<div id="web-parser-log-body">${renderWebParserLogBody(logs, { query, failedOnly })}</div></div></section>`;
}
