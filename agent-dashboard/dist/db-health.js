const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const date = value => value ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '기록 없음';

export function renderDbHealth(config, canEdit) {
  const health = config.health;
  if (!health) return '<p>DB 운영 상태를 읽지 못했습니다.</p>';
  const db = health.database || {}, ocr = health.ocr || {}, settings = config.settings || {};
  const jobs = health.advisories?.recentJobs || [];
  return `<section class="intake-next"><strong>보고서 파일을 올리려면 자료 관리 화면으로 이동하세요.</strong><p>이 화면은 DB 도구의 상태와 기본 설정을 확인하는 곳입니다.</p><button class="button primary" data-action="open-report-intake">보고서 올리기·내용 확인으로 이동</button></section><section class="ops-subpanel"><h3>실제 동작 상태</h3><p>확인 시각 ${escape(date(health.checkedAt))}</p><div class="ops-health-grid">${[
    ['DB 연결', db.available ? '연결 가능' : '확인 필요'], ['스키마', `${db.schemaVersion} / 지원 ${db.expectedSchemaVersion}`],
    ['보고서', `${db.reports}개 · 추출 버전 ${db.extractionVersions}개`], ['취약점 사례', `${db.cases}건 · 보관 ${db.archivedCases}건`],
    ['재현 준비 완료', `${db.reproductionReadyCases ?? 0}건`], ['재현 정보 보완 필요', `${db.incompleteReportRecords ?? 0}건`],
    ['로컬 보고서 모델', health.localLlm?.available ? health.localLlm.model : '연결되지 않음'],
    ['HWP 읽기', health.hwp?.available ? `pyhwp ${health.hwp.version}` : 'pyhwp 설치 필요'],
    ['이미지 문자 인식', ocr.available ? `Tesseract · ${settings.ocrLanguage}` : '사용 불가'],
    ['GitHub 권고', `${health.advisories?.providers?.github || 0}건`], ['NVD 권고', `${health.advisories?.providers?.nvd || 0}건`],
  ].map(([label, value]) => `<div><small>${escape(label)}</small><strong>${escape(value)}</strong></div>`).join('')}</div>${ocr.reason ? `<p role="status">OCR: ${escape(ocr.reason)}</p>` : ''}</section>
    <section class="ops-subpanel"><h3>접수·수집 기본 설정</h3><p>${escape(config.message)}</p><form id="db-settings-form" class="ops-edit-grid"><label><input name="ocrEnabled" type="checkbox" ${settings.ocrEnabled ? 'checked' : ''}> 기본으로 문서 내 이미지 읽기</label><label><input name="localLlmEnabled" type="checkbox" ${settings.localLlmEnabled ? 'checked' : ''} ${canEdit ? '' : 'disabled'}> 기본으로 로컬 LLM 문맥 추출·원문 대조</label><label>OCR 언어<select name="ocrLanguage">${[['ko', '한국어'], ['en', '영어'], ['kor+eng', '한국어 + 영어'], ['kor', '한국어 (kor)'], ['eng', '영어 (eng)']].map(([value, label]) => `<option value="${value}"${settings.ocrLanguage === value ? ' selected' : ''}>${label}</option>`).join('')}</select></label><fieldset><legend>외부 정보 제공처</legend>${['github', 'nvd'].map(value => `<label><input name="providers" type="checkbox" value="${value}" ${settings.providers?.includes(value) ? 'checked' : ''}> ${value}</label>`).join('')}</fieldset>${[['maxPages', '제공처별 최대 페이지', 1, 20], ['maxRequests', '전체 최대 요청 수', 1, 64], ['timeoutSeconds', '수집 제한 시간(초)', 10, 600]].map(([key, label, min, max]) => `<label>${label}<input name="${key}" type="number" min="${min}" max="${max}" value="${escape(settings[key])}" required></label>`).join('')}<button class="button primary" type="submit" ${canEdit ? '' : 'disabled'}>기본 설정 저장</button></form><small>revision ${escape(config.revision)} · 변경자 ${escape(health.updated_by || '기본값')}</small></section>
    <section class="ops-subpanel"><h3>최근 외부 정보 수집</h3>${jobs.map(job => `<div class="ops-row"><span><strong>${escape(job.targetId)} · ${escape(job.status === 'running' ? '완료 기록 대기' : job.status)}</strong><small>${escape(date(job.startedAt))} · 요청 ${job.requestCount}회 · 오류 ${job.errorCount}건</small></span></div>`).join('') || '<p>수집 기록이 없습니다.</p>'}</section>`;
}
