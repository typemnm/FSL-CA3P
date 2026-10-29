/** Display metadata and formatting for current and archived telemetry. */
export const MODULES = [
  { id: 'parser', name: 'web-parser', role: '사이트 응답 분석', icon: 'scan' },
  { id: 'casper', name: 'casper-db', role: '취약점 지식 조회', icon: 'database' },
  { id: 'attack', name: 'attack-module', role: 'curl 쓰기 요청', icon: 'terminal' },
  { id: 'guardrail', name: 'guardrail', role: '실행 전 요청 검사', icon: 'shield' },
  { id: 'pentest', name: 'run-evidence', role: '통합 DB 조회·실행 기록', icon: 'archive' },
];

export function validateTarget(input) {
  if (typeof input !== 'string' || !input.trim()) {
    return { ok: false, url: '', error: '대상 URL을 입력하세요.' };
  }
  const candidate = input.trim();
  if (!/^https?:\/\//i.test(candidate)) {
    return { ok: false, url: '', error: 'http:// 또는 https://로 시작하는 URL을 입력하세요.' };
  }
  try {
    const target = new URL(candidate);
    if (!['http:', 'https:'].includes(target.protocol) || !target.hostname) {
      return { ok: false, url: '', error: '올바른 HTTP 또는 HTTPS URL을 입력하세요.' };
    }
    if (target.username || target.password) {
      return { ok: false, url: '', error: '사용자 이름이나 비밀번호가 포함된 URL은 사용할 수 없습니다.' };
    }
    return { ok: true, url: target.href, error: '' };
  } catch {
    return { ok: false, url: '', error: '올바른 URL을 입력하세요. 예: https://example.com' };
  }
}

export function formatElapsed(ms) {
  const totalSeconds = Math.floor(Math.max(0, Number.isFinite(ms) ? ms : 0) / 1000);
  const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
  const seconds = (totalSeconds % 60).toString().padStart(2, '0');
  return `${minutes}:${seconds}`;
}

