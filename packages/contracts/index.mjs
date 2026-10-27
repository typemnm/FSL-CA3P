import { createHash } from 'node:crypto';

export const CONTRACT_VERSIONS = Object.freeze({ envelope: '1.0', parserReport: '3.4',
  catalog: 'casper-attack-catalog-1', caseStoreMigration: 7, runManifest: '1.0', runEvent: '1.0' });
export const RUN_MODES = Object.freeze(['core-fixture', 'local-lab-rule', 'local-lab-deepseek']);
export const TERMINAL_STATUSES = Object.freeze(['completed', 'failed', 'cancelled', 'interrupted']);
export const ACTIVE_STATUSES = Object.freeze(['queued', 'preparing', 'running', 'stopping']);
export const digest = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value)
  ? value : JSON.stringify(value)).digest('hex');
export function assertIdentifier(value, name = 'identifier') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value)) {
    throw Object.assign(new TypeError(`${name} must be a safe identifier of at most 128 characters.`), { status: 400 });
  }
  return value;
}

// Apply at the persistence boundary as well as the HTTP boundary. Token counts
// and boolean policy fields are telemetry, so do not redact by substring.
const SECRET_KEY = /^(?:authorization|proxyauthorization|cookie|setcookie|(?:x)?apikey|password|passwd|secret|accesstoken|refreshtoken|sessiontoken|clientsecret|bearertoken|jwt)$/iu;
const isSecretKey = key => SECRET_KEY.test(key.toLowerCase().replace(/[^a-z0-9]/gu, ''))
  || /(?:apikey|cookiesecret|clientsecret|accesstoken|refreshtoken|sessiontoken)$/u.test(key.toLowerCase().replace(/[^a-z0-9]/gu, ''));
function redactString(value) {
  const replaceUrl = candidate => {
    try {
      const url = new URL(candidate);
      let changed = false;
      if (url.username || url.password) { url.username = ''; url.password = ''; changed = true; }
      for (const key of [...url.searchParams.keys()]) if (isSecretKey(key)) { url.searchParams.set(key, '[REDACTED]'); changed = true; }
      return changed ? url.href : candidate;
    } catch { return candidate; }
  };
  const urlsMasked = /^https?:\/\//iu.test(value)
    ? replaceUrl(value)
    : value.replace(/https?:\/\/[^\s"'<>]+/giu, replaceUrl);
  return urlsMasked
    .replace(/\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|session-token|access-token)(\s*:\s*)[^\r\n]*?(?=(?:\\n|[\r\n]|$))/giu,
      (_match, label, separator) => `${label}${separator}[REDACTED]`)
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+/giu, 'Bearer [REDACTED]');
}
export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .map(([key, entry]) => [key, isSecretKey(key) ? '[REDACTED]' : redact(entry)]));
  if (typeof value === 'string') return redactString(value);
  return value;
}

export function emptyRun() {
  return { id: null, target: 'https://demo.ca3p.local', status: 'idle', mode: 'core-fixture',
    simulated: true, targetContacted: false, startedAt: new Date().toISOString(),
    elapsedMs: 0, step: 0, totalSteps: 25, iterations: 1, events: [], snapshots: {}, reviewItems: [] };
}

export function validateDisplayTarget(input) {
  if (typeof input !== 'string' || !input.trim()) return { ok: false, url: '', error: '대상 URL을 입력하세요.' };
  const candidate = input.trim();
  if (!/^https?:\/\//iu.test(candidate)) return { ok: false, url: '', error: 'http:// 또는 https://로 시작하는 URL을 입력하세요.' };
  try {
    const target = new URL(candidate);
    if (!['http:', 'https:'].includes(target.protocol) || !target.hostname || target.username || target.password) throw new Error();
    return { ok: true, url: target.href, error: '' };
  } catch { return { ok: false, url: '', error: '올바른 HTTP 또는 HTTPS URL을 입력하세요.' }; }
}
