import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS, hasCredentialQuery, abortable,
  withinExternalScope, resolvePublicAddresses, requestExternalHttp } from '../../packages/external-http/index.mjs';
export { isPublicAddress, externalScopeRejectionReason, withinExternalScope,
  resolvePublicAddresses, pinnedAddressLookup, requestExternalHttp } from '../../packages/external-http/index.mjs';

const TOKEN_KEY = randomBytes(32);
const TOKEN_LIFETIME_MS = 5 * 60_000;
const MAX_REQUESTS = 8;
const MAX_DURATION_MS = 30_000;
const fault = (status, message, code) => Object.assign(new Error(message), { status, code });

export function normalizeExternalTarget(input) {
  const body = typeof input === 'string' ? { target: input } : input;
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw fault(400, '외부 대상 URL을 입력하세요.', 'INVALID_EXTERNAL_TARGET');
  const raw = body.target ?? body.url;
  if (typeof raw !== 'string' || !raw.trim() || raw.length > 2048) {
    throw fault(400, '외부 대상 URL을 입력하세요.', 'INVALID_EXTERNAL_TARGET');
  }
  let url;
  try { url = new URL(raw.trim()); }
  catch { throw fault(400, '올바른 HTTP(S) URL을 입력하세요.', 'INVALID_EXTERNAL_TARGET'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw fault(400, '자격 증명이 없는 HTTP(S) URL만 사용할 수 있습니다.', 'INVALID_EXTERNAL_TARGET');
  }
  if (hasCredentialQuery(url)) throw fault(400, 'URL에 인증 정보를 포함하지 마세요.', 'EXTERNAL_URL_CREDENTIALS');
  url.hash = '';
  const suppliedScope = body.scope ?? {};
  if (!suppliedScope || typeof suppliedScope !== 'object' || Array.isArray(suppliedScope)
    || Object.keys(suppliedScope).some(key => key !== 'pathPrefix')) {
    throw fault(400, '지원하지 않는 외부 대상 범위입니다.', 'INVALID_EXTERNAL_SCOPE');
  }
  const pathPrefix = suppliedScope.pathPrefix ?? '/';
  let canonicalPath = false;
  try {
    const parsed = new URL(pathPrefix, url.origin);
    canonicalPath = parsed.origin === url.origin && parsed.pathname === pathPrefix
      && !parsed.search && !parsed.hash;
  } catch { /* Invalid paths are rejected below. */ }
  if (typeof pathPrefix !== 'string' || !pathPrefix.startsWith('/') || pathPrefix.length > 1024
    || pathPrefix.includes('?') || pathPrefix.includes('#') || pathPrefix.includes('\\')
    || !canonicalPath) {
    throw fault(400, '허용 경로는 정규화된 절대 경로여야 합니다.', 'INVALID_EXTERNAL_SCOPE');
  }
  const scope = { origin: url.origin, pathPrefix, methods: ['GET', 'HEAD'], maxRequests: MAX_REQUESTS,
    maxResponseBytes: MAX_RESPONSE_BYTES, requestTimeoutMs: REQUEST_TIMEOUT_MS,
    maxDurationMs: MAX_DURATION_MS };
  if (!withinExternalScope(url, scope)) throw fault(400, '시작 URL이 허용 경로 밖에 있습니다.', 'EXTERNAL_SCOPE_MISMATCH');
  return { normalizedUrl: url.href, scope };
}

function issueToken(normalizedUrl, scope) {
  const payload = Buffer.from(JSON.stringify({ normalizedUrl, scope, expiresAt: Date.now() + TOKEN_LIFETIME_MS })).toString('base64url');
  const signature = createHmac('sha256', TOKEN_KEY).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

export function verifyExternalPreflightToken(token, normalizedUrl, scope) {
  if (typeof token !== 'string' || token.length > 4096) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const expected = createHmac('sha256', TOKEN_KEY).update(parts[0]).digest();
  let given; let payload;
  try { given = Buffer.from(parts[1], 'base64url'); payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); }
  catch { return false; }
  return given.length === expected.length && timingSafeEqual(given, expected)
    && Number.isFinite(payload.expiresAt) && payload.expiresAt > Date.now()
    && payload.normalizedUrl === normalizedUrl && JSON.stringify(payload.scope) === JSON.stringify(scope);
}

export async function preflightExternalTarget(body, { lookup = dnsLookup, request = requestExternalHttp } = {}) {
  const { normalizedUrl, scope } = normalizeExternalTarget(body);
  const deadline = AbortSignal.timeout(12_000);
  await resolvePublicAddresses(new URL(normalizedUrl).hostname, { lookup, signal: deadline });
  let response;
  try { response = await abortable(request(normalizedUrl, { scope, method: 'HEAD', lookup, signal: deadline }), deadline); }
  catch (error) {
    return { ready: false, allowed: false, normalizedUrl, scope,
      message: `대상 연결을 확인하지 못했습니다: ${deadline.aborted ? 'EXTERNAL_TIMEOUT' : error.code ?? 'CONNECTION_FAILED'}`, token: null };
  }
  if ([405, 501].includes(response.status)) {
    try { response = await abortable(request(normalizedUrl, { scope, method: 'GET', lookup, signal: deadline }), deadline); }
    catch (error) { return { ready: false, allowed: false, normalizedUrl, scope,
      message: `대상 연결을 확인하지 못했습니다: ${deadline.aborted ? 'EXTERNAL_TIMEOUT' : error.code ?? 'CONNECTION_FAILED'}`, token: null }; }
  }
  const ready = response.status >= 200 && response.status < 300;
  return { ready, allowed: ready, normalizedUrl, scope, httpStatus: response.status,
    message: ready ? '외부 대상의 공개 페이지에 연결할 수 있습니다.'
      : '대상 공개 페이지에 접근할 수 없습니다. 응답 상태와 최종 URL을 확인하세요.',
    token: ready ? issueToken(normalizedUrl, scope) : null };
}
