import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP } from 'node:net';

const TOKEN_KEY = randomBytes(32);
const TOKEN_LIFETIME_MS = 5 * 60_000;
const MAX_REQUESTS = 8;
const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 5000;
const MAX_DURATION_MS = 30_000;
const blockedV4 = new BlockList();
for (const [address, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blockedV4.addSubnet(address, bits, 'ipv4');
const globalV6 = new BlockList(); globalV6.addSubnet('2000::', 3, 'ipv6');
const blockedV6 = new BlockList();
for (const [address, bits] of [['2001::', 32], ['2001:db8::', 32], ['2002::', 16]]) {
  blockedV6.addSubnet(address, bits, 'ipv6');
}

const fault = (status, message, code) => Object.assign(new Error(message), { status, code });
const hostWithoutBrackets = hostname => hostname.startsWith('[') && hostname.endsWith(']')
  ? hostname.slice(1, -1) : hostname;
const hasCredentialQuery = url => [...url.searchParams.keys()].some(key =>
  /(?:password|passwd|secret|token|api[_-]?key|authorization|session|cookie|signature|signed|credential|^auth$|^key$|^jwt$|^sig$|^sp$|^se$|^sv$|^x-amz-|^x-goog-|^awsaccesskeyid$|^googleaccessid$)/iu.test(key));

export function isPublicAddress(value) {
  const address = hostWithoutBrackets(String(value));
  const family = isIP(address);
  if (family === 4) return !blockedV4.check(address, 'ipv4');
  if (family === 6) return globalV6.check(address, 'ipv6') && !blockedV6.check(address, 'ipv6');
  return false;
}

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

export function externalScopeRejectionReason(input, scope) {
  let url;
  try { url = input instanceof URL ? input : new URL(input); } catch { return 'invalid_url'; }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return 'unsupported_scheme';
  if (url.username || url.password) return 'credential_userinfo';
  if (hasCredentialQuery(url)) return 'credential_query';
  if (url.origin !== scope?.origin) return 'out_of_scope_origin';
  const prefix = scope?.pathPrefix;
  if (typeof prefix !== 'string' || !(prefix === '/' || url.pathname === prefix
    || url.pathname.startsWith(prefix.endsWith('/') ? prefix : prefix + '/'))) {
    return 'out_of_scope_path';
  }
  return null;
}

export function withinExternalScope(input, scope) {
  return externalScopeRejectionReason(input, scope) === null;
}

function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(fault(504, '외부 대상 요청 시간이 초과되었습니다.', 'EXTERNAL_TIMEOUT'));
  return new Promise((resolve, reject) => {
    const aborted = () => reject(fault(504, '외부 대상 요청 시간이 초과되었습니다.', 'EXTERNAL_TIMEOUT'));
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(
      value => { signal.removeEventListener('abort', aborted); resolve(value); },
      failure => { signal.removeEventListener('abort', aborted); reject(failure); },
    );
  });
}

export async function resolvePublicAddresses(hostname, { lookup = dnsLookup, signal } = {}) {
  const name = hostWithoutBrackets(hostname);
  const family = isIP(name);
  let rows;
  try { rows = family ? [{ address: name, family }]
    : await abortable(lookup(name, { all: true, verbatim: true }), signal); }
  catch (error) {
    if (error?.code === 'EXTERNAL_TIMEOUT') throw error;
    throw fault(422, '대상 호스트의 DNS 조회에 실패했습니다.', 'EXTERNAL_DNS_UNAVAILABLE');
  }
  if (!Array.isArray(rows) || !rows.length
    || rows.some(row => !row || row.family !== isIP(row.address) || !isPublicAddress(row.address))) {
    throw fault(403, '공개 주소로 확인된 외부 대상만 사용할 수 있습니다.', 'EXTERNAL_ADDRESS_BLOCKED');
  }
  return rows;
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

export async function requestExternalHttp(input, { scope, method = 'GET', signal, lookup = dnsLookup,
  maxBytes = MAX_RESPONSE_BYTES, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const url = input instanceof URL ? input : new URL(input);
  if (!withinExternalScope(url, scope) || !['GET', 'HEAD'].includes(method)) {
    throw fault(403, '외부 대상 요청이 허용 범위를 벗어났습니다.', 'EXTERNAL_SCOPE_BLOCKED');
  }
  const addresses = await resolvePublicAddresses(url.hostname, { lookup, signal });
  const pinned = addresses[0];
  const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    const req = transport(url, { method, agent: false, signal, timeout: timeoutMs,
      maxHeaderSize: 8192, headers: { 'user-agent': 'CA3P-external-observer/1', 'accept-encoding': 'identity' },
      lookup: (_host, _options, callback) => callback(null, pinned.address, pinned.family) }, res => {
      const connected = req.socket?.remoteAddress;
      if (!connected || connected !== pinned.address) {
        res.destroy(); finish(fault(403, 'DNS 연결 주소가 검증한 주소와 다릅니다.', 'EXTERNAL_DNS_REBIND')); return;
      }
      const chunks = []; let length = 0; let truncated = false;
      res.on('data', chunk => {
        length += chunk.length;
        if (length > maxBytes) {
          truncated = true;
          res.destroy();
          finish(null, { url: url.href, status: res.statusCode ?? 0,
            contentType: String(res.headers['content-type'] ?? ''),
            contentEncoding: String(res.headers['content-encoding'] ?? ''),
            location: String(res.headers.location ?? ''), body: Buffer.concat(chunks).toString('utf8'),
            truncated, durationMs: Date.now() - startedAt });
        } else chunks.push(chunk);
      });
      res.on('end', () => finish(null, { url: url.href, status: res.statusCode ?? 0,
        contentType: String(res.headers['content-type'] ?? ''),
        contentEncoding: String(res.headers['content-encoding'] ?? ''),
        location: String(res.headers.location ?? ''),
        body: Buffer.concat(chunks).toString('utf8'), truncated, durationMs: Date.now() - startedAt }));
      res.on('error', error => finish(error));
    });
    req.on('timeout', () => req.destroy(fault(504, '외부 대상 응답 시간이 초과되었습니다.', 'EXTERNAL_TIMEOUT')));
    req.on('error', error => finish(error));
    req.end();
  });
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
