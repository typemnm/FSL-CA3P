/** Public external target scope and HTTP transport shared by inspection and report capture. */
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP } from 'node:net';

export const MAX_RESPONSE_BYTES = 64 * 1024;
export const REQUEST_TIMEOUT_MS = 5000;
const VISIBLE_RESPONSE_HEADERS = Object.freeze([
  'content-security-policy', 'x-frame-options', 'x-content-type-options',
  'strict-transport-security', 'access-control-allow-origin',
  'access-control-allow-credentials', 'access-control-allow-methods',
]);

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
export const hasCredentialQuery = url => [...url.searchParams.keys()].some(key =>
  /(?:password|passwd|secret|token|api[_-]?key|authorization|session|cookie|signature|signed|credential|^auth$|^key$|^jwt$|^sig$|^sp$|^se$|^sv$|^x-amz-|^x-goog-|^awsaccesskeyid$|^googleaccessid$)/iu.test(key));

export function isPublicAddress(value) {
  const address = hostWithoutBrackets(String(value));
  const family = isIP(address);
  if (family === 4) return !blockedV4.check(address, 'ipv4');
  if (family === 6) return globalV6.check(address, 'ipv6') && !blockedV6.check(address, 'ipv6');
  return false;
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

export function abortable(promise, signal) {
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

export function pinnedAddressLookup(pinned) {
  return (_hostname, options, callback) => options?.all
    ? callback(null, [pinned]) : callback(null, pinned.address, pinned.family);
}

export async function requestExternalHttp(input, { scope, method = 'GET', signal, lookup = dnsLookup,
  maxBytes = MAX_RESPONSE_BYTES, timeoutMs = REQUEST_TIMEOUT_MS, responseType = 'text' } = {}) {
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
      lookup: pinnedAddressLookup(pinned) }, res => {
      const connected = req.socket?.remoteAddress;
      if (!connected || connected !== pinned.address) {
        res.destroy(); finish(fault(403, 'DNS 연결 주소가 검증한 주소와 다릅니다.', 'EXTERNAL_DNS_REBIND')); return;
      }
      const visibleHeaders = Object.fromEntries(VISIBLE_RESPONSE_HEADERS.flatMap(name => {
        const value = res.headers[name];
        return typeof value === 'string' ? [[name, value.slice(0, 256)]] : [];
      }));
      const chunks = []; let length = 0; let truncated = false;
      res.on('data', chunk => {
        length += chunk.length;
        if (length > maxBytes) {
          truncated = true;
          res.destroy();
          finish(null, { url: url.href, status: res.statusCode ?? 0,
            contentType: String(res.headers['content-type'] ?? ''),
            contentEncoding: String(res.headers['content-encoding'] ?? ''),
            headers: visibleHeaders,
            location: String(res.headers.location ?? ''), body: responseType === 'buffer' ? Buffer.concat(chunks) : Buffer.concat(chunks).toString('utf8'),
            truncated, durationMs: Date.now() - startedAt });
        } else chunks.push(chunk);
      });
      res.on('end', () => finish(null, { url: url.href, status: res.statusCode ?? 0,
        contentType: String(res.headers['content-type'] ?? ''),
        contentEncoding: String(res.headers['content-encoding'] ?? ''),
        headers: visibleHeaders,
        location: String(res.headers.location ?? ''),
        body: responseType === 'buffer' ? Buffer.concat(chunks) : Buffer.concat(chunks).toString('utf8'), truncated, durationMs: Date.now() - startedAt }));
      res.on('error', error => finish(error));
    });
    req.on('timeout', () => req.destroy(fault(504, '외부 대상 응답 시간이 초과되었습니다.', 'EXTERNAL_TIMEOUT')));
    req.on('error', error => finish(error));
    req.end();
  });
}
