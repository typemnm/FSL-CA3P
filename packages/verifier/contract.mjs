import { createHash } from 'node:crypto';

export const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
export const LIMITS = { summaryBytes: 2048, evidenceBytes: 4096, maxEvidence: 4, bodyTextBytes: 65536, detailBytes: 256 };
export const STATUSES = ['confirmed', 'not_reproduced', 'inconclusive'];

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const SECRET_HEADERS = new Set(['cookie', 'set-cookie', 'authorization', 'proxy-authorization']);

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const invalidRecord = message => fail('INVALID_ATTACK_RECORD', message);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function loopbackOrigin(value) {
  let url;
  try { url = new URL(value); }
  catch { throw fail('INVALID_ORIGIN', 'origin must be an absolute URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || !LOOPBACK_HOSTS.has(url.hostname)
    || url.username || url.password || url.pathname !== '/') {
    throw fail('INVALID_ORIGIN', 'origin must be a loopback http(s) origin');
  }
  return url.origin;
}

export function redactHeaders(headers) {
  return Object.fromEntries(Object.entries(headers ?? {}).map(([name, value]) => [
    name, SECRET_HEADERS.has(name.toLowerCase()) ? '[redacted]' : value,
  ]));
}

function redactExchange(part) {
  if (!part) return;
  if (part.request) part.request.headers = redactHeaders(part.request.headers);
  if (part.response) part.response.headers = redactHeaders(part.response.headers);
}

function targetOrigin(value) {
  try { return loopbackOrigin(value); }
  catch { throw invalidRecord('target.origin must be a loopback origin'); }
}

function parseUrl(value) {
  try { return new URL(value); }
  catch { throw invalidRecord('request.url must be an absolute URL'); }
}

export function validateAttackRecord(record) {
  if (!isObject(record) || record.schemaVersion !== 'attack-record/1') throw invalidRecord('schemaVersion must be attack-record/1');
  if (typeof record.id !== 'string' || !ID.test(record.id)) throw invalidRecord('id is invalid');
  if (record.kind !== undefined && (typeof record.kind !== 'string' || record.kind.length > 64)) {
    throw invalidRecord('kind must be a string of at most 64 characters');
  }
  const origin = targetOrigin(record.target?.origin);
  const { request, response } = record;
  if (!isObject(request) || typeof request.method !== 'string') throw invalidRecord('request.method is required');
  if (parseUrl(request.url).origin !== origin) throw invalidRecord('request.url must match target origin');
  if (!isObject(response) || !(Number.isInteger(response.status) || response.status === null)) {
    throw invalidRecord('response.status must be an integer or null');
  }
  for (const key of ['info', 'control', 'followUp']) {
    if (record[key] !== undefined && !isObject(record[key])) throw invalidRecord(`${key} must be an object`);
  }
  const copy = structuredClone(record);
  copy.kind = record.kind ?? 'unspecified';
  redactExchange(copy);
  redactExchange(copy.control);
  redactExchange(copy.followUp);
  return copy;
}

export function evidenceItem({ id, source, kind, asset, summary }) {
  if (Buffer.byteLength(summary) > LIMITS.summaryBytes) throw fail('EVIDENCE_TOO_LARGE', 'summary exceeds 2048 bytes');
  const item = { id, source, kind, asset, summary, observedAt: new Date().toISOString() };
  if (Buffer.byteLength(JSON.stringify(item)) > LIMITS.evidenceBytes) throw fail('EVIDENCE_TOO_LARGE', 'evidence exceeds 4096 bytes');
  return item;
}

export function bodyDigest(text) {
  if (typeof text !== 'string' || text === '') return null;
  return `sha256:${createHash('sha256').update(text).digest('hex').slice(0, 12)}`;
}
