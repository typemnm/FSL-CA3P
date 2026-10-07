'use strict';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function curlFromHttpAction(action, origin) {
  if (!isPlainObject(action) || action.operation !== 'http_request'
    || typeof action.method !== 'string' || typeof action.path !== 'string') {
    throw new TypeError('A structured HTTP action is required to build curl JSON');
  }
  const target = new URL(action.path, origin);
  for (const [key, value] of Object.entries(action.query || {})) {
    target.searchParams.append(key, String(value));
  }
  const curl = { method: action.method, url: target.toString() };
  if (action.body !== undefined) curl.body = action.body;
  return curl;
}

module.exports = { curlFromHttpAction };
