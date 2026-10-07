'use strict';

const { randomBytes } = require('node:crypto');

const MARKER_RE = /^[a-f0-9]{32}$/;

function storedXssCanaryContent(marker) {
  if (typeof marker !== 'string' || !MARKER_RE.test(marker)) {
    throw new TypeError('Stored-XSS canary marker must be 32 lowercase hexadecimal characters.');
  }
  return `<img data-ca3p-xss-marker="${marker}" src="data:image/png;base64,AA" onerror="window.__ca3pXssProbe?.('${marker}')">`;
}

function createStoredXssCanary() {
  const marker = randomBytes(16).toString('hex');
  return { marker, content: storedXssCanaryContent(marker) };
}

module.exports = { storedXssCanaryContent, createStoredXssCanary };
