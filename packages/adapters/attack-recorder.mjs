import attackModule from '../../attack-module/index.js';

const { executeCurl } = attackModule;
const MAX_BODY_TEXT_BYTES = 64 * 1024;

function bodyText(value) {
  // Decoding a cut UTF-8 sequence yields U+FFFD, so the text stays valid.
  return Buffer.from(JSON.stringify(value ?? null), 'utf8').subarray(0, MAX_BODY_TEXT_BYTES).toString('utf8');
}

export async function executeCurlRecorded(command, { allowedOrigin, cookie = null, signal } = {}, info = {}) {
  const { id, kind, ...rest } = info;
  const startedAt = Date.now();
  const result = await executeCurl(command, { allowedOrigin, cookie, signal });
  const elapsedMs = Date.now() - startedAt;
  const record = {
    schemaVersion: 'attack-record/1',
    id,
    kind,
    target: { origin: new URL(allowedOrigin).origin },
    info: rest,
    request: {
      method: command.method,
      url: command.url,
      headers: cookie ? { cookie: '[redacted]' } : {},
      body: command.body ?? null,
    },
    response: {
      status: result.status ?? null,
      headers: {},
      bodyText: bodyText(result.bodyJson),
      bodyJson: result.bodyJson ?? null,
      error: result.success ? null : (result.error ?? 'unknown'),
      elapsedMs,
    },
    observedAt: new Date().toISOString(),
  };
  return { result, record };
}
