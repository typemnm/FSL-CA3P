'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { resolveDeepSeekOptions } = require('../src/deepseek-config');

function assertConfigError(callback) {
  assert.throws(callback, error => {
    assert.equal(error.name, 'DeepSeekError');
    assert.equal(error.code, 'DEEPSEEK_CONFIG_ERROR');
    assert.equal(error.source, 'deepseek_api');
    return true;
  });
}

test('resolveDeepSeekOptions rejects a missing or blank API key immediately', () => {
  assertConfigError(() => resolveDeepSeekOptions({ env: {}, envFile: false }));
  assertConfigError(() => resolveDeepSeekOptions({
    env: { DEEPSEEK_API_KEY: '   ' },
    envFile: false,
  }));
  assertConfigError(() => resolveDeepSeekOptions({
    env: { DEEPSEEK_API_KEY: 'test key' },
    envFile: false,
  }));
});

test('resolveDeepSeekOptions rejects unsupported models and non-official remote hosts', () => {
  assertConfigError(() => resolveDeepSeekOptions({
    env: {
      DEEPSEEK_API_KEY: 'test-key',
      DEEPSEEK_MODEL: 'deepseek-unknown',
    },
    envFile: false,
  }));
  assertConfigError(() => resolveDeepSeekOptions({
    env: {
      DEEPSEEK_API_KEY: 'test-key',
      DEEPSEEK_BASE_URL: 'https://example.test',
    },
    envFile: false,
  }));
});

test('resolveDeepSeekOptions returns normalized frozen settings', () => {
  const options = resolveDeepSeekOptions({
    env: {
      DEEPSEEK_API_KEY: '  test-key  ',
      DEEPSEEK_BASE_URL: 'https://api.deepseek.com/',
      DEEPSEEK_MODEL: ' deepseek-v4-pro ',
    },
    envFile: false,
  });

  assert.equal(options.apiKey, 'test-key');
  assert.equal(options.baseUrl, 'https://api.deepseek.com');
  assert.equal(options.model, 'deepseek-v4-pro');
  assert.equal(Object.isFrozen(options), true);
});

test('resolveDeepSeekOptions enforces numeric boundaries and applies valid overrides', () => {
  const valid = resolveDeepSeekOptions({
    env: {
      DEEPSEEK_API_KEY: 'test-key',
      DEEPSEEK_TIMEOUT_MS: '600000',
      DEEPSEEK_MAX_RETRIES: '2',
      DEEPSEEK_MAX_TOKENS: '8192',
    },
    envFile: false,
  });
  assert.equal(valid.timeoutMs, 600_000);
  assert.equal(valid.maxRetries, 2);
  assert.equal(valid.maxTokens, 8_192);

  const invalid = [
    ['DEEPSEEK_TIMEOUT_MS', '0'],
    ['DEEPSEEK_TIMEOUT_MS', '1.5'],
    ['DEEPSEEK_MAX_RETRIES', '-1'],
    ['DEEPSEEK_MAX_RETRIES', '3'],
    ['DEEPSEEK_MAX_TOKENS', '63'],
    ['DEEPSEEK_MAX_TOKENS', '8193'],
  ];
  for (const [name, value] of invalid) {
    assertConfigError(() => resolveDeepSeekOptions({
      env: { DEEPSEEK_API_KEY: 'test-key', [name]: value },
      envFile: false,
    }));
  }
});

test('resolveDeepSeekOptions permits loopback HTTP and rejects URL credentials, query, and fragment', () => {
  const loopback = resolveDeepSeekOptions({
    env: {
      DEEPSEEK_API_KEY: 'test-key',
      DEEPSEEK_BASE_URL: 'http://localhost:8080/v1/',
    },
    envFile: false,
  });
  assert.equal(loopback.baseUrl, 'http://localhost:8080/v1');

  for (const baseUrl of [
    'https://user:pass@api.deepseek.com',
    'https://api.deepseek.com?',
    'https://api.deepseek.com?key=value',
    'https://api.deepseek.com#',
    'https://api.deepseek.com/#fragment',
  ]) {
    assertConfigError(() => resolveDeepSeekOptions({
      env: { DEEPSEEK_API_KEY: 'test-key', DEEPSEEK_BASE_URL: baseUrl },
      envFile: false,
    }));
  }
});

test('resolveDeepSeekOptions parses common dotenv forms without mutating process.env', () => {
  const before = process.env.DEEPSEEK_API_KEY;
  const options = resolveDeepSeekOptions({
    env: {},
    envFile: 'virtual.env',
    readFileSync: () => [
      'export DEEPSEEK_API_KEY="test-key"',
      "DEEPSEEK_MODEL='deepseek-v4-pro'",
      'DEEPSEEK_TIMEOUT_MS=1234 # local timeout',
    ].join('\n'),
  });

  assert.equal(options.apiKey, 'test-key');
  assert.equal(options.model, 'deepseek-v4-pro');
  assert.equal(options.timeoutMs, 1234);
  assert.equal(process.env.DEEPSEEK_API_KEY, before);
});

test('resolveDeepSeekOptions ignores a missing env file but sanitizes other read failures', () => {
  const missing = resolveDeepSeekOptions({
    env: { DEEPSEEK_API_KEY: 'test-key' },
    envFile: 'missing.env',
    readFileSync: () => {
      throw Object.assign(new Error('missing'), { code: 'ENOENT' });
    },
  });
  assert.equal(missing.apiKey, 'test-key');

  assert.throws(
    () => resolveDeepSeekOptions({
      env: { DEEPSEEK_API_KEY: 'test-key' },
      envFile: 'denied.env',
      readFileSync: () => {
        throw Object.assign(new Error('upstream-secret'), { code: 'EACCES' });
      },
    }),
    error => {
      assert.equal(error.code, 'DEEPSEEK_CONFIG_ERROR');
      assert.doesNotMatch(error.message, /upstream-secret/);
      return true;
    },
  );
});
