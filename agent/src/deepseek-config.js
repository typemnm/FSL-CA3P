'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  DEFAULT_BASE_URL,
  DEFAULT_MAX_RETRIES,
  DEFAULT_MAX_TOKENS,
  DEFAULT_MODEL,
  DEFAULT_TIMEOUT_MS,
  DeepSeekClient,
  DeepSeekError,
} = require('./deepseek-client');
const { DeepSeekReasoningEngine } = require('./deepseek-reasoning-engine');

const DEFAULT_ENV_FILE = path.resolve(__dirname, '..', '.env');
const SUPPORTED_MODELS = new Set(['deepseek-flash', 'deepseek-v4-pro']);

function parseEnvText(text) {
  const values = {};
  const lines = String(text).replace(/^\uFEFF/, '').split(/\r?\n/);
  for (const originalLine of lines) {
    let line = originalLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7).trimStart();
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;

    const [, key] = match;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') {
        value = value
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\t/g, '\t')
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\');
      }
    } else {
      value = value.replace(/\s+#.*$/, '').trimEnd();
    }
    values[key] = value;
  }
  return values;
}

function configError(message) {
  return new DeepSeekError(message, {
    code: 'DEEPSEEK_CONFIG_ERROR',
  });
}

function readOptionalEnvFile(envFile, readFileSync = fs.readFileSync) {
  if (envFile === false || envFile === null) return {};
  try {
    return parseEnvText(readFileSync(envFile, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return {};
    throw configError('Unable to read the DeepSeek environment file');
  }
}

function pickSetting(env, fileValues, name) {
  if (Object.prototype.hasOwnProperty.call(env, name)) return env[name];
  return fileValues[name];
}

function parseIntegerSetting(name, raw, fallback, { min, max }) {
  if (raw === undefined || raw === null || String(raw).trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw configError(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function requireApiKey(raw) {
  if (typeof raw !== 'string'
    || raw.trim().length === 0
    || /[\u0000-\u0020\u007F]/.test(raw.trim())) {
    throw configError('DEEPSEEK_API_KEY is required');
  }
  return raw.trim();
}

function normalizeBaseUrl(raw) {
  if (typeof raw !== 'string'
    || raw.trim().length === 0
    || raw.includes('?')
    || raw.includes('#')) {
    throw configError('DEEPSEEK_BASE_URL must be a valid URL');
  }

  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    throw configError('DEEPSEEK_BASE_URL must be a valid URL');
  }

  const loopback = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
  const official = url.protocol === 'https:' && url.hostname === 'api.deepseek.com';
  const localHttp = url.protocol === 'http:' && loopback.has(url.hostname);
  if (!official && !localHttp) {
    throw configError('DEEPSEEK_BASE_URL must use the official HTTPS host or an explicit loopback HTTP URL');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw configError('DEEPSEEK_BASE_URL cannot contain credentials, query parameters, or fragments');
  }

  return url.toString().replace(/\/+$/, '');
}

function requireSupportedModel(raw) {
  if (typeof raw !== 'string' || !SUPPORTED_MODELS.has(raw.trim())) {
    throw configError('DEEPSEEK_MODEL must be deepseek-flash or deepseek-v4-pro');
  }
  return raw.trim();
}

function resolveDeepSeekOptions({
  env = process.env,
  envFile = DEFAULT_ENV_FILE,
  readFileSync,
} = {}) {
  if (!env || typeof env !== 'object') throw configError('env must be an object');
  const fileValues = readOptionalEnvFile(envFile, readFileSync);
  const apiKey = requireApiKey(pickSetting(env, fileValues, 'DEEPSEEK_API_KEY'));
  const baseUrl = normalizeBaseUrl(
    pickSetting(env, fileValues, 'DEEPSEEK_BASE_URL') || DEFAULT_BASE_URL,
  );
  const model = requireSupportedModel(
    pickSetting(env, fileValues, 'DEEPSEEK_MODEL') || DEFAULT_MODEL,
  );
  return Object.freeze({
    apiKey,
    baseUrl,
    model,
    timeoutMs: parseIntegerSetting(
      'DEEPSEEK_TIMEOUT_MS',
      pickSetting(env, fileValues, 'DEEPSEEK_TIMEOUT_MS'),
      DEFAULT_TIMEOUT_MS,
      { min: 1, max: 600_000 },
    ),
    maxRetries: parseIntegerSetting(
      'DEEPSEEK_MAX_RETRIES',
      pickSetting(env, fileValues, 'DEEPSEEK_MAX_RETRIES'),
      DEFAULT_MAX_RETRIES,
      { min: 0, max: 2 },
    ),
    maxTokens: parseIntegerSetting(
      'DEEPSEEK_MAX_TOKENS',
      pickSetting(env, fileValues, 'DEEPSEEK_MAX_TOKENS'),
      DEFAULT_MAX_TOKENS,
      { min: 64, max: 8_192 },
    ),
  });
}

function createDeepSeekReasoningEngineFromEnv({
  env,
  envFile,
  readFileSync,
  fetchImpl,
  sleep,
  ruleEngine,
  curlMode,
} = {}) {
  const options = resolveDeepSeekOptions({ env, envFile, readFileSync });
  const client = new DeepSeekClient({ ...options, fetchImpl, sleep });
  return new DeepSeekReasoningEngine({ client, ruleEngine, curlMode });
}

module.exports = {
  DEFAULT_ENV_FILE,
  createDeepSeekReasoningEngineFromEnv,
  parseEnvText,
  resolveDeepSeekOptions,
};
