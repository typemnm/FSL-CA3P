'use strict';

const DEFAULT_BASE_URL = 'https://api.deepseek.com';
const DEFAULT_MODEL = 'deepseek-flash';
const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_RETRIES = 1;
const DEFAULT_MAX_TOKENS = 512;
const MAX_PROMPT_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_CONTENT_BYTES = 64 * 1024;
const SUPPORTED_MODELS = new Set(['deepseek-flash', 'deepseek-v4-pro']);
const RETRYABLE_STATUSES = new Set([429, 500, 503]);

class DeepSeekError extends Error {
  constructor(message, {
    code = 'DEEPSEEK_ERROR',
    status = null,
    retryable = false,
  } = {}) {
    super(message);
    this.name = 'DeepSeekError';
    this.code = code;
    this.status = status;
    this.retryable = retryable;
    this.source = 'deepseek_api';
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      status: this.status,
      retryable: this.retryable,
      source: this.source,
      message: this.message,
    };
  }
}

function configError(message) {
  return new DeepSeekError(message, { code: 'DEEPSEEK_CONFIG_ERROR' });
}

function boundedInteger(name, value, { min, max }) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw configError(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function normalizeBaseUrl(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw || raw.includes('?') || raw.includes('#')) {
    throw configError('DeepSeek base URL cannot contain query parameters or fragments');
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw configError('DeepSeek base URL must be a valid URL');
  }

  const loopback = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
  const official = url.protocol === 'https:' && url.hostname === 'api.deepseek.com';
  const localHttp = url.protocol === 'http:' && loopback.has(url.hostname);
  if (!official && !localHttp) {
    throw configError('DeepSeek base URL must use the official HTTPS host or an explicit loopback HTTP URL');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw configError('DeepSeek base URL cannot contain credentials, query parameters, or fragments');
  }

  return url.toString().replace(/\/+$/, '');
}

function statusError(status) {
  const common = { status, retryable: RETRYABLE_STATUSES.has(status) };
  if (status === 401 || status === 403) {
    return new DeepSeekError('DeepSeek authentication failed', {
      ...common,
      code: 'DEEPSEEK_AUTH_ERROR',
    });
  }
  if (status === 402) {
    return new DeepSeekError('DeepSeek account has insufficient balance', {
      ...common,
      code: 'DEEPSEEK_BALANCE_ERROR',
    });
  }
  if (status === 429) {
    return new DeepSeekError('DeepSeek rate limit reached', {
      ...common,
      code: 'DEEPSEEK_RATE_LIMITED',
    });
  }
  if (status === 400 || status === 422) {
    return new DeepSeekError('DeepSeek rejected the request format', {
      ...common,
      code: 'DEEPSEEK_REQUEST_ERROR',
    });
  }
  if (status === 500 || status === 503) {
    return new DeepSeekError('DeepSeek service is temporarily unavailable', {
      ...common,
      code: 'DEEPSEEK_UPSTREAM_ERROR',
    });
  }
  return new DeepSeekError(`DeepSeek request failed with HTTP ${status}`, {
    ...common,
    code: 'DEEPSEEK_HTTP_ERROR',
  });
}

function sanitizeUsage(usage) {
  if (!usage || typeof usage !== 'object' || Array.isArray(usage)) return null;
  const sanitized = {};
  for (const key of ['prompt_tokens', 'completion_tokens', 'total_tokens']) {
    if (Number.isInteger(usage[key]) && usage[key] >= 0) sanitized[key] = usage[key];
  }
  return Object.keys(sanitized).length > 0 ? sanitized : null;
}

function defaultSleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function responseError(message) {
  return new DeepSeekError(message, { code: 'DEEPSEEK_RESPONSE_ERROR' });
}

function responseTooLargeError() {
  return responseError(`DeepSeek response exceeds ${MAX_RESPONSE_BYTES} bytes`);
}

function declaredContentLength(response) {
  if (!response?.headers || typeof response.headers.get !== 'function') return null;
  const raw = response.headers.get('content-length');
  if (raw === null || raw === undefined || String(raw).trim() === '') return null;
  const normalized = String(raw).trim();
  if (!/^\d+$/.test(normalized)) {
    throw responseError('DeepSeek returned an invalid Content-Length header');
  }
  const length = Number(normalized);
  if (!Number.isSafeInteger(length)) throw responseTooLargeError();
  return length;
}

async function cancelBody(body, controller, reason) {
  controller.abort(reason);
  if (!body || typeof body.cancel !== 'function') return;
  try {
    await body.cancel(reason);
  } catch {
    // The abort may cause cancel() itself to reject; the bounded read still fails closed.
  }
}

async function readBoundedResponseText(response, controller) {
  const contentLength = declaredContentLength(response);
  if (contentLength !== null && contentLength > MAX_RESPONSE_BYTES) {
    const error = responseTooLargeError();
    await cancelBody(response.body, controller, error);
    throw error;
  }

  if (response.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) {
          throw responseError('DeepSeek returned an invalid response body chunk');
        }
        totalBytes += value.byteLength;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          const error = responseTooLargeError();
          controller.abort(error);
          if (typeof reader.cancel === 'function') {
            try {
              await reader.cancel(error);
            } catch {
              // The abort may already have errored the reader.
            }
          }
          throw error;
        }
        chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      }
    } finally {
      if (typeof reader.releaseLock === 'function') reader.releaseLock();
    }
    return Buffer.concat(chunks, totalBytes).toString('utf8');
  }

  if (typeof response.text !== 'function') {
    throw responseError('DeepSeek returned an invalid HTTP response body');
  }
  const text = await response.text();
  if (typeof text !== 'string') {
    throw responseError('DeepSeek returned an invalid HTTP response body');
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw responseTooLargeError();
  return text;
}

class DeepSeekClient {
  #apiKey;

  #fetchImpl;

  #sleep;

  constructor({
    apiKey,
    fetchImpl = globalThis.fetch,
    baseUrl = DEFAULT_BASE_URL,
    model = DEFAULT_MODEL,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRetries = DEFAULT_MAX_RETRIES,
    maxTokens = DEFAULT_MAX_TOKENS,
    sleep = defaultSleep,
  } = {}) {
    if (typeof apiKey !== 'string'
      || apiKey.trim().length === 0
      || /[\u0000-\u0020\u007F]/.test(apiKey.trim())) {
      throw configError('DEEPSEEK_API_KEY is required');
    }
    if (typeof fetchImpl !== 'function') {
      throw configError('A Fetch-compatible implementation is required');
    }
    if (typeof sleep !== 'function') throw configError('sleep must be a function');
    if (!SUPPORTED_MODELS.has(model)) {
      throw configError(`Unsupported DeepSeek model: ${model}`);
    }

    this.#apiKey = apiKey.trim();
    this.#fetchImpl = fetchImpl;
    this.#sleep = sleep;
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.model = model;
    this.timeoutMs = boundedInteger('timeoutMs', timeoutMs, { min: 1, max: 600_000 });
    this.maxRetries = boundedInteger('maxRetries', maxRetries, { min: 0, max: 2 });
    this.maxTokens = boundedInteger('maxTokens', maxTokens, { min: 64, max: 8_192 });
  }

  async completeJson({ systemPrompt, userPayload, signal } = {}) {
    if (typeof systemPrompt !== 'string' || systemPrompt.trim().length === 0) {
      throw configError('systemPrompt is required');
    }
    if (!/json/i.test(systemPrompt)) {
      throw configError('systemPrompt must explicitly request JSON output');
    }

    let serializedPayload;
    try {
      serializedPayload = JSON.stringify(userPayload);
    } catch (error) {
      throw configError(`userPayload must be JSON serializable: ${error.message}`);
    }
    if (serializedPayload === undefined) throw configError('userPayload must be JSON serializable');
    if (Buffer.byteLength(systemPrompt, 'utf8') + Buffer.byteLength(serializedPayload, 'utf8')
      > MAX_PROMPT_BYTES) {
      throw configError(`DeepSeek prompt exceeds ${MAX_PROMPT_BYTES} bytes`);
    }

    const requestBody = {
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: serializedPayload },
      ],
      response_format: { type: 'json_object' },
      thinking: { type: 'disabled' },
      max_tokens: this.maxTokens,
      stream: false,
    };

    let lastError;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      if (signal?.aborted) {
        throw new DeepSeekError('DeepSeek request was aborted', {
          code: 'DEEPSEEK_ABORTED',
        });
      }
      try {
        return await this.#attempt(requestBody, signal);
      } catch (error) {
        const normalized = error instanceof DeepSeekError
          ? error
          : new DeepSeekError('DeepSeek transport failed', {
            code: 'DEEPSEEK_TRANSPORT_ERROR',
            retryable: true,
          });
        lastError = normalized;
        if (!normalized.retryable || attempt === this.maxRetries) throw normalized;
        await this.#sleep(Math.min(250 * (2 ** attempt), 2_000));
      }
    }
    throw lastError;
  }

  async #attempt(requestBody, externalSignal) {
    const controller = new AbortController();
    let timedOut = false;
    const onExternalAbort = () => controller.abort(externalSignal.reason);
    if (externalSignal) externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new Error('DeepSeek request timeout'));
    }, this.timeoutMs);

    try {
      let response;
      try {
        response = await this.#fetchImpl(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.#apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        });
      } catch {
        if (timedOut) {
          throw new DeepSeekError('DeepSeek request timed out', {
            code: 'DEEPSEEK_TIMEOUT',
            retryable: true,
          });
        }
        if (externalSignal?.aborted) {
          throw new DeepSeekError('DeepSeek request was aborted', {
            code: 'DEEPSEEK_ABORTED',
          });
        }
        throw new DeepSeekError('DeepSeek transport failed', {
          code: 'DEEPSEEK_TRANSPORT_ERROR',
          retryable: true,
        });
      }

      if (!response || typeof response.ok !== 'boolean' || !Number.isInteger(response.status)) {
        throw responseError('DeepSeek returned an invalid HTTP response');
      }
      if (!response.ok) {
        const error = statusError(response.status);
        await cancelBody(response.body, controller, error);
        throw error;
      }

      let responseText;
      try {
        responseText = await readBoundedResponseText(response, controller);
      } catch (error) {
        if (error instanceof DeepSeekError) throw error;
        if (timedOut) {
          throw new DeepSeekError('DeepSeek request timed out', {
            code: 'DEEPSEEK_TIMEOUT',
            retryable: true,
          });
        }
        if (externalSignal?.aborted) {
          throw new DeepSeekError('DeepSeek request was aborted', {
            code: 'DEEPSEEK_ABORTED',
          });
        }
        throw responseError('DeepSeek response body could not be read');
      }

      let envelope;
      try {
        envelope = JSON.parse(responseText);
      } catch {
        throw responseError('DeepSeek returned a non-JSON response envelope');
      }

      if (!Array.isArray(envelope?.choices) || envelope.choices.length !== 1) {
        throw responseError('DeepSeek response must contain exactly one choice');
      }
      const choice = envelope.choices[0];
      const finishReason = choice?.finish_reason;
      if (finishReason !== 'stop') {
        const retryable = finishReason === 'insufficient_system_resource';
        throw new DeepSeekError('DeepSeek did not complete the JSON response', {
          code: 'DEEPSEEK_INCOMPLETE_RESPONSE',
          retryable,
        });
      }

      const content = choice?.message?.content;
      if (typeof content !== 'string' || content.trim().length === 0) {
        throw new DeepSeekError('DeepSeek returned empty JSON content', {
          code: 'DEEPSEEK_EMPTY_RESPONSE',
          retryable: true,
        });
      }
      if (Buffer.byteLength(content, 'utf8') > MAX_CONTENT_BYTES) {
        throw new DeepSeekError(`DeepSeek JSON content exceeds ${MAX_CONTENT_BYTES} bytes`, {
          code: 'DEEPSEEK_OUTPUT_ERROR',
        });
      }

      let value;
      try {
        value = JSON.parse(content);
      } catch {
        throw new DeepSeekError('DeepSeek returned invalid JSON content', {
          code: 'DEEPSEEK_OUTPUT_ERROR',
        });
      }
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new DeepSeekError('DeepSeek JSON output must be an object', {
          code: 'DEEPSEEK_OUTPUT_ERROR',
        });
      }

      return {
        value,
        metadata: {
          provider: 'deepseek',
          model: this.model,
          finishReason,
          usage: sanitizeUsage(envelope.usage),
        },
      };
    } finally {
      clearTimeout(timer);
      if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
    }
  }
}

module.exports = {
  DEFAULT_BASE_URL,
  DEFAULT_MAX_RETRIES,
  DEFAULT_MAX_TOKENS,
  DEFAULT_MODEL,
  DEFAULT_TIMEOUT_MS,
  DeepSeekClient,
  DeepSeekError,
  MAX_CONTENT_BYTES,
  MAX_PROMPT_BYTES,
  MAX_RESPONSE_BYTES,
};
