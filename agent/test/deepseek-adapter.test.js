'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { inspect } = require('node:util');
const {
  DeepSeekClient,
  DeepSeekError,
  resolveDeepSeekOptions,
} = require('../src');
const {
  MAX_CONTENT_BYTES,
  MAX_PROMPT_BYTES,
  MAX_RESPONSE_BYTES,
} = require('../src/deepseek-client');

const API_KEY = 'ds-test-secret-that-must-not-leak';
const DEFAULT_URL = 'https://api.deepseek.com/chat/completions';

const VALID_DECISION = Object.freeze({
  state: 'act',
  candidateId: 'candidate-0',
  actionCatalogId: 'delete_observed_canary',
});

function completionBody(content = JSON.stringify(VALID_DECISION), {
  finishReason = 'stop',
  model = 'deepseek-flash',
} = {}) {
  return {
    id: 'chatcmpl-test',
    model,
    choices: [{
      index: 0,
      finish_reason: finishReason,
      message: { role: 'assistant', content },
    }],
    usage: {
      prompt_tokens: 23,
      completion_tokens: 17,
      total_tokens: 40,
    },
  };
}

function httpResponse(status, body, {
  rawText,
  headers = {},
} = {}) {
  const normalizedHeaders = new Map(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]),
  );
  const text = rawText === undefined ? JSON.stringify(body) : rawText;

  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return normalizedHeaders.get(String(name).toLowerCase()) ?? null;
      },
    },
    async text() {
      return text;
    },
    async json() {
      return JSON.parse(text);
    },
  };
}

function streamedHttpResponse(chunks, { headers = {} } = {}) {
  const normalizedHeaders = new Map(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]),
  );
  const state = {
    bodyCancelled: false,
    readerCancelled: false,
    readerCreated: false,
    readCalls: 0,
    textCalls: 0,
  };
  let index = 0;
  const body = {
    async cancel() {
      state.bodyCancelled = true;
    },
    getReader() {
      state.readerCreated = true;
      return {
        async cancel() {
          state.readerCancelled = true;
        },
        async read() {
          state.readCalls += 1;
          if (index >= chunks.length) return { done: true, value: undefined };
          const value = chunks[index];
          index += 1;
          return { done: false, value };
        },
        releaseLock() {},
      };
    },
  };
  return {
    response: {
      ok: true,
      status: 200,
      headers: {
        get(name) {
          return normalizedHeaders.get(String(name).toLowerCase()) ?? null;
        },
      },
      body,
      async text() {
        state.textCalls += 1;
        throw new Error('stream response must not use text()');
      },
    },
    state,
  };
}

function sequenceFetch(...steps) {
  const calls = [];
  let index = 0;
  const fetchImpl = async (...args) => {
    calls.push(args);
    if (index >= steps.length) throw new Error('Unexpected extra fake fetch call');
    const step = steps[index];
    index += 1;
    if (typeof step === 'function') return step(...args);
    if (step instanceof Error) throw step;
    return step;
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

async function expectDeepSeekError(promise, assertion = () => {}) {
  try {
    await promise;
    assert.fail('Expected a DeepSeekError rejection');
  } catch (error) {
    assert.ok(error instanceof DeepSeekError, `expected DeepSeekError, received ${error?.constructor?.name}`);
    assertion(error);
    return error;
  }
}

test('DeepSeekClient sends the documented JSON request and returns parsed value plus safe metadata', async () => {
  const fetchImpl = sequenceFetch(httpResponse(200, completionBody(), {
    headers: { 'x-request-id': 'request-test-1' },
  }));
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    sleep: async () => {},
  });

  const userPayload = { candidates: [{ candidateId: 'lab-cwe-639' }] };
  const result = await client.completeJson({
    systemPrompt: 'Return only the requested JSON decision.',
    userPayload,
  });

  assert.deepEqual(result.value, VALID_DECISION);
  assert.equal(typeof result.metadata, 'object');
  assert.deepEqual(result.metadata, {
    provider: 'deepseek',
    model: 'deepseek-flash',
    reportedModel: 'deepseek-flash',
    finishReason: 'stop',
    usage: { prompt_tokens: 23, completion_tokens: 17, total_tokens: 40 },
  });
  assert.doesNotMatch(JSON.stringify(result), new RegExp(API_KEY));
  assert.equal(result.metadata.raw, undefined);

  assert.equal(fetchImpl.calls.length, 1);
  const [url, options] = fetchImpl.calls[0];
  assert.equal(url, DEFAULT_URL);
  assert.equal(options.method, 'POST');
  assert.ok(options.signal instanceof AbortSignal);

  const headers = new Headers(options.headers);
  assert.equal(headers.get('authorization'), `Bearer ${API_KEY}`);
  assert.equal(headers.get('content-type'), 'application/json');

  const body = JSON.parse(options.body);
  assert.equal(body.model, 'deepseek-flash');
  assert.equal(body.stream, false);
  assert.equal(body.max_tokens, 512);
  assert.deepEqual(body.response_format, { type: 'json_object' });
  assert.deepEqual(body.thinking, { type: 'disabled' });
  assert.deepEqual(body.messages.map(message => message.role), ['system', 'user']);
  assert.equal(body.messages[0].content, 'Return only the requested JSON decision.');
  assert.deepEqual(JSON.parse(body.messages[1].content), userPayload);
  assert.doesNotMatch(options.body, new RegExp(API_KEY));
});

test('DeepSeekClient never includes the API key or upstream response body in exposed errors', async () => {
  const fetchImpl = sequenceFetch(httpResponse(401, {
    error: { message: `rejected Authorization: Bearer ${API_KEY}` },
  }));
  const client = new DeepSeekClient({ apiKey: API_KEY, fetchImpl });

  const error = await expectDeepSeekError(client.completeJson({
    systemPrompt: 'Return JSON only.',
    userPayload: { safe: true },
  }));

  assert.doesNotMatch(error.message, new RegExp(API_KEY));
  assert.doesNotMatch(JSON.stringify(error), new RegExp(API_KEY));
  assert.equal(error.responseBody, undefined);
});

test('DeepSeekClient drops a transport cause that contains authorization data', async () => {
  const leakyCause = new Error(`Bearer ${API_KEY}`);
  leakyCause.request = { headers: { Authorization: `Bearer ${API_KEY}` } };
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl: sequenceFetch(leakyCause),
    maxRetries: 0,
  });

  const error = await expectDeepSeekError(client.completeJson({
    systemPrompt: 'Return JSON only.',
    userPayload: {},
  }));

  assert.equal(error.cause, undefined);
  assert.doesNotMatch(inspect(error), new RegExp(API_KEY));
});

test('DeepSeekClient rejects empty, invalid, malformed-wire, and length-truncated output', async t => {
  const cases = [
    ['empty content', httpResponse(200, completionBody(''))],
    ['invalid content JSON', httpResponse(200, completionBody('not-json'))],
    ['malformed response JSON', httpResponse(200, null, { rawText: '{' })],
    ['length finish reason', httpResponse(200, completionBody(JSON.stringify(VALID_DECISION), {
      finishReason: 'length',
    }))],
  ];

  for (const [name, response] of cases) {
    await t.test(name, async () => {
      const client = new DeepSeekClient({
        apiKey: API_KEY,
        fetchImpl: sequenceFetch(response),
        maxRetries: 0,
      });
      await expectDeepSeekError(client.completeJson({
        systemPrompt: 'Return JSON only.',
        userPayload: {},
      }), error => {
        assert.equal(typeof error.code, 'string');
        if (name === 'length finish reason') assert.equal(error.finishReason, 'length');
      });
    });
  }
});

test('DeepSeekClient treats 401 as non-retryable even when retries are configured', async () => {
  const sleeps = [];
  const fetchImpl = sequenceFetch(httpResponse(401, { error: { message: 'unauthorized' } }));
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    maxRetries: 1,
    sleep: async delay => sleeps.push(delay),
  });

  await expectDeepSeekError(client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }), error => {
    assert.equal(error.status, 401);
    assert.equal(error.retryable, false);
  });
  assert.equal(fetchImpl.calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test('DeepSeekClient cancels non-success response bodies before returning or retrying', async t => {
  for (const status of [401, 429]) {
    await t.test(`HTTP ${status}`, async () => {
      let bodyCancelled = false;
      const response = httpResponse(status, { error: { message: 'ignored' } });
      response.body = {
        async cancel() {
          bodyCancelled = true;
        },
      };
      const client = new DeepSeekClient({
        apiKey: API_KEY,
        fetchImpl: sequenceFetch(response),
        maxRetries: 0,
      });

      await expectDeepSeekError(
        client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }),
        error => assert.equal(error.status, status),
      );
      assert.equal(bodyCancelled, true);
    });
  }
});

test('DeepSeekClient retries a 429 once before returning a successful JSON response', async () => {
  const sleeps = [];
  const fetchImpl = sequenceFetch(
    httpResponse(429, { error: { message: 'rate limited' } }),
    httpResponse(200, completionBody()),
  );
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    maxRetries: 1,
    sleep: async delay => sleeps.push(delay),
  });

  const result = await client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} });
  assert.deepEqual(result.value, VALID_DECISION);
  assert.equal(fetchImpl.calls.length, 2);
  assert.equal(sleeps.length, 1);
  assert.ok(Number.isFinite(sleeps[0]) && sleeps[0] >= 0);
});

test('DeepSeekClient retries 5xx responses only up to the configured bound', async () => {
  const sleeps = [];
  const fetchImpl = sequenceFetch(
    httpResponse(503, { error: { message: 'temporarily unavailable' } }),
    httpResponse(503, { error: { message: 'still unavailable' } }),
  );
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    maxRetries: 1,
    sleep: async delay => sleeps.push(delay),
  });

  await expectDeepSeekError(client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }), error => {
    assert.equal(error.status, 503);
    assert.equal(error.retryable, true);
  });
  assert.equal(fetchImpl.calls.length, 2);
  assert.equal(sleeps.length, 1);
});

test('DeepSeekClient aborts an in-flight fake fetch when its timeout expires', async () => {
  let observedAbort = false;
  const fetchImpl = sequenceFetch((_url, { signal }) => new Promise((resolve, reject) => {
    const abort = () => {
      observedAbort = true;
      reject(signal.reason || new Error('aborted'));
    };
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  }));
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    timeoutMs: 5,
    maxRetries: 0,
  });

  await expectDeepSeekError(client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }), error => {
    assert.match(error.code, /TIMEOUT/);
  });
  assert.equal(observedAbort, true);
  assert.equal(fetchImpl.calls.length, 1);
});

test('DeepSeekClient timeout remains active while reading the response body', async () => {
  let observedAbort = false;
  const fetchImpl = sequenceFetch((_url, { signal }) => ({
    ok: true,
    status: 200,
    async text() {
      return new Promise((resolve, reject) => {
        const abort = () => {
          observedAbort = true;
          reject(new Error('body aborted'));
        };
        if (signal.aborted) abort();
        else signal.addEventListener('abort', abort, { once: true });
      });
    },
  }));
  const client = new DeepSeekClient({
    apiKey: API_KEY,
    fetchImpl,
    timeoutMs: 5,
    maxRetries: 0,
  });

  await expectDeepSeekError(client.completeJson({
    systemPrompt: 'Return JSON only.',
    userPayload: {},
  }), error => {
    assert.equal(error.code, 'DEEPSEEK_TIMEOUT');
  });
  assert.equal(observedAbort, true);
});

test('DeepSeekClient enforces the response byte limit before and during body reads', async t => {
  await t.test('rejects declared oversized content before creating a reader', async () => {
    const { response, state } = streamedHttpResponse([], {
      headers: { 'content-length': MAX_RESPONSE_BYTES + 1 },
    });
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl: sequenceFetch(response),
      maxRetries: 0,
    });

    await expectDeepSeekError(
      client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }),
      error => {
        assert.equal(error.code, 'DEEPSEEK_RESPONSE_ERROR');
        assert.match(error.message, /exceeds/);
      },
    );
    assert.equal(state.bodyCancelled, true);
    assert.equal(state.readerCreated, false);
    assert.equal(state.textCalls, 0);
  });

  await t.test('cancels a streamed body as soon as decoded bytes exceed the limit', async () => {
    const { response, state } = streamedHttpResponse([
      new Uint8Array(MAX_RESPONSE_BYTES),
      new Uint8Array([0]),
      new Uint8Array([1]),
    ]);
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl: sequenceFetch(response),
      maxRetries: 0,
    });

    await expectDeepSeekError(
      client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }),
      error => {
        assert.equal(error.code, 'DEEPSEEK_RESPONSE_ERROR');
        assert.match(error.message, /exceeds/);
      },
    );
    assert.equal(state.readerCancelled, true);
    assert.equal(state.readCalls, 2, 'the reader must stop before consuming later chunks');
    assert.equal(state.textCalls, 0);
  });

  await t.test('retains the post-read limit for a text-only response fallback', async () => {
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl: sequenceFetch(httpResponse(200, null, {
        rawText: 'x'.repeat(MAX_RESPONSE_BYTES + 1),
      })),
      maxRetries: 0,
    });

    await expectDeepSeekError(
      client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: {} }),
      error => {
        assert.equal(error.code, 'DEEPSEEK_RESPONSE_ERROR');
        assert.match(error.message, /exceeds/);
      },
    );
  });
});

test('DeepSeekClient rejects oversized prompts and model JSON content at the 64 KiB boundaries', async t => {
  await t.test('rejects an oversized prompt before dispatching fake fetch', async () => {
    let fetchCalls = 0;
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error('oversized prompts must not be dispatched');
      },
      maxRetries: 0,
    });

    await expectDeepSeekError(client.completeJson({
      systemPrompt: `Return JSON only. ${'x'.repeat(MAX_PROMPT_BYTES)}`,
      userPayload: {},
    }), error => {
      assert.equal(error.code, 'DEEPSEEK_CONFIG_ERROR');
      assert.match(error.message, /prompt exceeds/);
    });
    assert.equal(fetchCalls, 0);
  });

  await t.test('rejects oversized model content before parsing it', async () => {
    const fetchImpl = sequenceFetch(httpResponse(
      200,
      completionBody('x'.repeat(MAX_CONTENT_BYTES + 1)),
    ));
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl,
      maxRetries: 0,
    });

    await expectDeepSeekError(client.completeJson({
      systemPrompt: 'Return JSON only.',
      userPayload: {},
    }), error => {
      assert.equal(error.code, 'DEEPSEEK_OUTPUT_ERROR');
      assert.match(error.message, /content exceeds/);
    });
    assert.equal(fetchImpl.calls.length, 1);
  });
});

test('DeepSeekClient treats caller abort signals as non-retryable cancellation', async t => {
  await t.test('pre-aborted signal prevents the first fetch and any retry sleep', async () => {
    let fetchCalls = 0;
    const sleeps = [];
    const controller = new AbortController();
    controller.abort(new Error(`Bearer ${API_KEY}`));
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error('a pre-aborted call must not dispatch');
      },
      maxRetries: 2,
      sleep: async delay => sleeps.push(delay),
    });

    const error = await expectDeepSeekError(client.completeJson({
      systemPrompt: 'Return JSON only.',
      userPayload: {},
      signal: controller.signal,
    }), thrown => {
      assert.equal(thrown.code, 'DEEPSEEK_ABORTED');
      assert.equal(thrown.retryable, false);
    });
    assert.equal(fetchCalls, 0);
    assert.deepEqual(sleeps, []);
    assert.doesNotMatch(inspect(error), new RegExp(API_KEY));
  });

  await t.test('in-flight caller abort reaches fetch and is never retried', async () => {
    let announceStarted;
    const started = new Promise(resolve => { announceStarted = resolve; });
    let observedAbort = false;
    const sleeps = [];
    const fetchImpl = sequenceFetch((_url, { signal }) => new Promise((resolve, reject) => {
      const onAbort = () => {
        observedAbort = true;
        reject(signal.reason || new Error('aborted'));
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
      announceStarted();
    }));
    const client = new DeepSeekClient({
      apiKey: API_KEY,
      fetchImpl,
      timeoutMs: 1_000,
      maxRetries: 2,
      sleep: async delay => sleeps.push(delay),
    });
    const controller = new AbortController();

    const pending = client.completeJson({
      systemPrompt: 'Return JSON only.',
      userPayload: {},
      signal: controller.signal,
    });
    await started;
    controller.abort(new Error(`Bearer ${API_KEY}`));
    const error = await expectDeepSeekError(pending, thrown => {
      assert.equal(thrown.code, 'DEEPSEEK_ABORTED');
      assert.equal(thrown.retryable, false);
    });

    assert.equal(observedAbort, true);
    assert.equal(fetchImpl.calls.length, 1);
    assert.deepEqual(sleeps, []);
    assert.doesNotMatch(inspect(error), new RegExp(API_KEY));
  });
});

test('DeepSeekClient rejects missing, blank, or control-containing API keys before fake fetch dispatch', () => {
  for (const apiKey of [undefined, '', '   ', 'test key', 'test\nkey']) {
    let calls = 0;
    assert.throws(
      () => new DeepSeekClient({
        apiKey,
        fetchImpl: async () => { calls += 1; },
      }),
      error => error instanceof DeepSeekError && typeof error.code === 'string',
    );
    assert.equal(calls, 0);
  }
});

test('DeepSeek config loads an explicit env file without mutating process.env and lets env win', () => {
  const original = process.env.DEEPSEEK_API_KEY;
  const options = resolveDeepSeekOptions({
    env: { DEEPSEEK_MODEL: 'deepseek-v4-pro' },
    envFile: 'virtual-agent.env',
    readFileSync: file => {
      assert.equal(file, 'virtual-agent.env');
      return [
        `DEEPSEEK_API_KEY=${API_KEY}`,
        'DEEPSEEK_MODEL=deepseek-flash',
        'DEEPSEEK_TIMEOUT_MS=1234',
        'DEEPSEEK_MAX_RETRIES=0',
      ].join('\n');
    },
  });

  assert.equal(options.apiKey, API_KEY);
  assert.equal(options.model, 'deepseek-v4-pro');
  assert.equal(options.timeoutMs, 1234);
  assert.equal(options.maxRetries, 0);
  assert.equal(Object.isFrozen(options), true);
  assert.equal(process.env.DEEPSEEK_API_KEY, original);
});

test('DeepSeek client refuses to send a key to an arbitrary remote host', () => {
  assert.throws(
    () => new DeepSeekClient({
      apiKey: API_KEY,
      baseUrl: 'https://attacker.example',
      fetchImpl: async () => { throw new Error('must not be called'); },
    }),
    error => error instanceof DeepSeekError && error.code === 'DEEPSEEK_CONFIG_ERROR',
  );
});

test('DeepSeek client rejects empty query and fragment delimiters in its base URL', () => {
  for (const baseUrl of ['https://api.deepseek.com?', 'https://api.deepseek.com#']) {
    assert.throws(
      () => new DeepSeekClient({ apiKey: API_KEY, baseUrl, fetchImpl: async () => {} }),
      error => error instanceof DeepSeekError && error.code === 'DEEPSEEK_CONFIG_ERROR',
    );
  }
});
