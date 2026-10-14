import deepSeekConfig from '../agent/src/deepseek-config.js';

const { createDeepSeekReasoningEngineFromEnv, resolveDeepSeekOptions } = deepSeekConfig;

function abortError() {
  const error = new Error('Local lab model request was stopped.');
  error.name = 'AbortError';
  return error;
}

// Keep the run's cancellation signal attached until the response body has been
// consumed. fetch() itself may resolve before a streamed model answer arrives.
function responseWithCleanup(response, cleanup) {
  const body = response?.body;
  if (!body || typeof body.getReader !== 'function') {
    if (typeof response?.text !== 'function') {
      cleanup();
      return response;
    }
    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      body,
      async text() {
        try { return await response.text(); } finally { cleanup(); }
      },
    };
  }

  const cancellableBody = {
    getReader(...args) {
      let reader;
      try { reader = body.getReader(...args); } catch (error) { cleanup(); throw error; }
      return {
        async read(...readArgs) {
          try {
            const result = await reader.read(...readArgs);
            if (result.done) cleanup();
            return result;
          } catch (error) {
            cleanup();
            throw error;
          }
        },
        async cancel(reason) {
          try { return await reader.cancel(reason); } finally { cleanup(); }
        },
        releaseLock() { reader.releaseLock(); },
      };
    },
    async cancel(reason) {
      try { return await body.cancel(reason); } finally { cleanup(); }
    },
  };
  return {
    ok: response.ok,
    status: response.status,
    headers: response.headers,
    body: cancellableBody,
    async text() {
      try { return await response.text(); } finally { cleanup(); }
    },
  };
}

function fetchForRun(signal) {
  return async (url, init = {}) => {
    if (signal?.aborted || init.signal?.aborted) throw abortError();
    const controller = new AbortController();
    const onRunAbort = () => controller.abort(signal.reason ?? abortError());
    const onClientAbort = () => controller.abort(init.signal.reason ?? abortError());
    const cleanup = () => {
      signal?.removeEventListener('abort', onRunAbort);
      init.signal?.removeEventListener('abort', onClientAbort);
    };
    signal?.addEventListener('abort', onRunAbort, { once: true });
    init.signal?.addEventListener('abort', onClientAbort, { once: true });

    try {
      // An abort can occur between the first check and listener installation.
      if (signal?.aborted) onRunAbort();
      if (init.signal?.aborted) onClientAbort();
      if (controller.signal.aborted) throw abortError();
      const response = await globalThis.fetch(url, { ...init, signal: controller.signal });
      return responseWithCleanup(response, cleanup);
    } catch (error) {
      cleanup();
      throw error;
    }
  };
}

export function checkLabReasoningConfig() {
  const options = resolveDeepSeekOptions();
  return Object.freeze({
    provider: 'deepseek',
    model: options.model,
    possibleRetries: options.maxRetries,
  });
}

export function createLabReasoning({ signal } = {}) {
  if (signal && (typeof signal.aborted !== 'boolean'
    || typeof signal.addEventListener !== 'function'
    || typeof signal.removeEventListener !== 'function')) {
    throw new TypeError('signal must be an AbortSignal.');
  }
  return createDeepSeekReasoningEngineFromEnv({ fetchImpl: fetchForRun(signal), curlMode: true });
}
