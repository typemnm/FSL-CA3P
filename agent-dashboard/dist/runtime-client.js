/** Same-origin API, authenticated controls and live telemetry. */
export function createRuntimeClient({ onState, onConnection, onError, onSession = () => {}, onAuthRequired = () => {},
  fetchImpl = globalThis.fetch, EventSourceImpl = globalThis.EventSource, hostname = globalThis.location?.hostname ?? 'localhost',
  pollIntervalMs = 1000 } = {}) {
  let stream = null;
  let timer = null;
  let closed = false;
  let polling = false;
  let session = null;
  let transport = 'polling';
  let generation = 0;
  const remote = !['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname);

  function readEnvelope(value) {
    if (!value || !['core-fixture', 'local-lab-rule', 'local-lab-deepseek', 'local-lab-general', 'external-general'].includes(value.mode ?? value.run?.mode)
      || typeof value.instanceId !== 'string' || !value.run || !Array.isArray(value.run.events)) {
      throw new Error('실행 서버의 상태 형식을 확인할 수 없습니다.');
    }
    return value;
  }

  function disconnect() {
    generation += 1; polling = false;
    stream?.close(); stream = null;
    clearTimeout(timer); timer = null;
  }

  async function api(path, { method = 'GET', body, formData, signal } = {}) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (!['GET', 'HEAD'].includes(method) && session?.csrfToken) headers['X-CSRF-Token'] = session.csrfToken;
    const response = await fetchImpl(path, {
      method, headers,
      ...(body === undefined ? formData === undefined ? {} : { body: formData } : { body: JSON.stringify(body) }),
      credentials: 'same-origin', cache: 'no-store', ...(signal ? { signal } : {}),
    });
    let payload;
    try { payload = response.status === 204 ? {} : await response.json(); }
    catch { throw new Error(`서버 응답을 읽을 수 없습니다 (${response.status}).`); }
    if (!response.ok) {
      if (response.status === 401) { closed = true; disconnect(); onConnection('disconnected', transport); onAuthRequired(); }
      const message = typeof payload?.error === 'string' ? payload.error : typeof payload?.message === 'string' ? payload.message : `요청 실패 (${response.status})`;
      throw Object.assign(new Error(message), { status: response.status });
    }
    return payload;
  }
  function request(path, body) { return api(path, { method: body === undefined ? 'GET' : 'POST', ...(body === undefined ? {} : { body }) }); }

  function receive(value) { onState(readEnvelope(value)); }

  async function refreshSession() {
    session = await request('/api/auth/session');
    onSession(session);
    return session;
  }

  async function poll() {
    if (closed || polling) return;
    polling = true;
    const cycle = generation;
    let unauthorized = false;
    try {
      const value = await request('/api/state');
      if (closed || cycle !== generation) return;
      receive(value); onConnection('connected', 'polling');
    }
    catch (error) {
      if (closed || cycle !== generation) return;
      unauthorized = error.status === 401;
      onConnection('disconnected', 'polling');
      if (!unauthorized) onError(error.message);
    } finally {
      if (cycle === generation) {
        polling = false;
        if (!closed && !unauthorized) timer = setTimeout(poll, pollIntervalMs);
      }
    }
  }

  function connectStream() {
    if (closed) return;
    const cycle = generation;
    if (remote || !EventSourceImpl) { transport = 'polling'; void poll(); return; }
    transport = 'sse';
    stream = new EventSourceImpl('/api/events');
    stream.onopen = () => { if (!closed && cycle === generation) onConnection('connecting', transport); };
    stream.addEventListener('state', event => {
      if (closed || cycle !== generation) return;
      try { receive(JSON.parse(event.data)); onConnection('connected', transport); }
      catch (error) { onConnection('disconnected', transport); onError(error.message); }
    });
    stream.onerror = () => {
      if (closed || cycle !== generation) return;
      // Some proxies do not forward streaming responses. Fall back permanently.
      stream?.close(); stream = null; transport = 'polling';
      onConnection('connecting', transport); void poll();
    };
  }

  async function connect() {
    closed = false;
    disconnect();
    onConnection('connecting', remote ? 'polling' : 'sse');
    try {
      const currentSession = await refreshSession();
      if (currentSession.authRequired && !currentSession.authenticated) { onAuthRequired(); return; }
      receive(await request('/api/state'));
      onConnection('connected', remote ? 'polling' : 'sse');
      connectStream();
    } catch (error) {
      onConnection('disconnected', transport);
      if (error.status !== 401) {
        onError(error.message);
        if (!closed) timer = setTimeout(() => void connect(), pollIntervalMs);
      }
    }
  }

  return {
    connect, refreshSession, api,
    async login(username, password) {
      if (!session) await refreshSession();
      await request('/api/auth/login', { username, password });
      await connect();
      return session;
    },
    async logout() {
      await request('/api/auth/logout', {}); closed = true; disconnect();
      session = { ...session, authenticated: false, user: null, csrfToken: null };
      onSession(session); onAuthRequired(); onConnection('disconnected', transport);
    },
    async start(target, delayMs, options = {}) {
      const value = await request('/api/runs', { target, delayMs, mode: 'core-fixture', ...options });
      receive(value); return value;
    },
    async startLab(modelId, mode = 'local-lab-deepseek', fixtureId = 'vul-web-1', target) {
      const value = await request('/api/runs', { mode, ...(modelId ? { modelId } : {}), ...(fixtureId !== 'vul-web-1' ? { fixtureId } : {}), ...(target ? { target } : {}) });
      receive(value); return value;
    },
    preflightExternal(target, pathPrefix = '/') { return api('/api/targets/preflight', { method: 'POST', body: { target, scope: { pathPrefix }, authorizationConfirmed: true } }); },
    async startExternal({ target, pathPrefix, preflightToken }) {
      const value = await api('/api/runs', { method: 'POST', body: {
        mode: 'external-general', target, scope: { pathPrefix }, preflightToken,
        authorizationConfirmed: true, modelId: 'rule-baseline',
      } });
      receive(value); return value;
    },
    async stop(id) { const value = await request(`/api/runs/${encodeURIComponent(id)}/stop`, {}); receive(value); return value; },
    async reset() { const value = await request('/api/reset', {}); receive(value); return value; },
    async resetExperiment() {
      // Ignore queued telemetry and in-flight polls from the previous experiment.
      disconnect();
      try {
        const value = await request('/api/experiment-reset', { confirmed: true });
        if (value.experimentReset?.status !== 'completed') throw new Error('전체 실험 초기화 완료를 확인할 수 없습니다.');
        receive(value);
        onConnection('connected', transport);
        return value;
      } finally { if (!closed) connectStream(); }
    },
    listRuns({ limit, offset } = {}) {
      const query = new URLSearchParams();
      if (limit !== undefined) query.set('limit', String(limit));
      if (offset !== undefined) query.set('offset', String(offset));
      return request(`/api/runs${query.size ? `?${query}` : ''}`);
    },
    getRun(id) { return request(`/api/runs/${encodeURIComponent(id)}`); },
    reportDownloadUrl(id) { return `/api/runs/${encodeURIComponent(id)}/report.hwpx`; },
    findingReportDownloadUrl(runId, artifactId) {
      return `/api/runs/${encodeURIComponent(runId)}/reports/${encodeURIComponent(artifactId)}.hwpx`;
    },
    reportPreviewUrl(runId, findingId) {
      return `/api/runs/${encodeURIComponent(runId)}/report-preview/${encodeURIComponent(findingId)}`;
    },
    getModels() { return request('/api/models'); },
    getPlatform() { return request('/api/platform'); },
    getCiResults() { return request('/api/ci-results'); },
    reviewCheck(runId, checkId, note) { return request(`/api/runs/${encodeURIComponent(runId)}/reviews/${encodeURIComponent(checkId)}`, { note }); },
    compare(baseline, candidate, kind = 'code') { return request(`/api/comparisons?${new URLSearchParams({ baseline, candidate, kind })}`); },
    close() { closed = true; disconnect(); },
  };
}
