/** Same-origin control and telemetry for the local agent runtime. */
export function createRuntimeClient({ onState, onConnection, onError }) {
  let stream = null;
  let closed = false;

  function readEnvelope(value) {
    if (!value || !['core-fixture', 'local-lab-deepseek'].includes(value.mode) || typeof value.instanceId !== 'string' ||
        !value.run || typeof value.run !== 'object' || !Array.isArray(value.run.events)) {
      throw new Error('로컬 런타임의 상태 형식을 확인할 수 없습니다.');
    }
    return value;
  }

  async function request(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      cache: 'no-store',
    });
    let payload;
    try { payload = await response.json(); }
    catch { throw new Error(`로컬 런타임 응답을 읽을 수 없습니다 (${response.status}).`); }
    if (!response.ok) {
      const message = typeof payload?.error === 'string' ? payload.error : typeof payload?.message === 'string' ? payload.message : `요청 실패 (${response.status})`;
      throw new Error(message);
    }
    return readEnvelope(payload);
  }

  function receive(value) {
    const envelope = readEnvelope(value);
    onState(envelope);
  }

  function connectStream() {
    if (closed) return;
    stream = new EventSource('/api/events');
    // Controls unlock only after a valid state event arrives, including reconnection.
    stream.onopen = () => onConnection('connecting');
    stream.addEventListener('state', (event) => {
      try { receive(JSON.parse(event.data)); onConnection('connected'); }
      catch (error) { onConnection('disconnected'); onError(error.message); }
    });
    stream.onerror = () => onConnection('disconnected');
  }

  return {
    async connect() {
      onConnection('connecting');
      try { receive(await request('/api/state')); }
      catch (error) { onError(error.message); }
      // EventSource reconnects automatically, including when the initial fetch fails.
      connectStream();
    },
    async start(target, delayMs) {
      const envelope = await request('/api/runs', { target, delayMs });
      receive(envelope);
      return envelope;
    },
    async startLab() {
      const envelope = await request('/api/lab-runs', {});
      receive(envelope);
      return envelope;
    },
    async stop(id) {
      const envelope = await request(`/api/runs/${encodeURIComponent(id)}/stop`, {});
      receive(envelope);
      return envelope;
    },
    async reset() {
      const envelope = await request('/api/reset', {});
      receive(envelope);
      return envelope;
    },
    close() { closed = true; stream?.close(); },
  };
}
