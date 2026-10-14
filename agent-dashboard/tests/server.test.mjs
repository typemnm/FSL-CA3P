import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request } from 'node:http';
import { createLocalRuntime } from '../local-runtime.mjs';
import { createDashboardServer } from '../local-server.mjs';

async function serve(t, { delayMs = 0 } = {}) {
  const runtime = createLocalRuntime({ defaultDelayMs: delayMs });
  const server = createDashboardServer({ runtime });
  assert.equal(server.listening, false, 'Creating the server must have no listen side effect');
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await runtime.close();
    server.closeAllConnections?.();
    if (server.listening) {
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });
  return { runtime, server, base };
}

function jsonPost(body, options = {}) {
  return { ...options, method: 'POST', headers: { 'Content-Type': 'application/json', ...options.headers }, body: JSON.stringify(body) };
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.json();
  return { response, body };
}

function statusWithHostHeader(url, host) {
  // Node fetch may replace Host. Use a direct request only to this loopback test server.
  assert.equal(new URL(url).hostname, '127.0.0.1');
  return new Promise((resolve, reject) => {
    const req = request(url, { agent: false, headers: { Host: host } }, res => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Local Host-header check timed out')));
    req.end();
  });
}

function readStateEvents(reader) {
  const decoder = new TextDecoder();
  let buffer = '';
  const queued = [];
  return async function nextState() {
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Timed out waiting for an SSE state event')), 5000);
      timer.unref?.();
    });
    const read = async () => {
      for (;;) {
        if (queued.length) return queued.shift();
        const { value, done } = await reader.read();
        assert.equal(done, false, 'SSE must remain open while the run progresses');
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const lines = frame.split('\n');
          const name = lines.find(line => line.startsWith('event:'))?.slice(6).trim();
          const data = lines.filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
          if (name === 'state' && data) queued.push(JSON.parse(data));
        }
      }
    };
    try { return await Promise.race([read(), deadline]); }
    finally { clearTimeout(timer); }
  };
}

function waitForStopped(runtime) {
  if (runtime.getState().run.status === 'stopped') return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { unsubscribe(); reject(new Error('Runtime did not stop')); }, 5000);
    const unsubscribe = runtime.subscribe(state => {
      if (state.run.status !== 'stopped') return;
      clearTimeout(timer);
      unsubscribe();
      resolve();
    });
  });
}

test('the local API serves static UI and exposes the same runtime state envelope', async t => {
  const { runtime, base } = await serve(t);
  const home = await fetch(`${base}/`);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /CA3P/);
  const { response, body } = await getJson(`${base}/api/state`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.deepEqual(body, runtime.getState());
  const started = await getJson(`${base}/api/runs`, jsonPost({ target: 'https://metadata-only.invalid', delayMs: 0 }));
  assert.equal(started.response.ok, true);
  assert.equal(started.body.mode, 'core-fixture');
  assert.equal(started.body.run.target, 'https://metadata-only.invalid/');
  assert.equal(started.body.run.targetContacted, false);
});

test('the API rejects invalid input, oversized JSON, unsupported methods, and unknown routes', async t => {
  const { runtime, base } = await serve(t);
  const idle = runtime.getState();
  const cases = [
    ['/api/runs', jsonPost({ target: 'not a URL' }), 400],
    ['/api/runs', jsonPost({ target: 'https://metadata-only.invalid', delayMs: -1 }), 400],
    ['/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{broken' }, 400],
    ['/api/runs', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' }, 415],
    ['/api/runs', { method: 'POST', body: '{}' }, 415],
    ['/api/runs', jsonPost({ target: 'https://metadata-only.invalid', gateway: {} }), 400],
    ['/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: `https://metadata-only.invalid/${'x'.repeat(8192)}` }) }, 413],
    ['/api/state', { method: 'POST' }, 405],
    ['/api/runs', { method: 'GET' }, 405],
    ['/api/missing', undefined, 404],
  ];
  for (const [path, options, expected] of cases) {
    const response = await fetch(`${base}${path}`, options);
    assert.equal(response.status, expected, `${options?.method ?? 'GET'} ${path}`);
    await response.text();
    assert.deepEqual(runtime.getState(), idle, 'Rejected requests must leave the runtime unchanged');
  }
});

test('cross-origin requests and non-local Host values cannot read or mutate the local API', async t => {
  const { runtime, base } = await serve(t);
  const idle = runtime.getState();
  for (const path of ['/api/state', '/api/events']) {
    const response = await fetch(`${base}${path}`, { headers: { Origin: 'https://untrusted.invalid' } });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    await response.text();
  }
  const externalOrigin = await fetch(`${base}/api/runs`, jsonPost({ target: 'https://metadata-only.invalid' }, {
    headers: { 'Content-Type': 'application/json', Origin: 'https://untrusted.invalid' },
  }));
  assert.equal(externalOrigin.status, 403);
  await externalOrigin.text();
  assert.equal(await statusWithHostHeader(`${base}/api/state`, 'untrusted.invalid'), 403);
  assert.deepEqual(runtime.getState(), idle);
  const sameOrigin = await fetch(`${base}/api/state`, { headers: { Origin: base } });
  assert.equal(sameOrigin.status, 200);
  await sameOrigin.text();
});

test('SSE sends an initial snapshot and live core events through completion', async t => {
  const { runtime, base } = await serve(t);
  const controller = new AbortController();
  const response = await fetch(`${base}/api/events`, { signal: controller.signal });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/event-stream/);
  assert.match(response.headers.get('cache-control'), /no-store/);
  const reader = response.body.getReader();
  t.after(async () => {
    controller.abort();
    await reader.cancel().catch(() => {});
  });
  const nextState = readStateEvents(reader);
  assert.deepEqual(await nextState(), runtime.getState());
  const started = await getJson(`${base}/api/runs`, jsonPost({ target: 'https://metadata-only.invalid', delayMs: 0 }));
  assert.equal(started.response.ok, true);
  const seen = [];
  let final;
  for (let index = 0; index < 100; index += 1) {
    const state = await nextState();
    assert.equal(state.instanceId, started.body.instanceId);
    assert.equal(state.mode, 'core-fixture');
    seen.push(state);
    if (['completed', 'failed'].includes(state.run?.status)) {
      final = state;
      break;
    }
  }
  assert.ok(final, 'The stream must deliver a terminal state');
  assert.equal(final.run.status, 'completed');
  assert.equal(final.run.events.length, 25);
  assert.equal(final.run.targetContacted, false);
  assert.ok(seen.some(state => state.run?.status === 'running' && state.run.events.length > 0));
  assert.deepEqual(final, runtime.getState());
  controller.abort();
  await reader.cancel().catch(() => {});
});

test('API stop cancels an active run, while active replacement and reset return conflict', async t => {
  const { runtime, base } = await serve(t, { delayMs: 100 });
  const started = await getJson(`${base}/api/runs`, jsonPost({ target: 'https://metadata-only.invalid' }));
  assert.equal(started.response.ok, true);
  for (const [path, payload] of [['/api/runs', { target: 'https://second.invalid' }], ['/api/reset', {}]]) {
    const response = await fetch(`${base}${path}`, jsonPost(payload));
    assert.equal(response.status, 409);
    await response.text();
  }
  const stopped = await getJson(`${base}/api/runs/${encodeURIComponent(started.body.run.id)}/stop`, jsonPost({}));
  assert.equal(stopped.response.ok, true);
  assert.ok(['stopping', 'stopped'].includes(stopped.body.run.status));
  await waitForStopped(runtime);
  assert.equal(runtime.getState().run.status, 'stopped');
  assert.ok(runtime.getState().run.events.length < 25);
  const reset = await getJson(`${base}/api/reset`, jsonPost({}));
  assert.equal(reset.response.ok, true);
  assert.ok(!reset.body.run || reset.body.run.status === 'idle');
});

test('shutdown ends an active SSE stream and awaits cancellation before closing the server', { timeout: 10000 }, async t => {
  const { runtime, server, base } = await serve(t, { delayMs: 150 });
  const controller = new AbortController();
  const response = await fetch(`${base}/api/events`, { signal: controller.signal });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  t.after(async () => {
    controller.abort();
    await reader.cancel().catch(() => {});
  });
  const nextState = readStateEvents(reader);
  await nextState();
  const started = await getJson(`${base}/api/runs`, jsonPost({ target: 'https://metadata-only.invalid' }));
  assert.equal(started.response.status, 201);
  for (;;) {
    const state = await nextState();
    if (state.run?.status === 'running' && state.run.events.length > 0) break;
  }
  assert.equal(server.listening, true);
  assert.equal(runtime.getState().run.status, 'running');

  const shutdown = server.shutdown();
  let streamEnded = false;
  const consumeUntilEnd = async () => {
    for (;;) {
      const { done } = await reader.read();
      if (done) { streamEnded = true; return; }
    }
  };
  await Promise.all([shutdown, consumeUntilEnd()]);
  assert.equal(streamEnded, true, 'Shutdown must end the stream without client cancellation');
  assert.equal(server.listening, false);
  const final = runtime.getState();
  assert.equal(final.run.status, 'stopped');
  assert.ok(final.run.events.length > 0);
  assert.ok(final.run.events.length < 19);
  assert.equal(final.run.targetContacted, false);
  assert.equal(final.run.report.status, 'failed');
  assert.throws(() => runtime.start({ target: 'https://metadata-only.invalid' }), error => error.status === 503);
});
