import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntimeClient } from '../dist/runtime-client.js';

const envelope = { instanceId: 'server-a', mode: 'local-lab-rule', run: { id: 'run-a', mode: 'local-lab-rule', events: [] }, lab: {} };
const session = { authenticated: true, authRequired: true, user: { name: 'Operator', role: 'operator' }, csrfToken: 'csrf-a' };
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

test('remote deployment defaults to polling, forwards CSRF, and requests a selected real lab model', async t => {
  const calls = []; const states = []; const connections = []; let streams = 0;
  const client = createRuntimeClient({ hostname: 'workspace.trycloudflare.com', pollIntervalMs: 10,
    onState: value => states.push(value), onConnection: (...args) => connections.push(args), onError: assert.fail,
    EventSourceImpl: class { constructor() { streams += 1; } },
    fetchImpl: async (path, options) => {
      calls.push({ path, options });
      if (path === '/api/auth/session') return response(session);
      if (path.startsWith('/api/comparisons')) return response({ compatible: true });
      return response(envelope);
    },
  });
  t.after(() => client.close());
  await client.connect();
  await pause(35);
  assert.equal(streams, 0);
  assert.ok(calls.filter(call => call.path === '/api/state').length >= 3);
  assert.ok(connections.some(([state, transport]) => state === 'connected' && transport === 'polling'));
  await client.startLab('rule-baseline', 'local-lab-rule');
  const start = calls.find(call => call.path === '/api/runs');
  assert.deepEqual(JSON.parse(start.options.body), { mode: 'local-lab-rule', modelId: 'rule-baseline' });
  assert.equal(start.options.headers['X-CSRF-Token'], 'csrf-a');
  await client.compare('baseline /?', 'candidate #');
  assert.equal(client.reportDownloadUrl('run /?#'), '/api/runs/run%20%2F%3F%23/report.hwpx');
  const comparison = calls.find(call => call.path.startsWith('/api/comparisons'));
  assert.equal(new URL(comparison.path, 'http://test').searchParams.get('baseline'), 'baseline /?');
  client.close(); const count = calls.length; await pause(30); assert.equal(calls.length, count);
  assert.ok(states.every(value => value.mode === 'local-lab-rule'));
});

test('local SSE failure activates polling and unauthorized polling stops retries', async t => {
  let source; let failAuthentication = false; let authRequests = 0; const calls = [];
  class Source { constructor() { source = this; } addEventListener() {} close() { this.closed = true; } }
  const client = createRuntimeClient({ hostname: '127.0.0.1', EventSourceImpl: Source, pollIntervalMs: 10,
    onState() {}, onConnection() {}, onError: assert.fail, onAuthRequired() { authRequests += 1; },
    fetchImpl: async path => {
      calls.push(path);
      if (path === '/api/auth/session') return response(session);
      return failAuthentication ? response({ error: 'Login required' }, 401) : response(envelope);
    },
  });
  t.after(() => client.close());
  await client.connect(); assert.ok(source); source.onerror();
  await pause(20); assert.equal(source.closed, true);
  failAuthentication = true; await pause(30);
  assert.equal(authRequests, 1); const count = calls.length; await pause(30); assert.equal(calls.length, count);
});

test('anonymous session shows login without polling; login obtains the rotated CSRF token', async t => {
  let loggedIn = false; let authRequests = 0; const calls = [];
  const client = createRuntimeClient({ hostname: 'remote.example', pollIntervalMs: 20,
    onState() {}, onConnection() {}, onError: assert.fail, onAuthRequired() { authRequests += 1; },
    fetchImpl: async (path, options) => {
      calls.push({ path, options });
      if (path === '/api/auth/session') return response(loggedIn ? session : { authenticated: false, authRequired: true, csrfToken: 'csrf-anonymous' });
      if (path === '/api/auth/login') { assert.equal(options.headers['X-CSRF-Token'], 'csrf-anonymous'); loggedIn = true; return response({ authenticated: true }); }
      return response(envelope);
    },
  });
  t.after(() => client.close());
  await client.connect(); assert.equal(authRequests, 1); assert.equal(calls.length, 1);
  await client.login('operator', 'test-password'); await client.start('https://display.invalid', 0);
  const start = calls.find(call => call.path === '/api/runs'); assert.equal(start.options.headers['X-CSRF-Token'], 'csrf-a');
});

test('initial temporary API failure retries connection and recovers polling', async t => {
  let stateCalls = 0; const errors = []; const states = [];
  const client = createRuntimeClient({ hostname: 'remote.example', pollIntervalMs: 10,
    onState: value => states.push(value), onConnection() {}, onError: message => errors.push(message),
    fetchImpl: async path => {
      if (path === '/api/auth/session') return response(session);
      stateCalls += 1;
      return stateCalls === 1 ? response({ error: 'Temporarily unavailable' }, 503) : response(envelope);
    },
  });
  t.after(() => client.close());
  await client.connect(); await pause(35);
  assert.equal(errors[0], 'Temporarily unavailable'); assert.ok(states.length > 0); assert.ok(stateCalls >= 3);
});
