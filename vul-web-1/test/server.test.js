'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const test = require('node:test');

const appDir = path.resolve(__dirname, '..');

async function availablePort() {
  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.kill();
  const forceKill = setTimeout(() => child.kill('SIGKILL'), 3000);
  forceKill.unref();
  await exited;
  clearTimeout(forceKill);
}

test('stored XSS payload and forged authorId deletion are reproducible', async t => {
  const temporaryDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulnerable-board-test-'));
  let child;
  t.after(async () => {
    if (child) await stopProcess(child);
    await fs.rm(temporaryDir, { recursive: true, force: true });
  });

  const port = await availablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const dataFile = path.join(temporaryDir, 'board.json');
  const serverFile = path.join(appDir, 'server.js');
  await fs.access(serverFile);

  let serverOutput = '';
  let startupError;
  child = spawn(process.execPath, [serverFile], {
    cwd: appDir,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      BOARD_DATA_FILE: dataFile,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', chunk => { serverOutput = (serverOutput + chunk).slice(-4000); });
  }
  child.on('error', error => { startupError = error; });

  let sessionResponse;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (startupError) throw startupError;
    if (child.exitCode !== null) throw new Error(`Server exited early (${child.exitCode}): ${serverOutput}`);
    try {
      const response = await fetch(`${baseUrl}/api/session`);
      if (response.ok) {
        sessionResponse = response;
        break;
      }
    } catch { /* The listener may not be ready yet. */ }
    await delay(100);
  }
  assert.ok(sessionResponse, `Server did not start: ${serverOutput}`);
  assert.equal((await sessionResponse.json()).user.id, 'alice');

  const setCookie = sessionResponse.headers.get('set-cookie');
  assert.ok(setCookie, 'The default session must set a cookie');
  const aliceCookie = setCookie.split(';', 1)[0];
  assert.ok(aliceCookie.includes('='));

  const switchResponse = await fetch(`${baseUrl}/api/session`, {
    method: 'POST',
    headers: { Cookie: aliceCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: 'bob' }),
  });
  assert.equal(switchResponse.status, 200);
  assert.equal((await switchResponse.json()).user.id, 'bob');
  const bobCookie = switchResponse.headers.get('set-cookie')?.split(';', 1)[0];
  assert.ok(bobCookie && bobCookie !== aliceCookie);
  const bobSession = await fetch(`${baseUrl}/api/session`, { headers: { Cookie: bobCookie } });
  assert.equal((await bobSession.json()).user.id, 'bob');

  async function api(method, route, body) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: {
        Cookie: aliceCookie,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const responseBody = await response.text();
    return {
      status: response.status,
      data: responseBody ? JSON.parse(responseBody) : null,
    };
  }

  const initial = await api('GET', '/api/posts');
  assert.equal(initial.status, 200);
  assert.ok(Array.isArray(initial.data.posts));
  const adminPost = initial.data.posts.find(post => post.authorId === 'admin');
  assert.ok(adminPost, 'A seeded admin post is required');

  const payload = '<img src=x onerror=alert(1)>';
  const created = await api('POST', '/api/posts', {
    title: 'XSS demonstration',
    content: payload,
  });
  assert.ok(created.status >= 200 && created.status < 300, JSON.stringify(created));
  const ownPost = created.data?.post ?? created.data;
  assert.ok(ownPost?.id, 'The created post response must include its id');
  assert.equal(ownPost.authorId, 'alice');

  const afterCreate = await api('GET', '/api/posts');
  assert.equal(afterCreate.status, 200);
  assert.equal(afterCreate.data.posts.find(post => String(post.id) === String(ownPost.id))?.content, payload);

  const denied = await api('DELETE', `/api/posts/${encodeURIComponent(ownPost.id)}?authorId=bob`);
  assert.ok(denied.status >= 400 && denied.status < 500, JSON.stringify(denied));

  const ownDeletion = await api('DELETE', `/api/posts/${encodeURIComponent(ownPost.id)}?authorId=alice`);
  assert.ok(ownDeletion.status >= 200 && ownDeletion.status < 300, JSON.stringify(ownDeletion));
  const afterOwnDelete = await api('GET', '/api/posts');
  assert.equal(afterOwnDelete.data.posts.some(post => String(post.id) === String(ownPost.id)), false);

  // The same Alice cookie is still in use; only the authorId query parameter changes.
  const forgedDeletion = await api('DELETE', `/api/posts/${encodeURIComponent(adminPost.id)}?authorId=admin`);
  assert.ok(forgedDeletion.status >= 200 && forgedDeletion.status < 300, JSON.stringify(forgedDeletion));
  const afterForgedDelete = await api('GET', '/api/posts');
  assert.equal(afterForgedDelete.data.posts.some(post => String(post.id) === String(adminPost.id)), false);
});
