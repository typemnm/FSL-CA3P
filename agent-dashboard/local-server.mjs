import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { createLocalRuntime } from './local-runtime.mjs';

const root = fileURLToPath(new URL('./dist/', import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const MAX_BODY = 8192;
const headers = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

function error(status, message) { return Object.assign(new Error(message), { status }); }
function json(res, status, data, extra = {}) {
  res.writeHead(status, { ...headers, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw error(415, 'Use application/json.');
  if (Number(req.headers['content-length']) > MAX_BODY) { req.resume(); throw error(413, 'Request body exceeds 8192 bytes.'); }
  return new Promise((resolveBody, reject) => {
    let bytes = 0;
    const chunks = [];
    const cleanup = () => {
      req.removeListener('data', data);
      req.removeListener('end', end);
      req.removeListener('error', rejectRequest);
      req.removeListener('aborted', aborted);
    };
    const rejectRequest = failure => { cleanup(); reject(failure); };
    const aborted = () => rejectRequest(error(400, 'Request aborted.'));
    const data = chunk => {
      bytes += chunk.length;
      if (bytes > MAX_BODY) { cleanup(); req.resume(); reject(error(413, 'Request body exceeds 8192 bytes.')); }
      else chunks.push(chunk);
    };
    const end = () => {
      cleanup();
      try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(error(400, 'Provide valid JSON.')); }
    };
    req.on('data', data).on('end', end).on('error', rejectRequest).on('aborted', aborted);
  });
}

export function createDashboardServer({ runtime = createLocalRuntime() } = {}) {
  const streams = new Set();
  const server = http.createServer(async (req, res) => {
    try {
      const port = server.address()?.port;
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(req.headers.host)) throw error(403, 'Use a loopback Host header.');
      const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      if (pathname.startsWith('/api/')) {
        if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) throw error(403, 'Cross-origin API access is not allowed.');
        if (req.headers['sec-fetch-site'] === 'cross-site') throw error(403, 'Cross-site API access is not allowed.');
        if (pathname === '/api/state' || pathname === '/api/events') {
          if (req.method !== 'GET') return json(res, 405, { error: 'Use GET.' }, { Allow: 'GET' });
          if (pathname === '/api/state') return json(res, 200, runtime.getState());
          if (streams.size >= 20) throw error(429, 'Too many local event streams.');
          res.writeHead(200, { ...headers, 'Content-Type': 'text/event-stream; charset=utf-8', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
          res.flushHeaders();
          const send = state => {
            if (!res.writableEnded && !res.destroyed) res.write(`event: state\ndata: ${JSON.stringify(state)}\n\n`);
          };
          const unsubscribe = runtime.subscribe(send);
          streams.add(res);
          send(runtime.getState());
          const heartbeat = setInterval(() => {
            if (!res.writableEnded && !res.destroyed) res.write(': heartbeat\n\n');
          }, 15000);
          heartbeat.unref();
          res.on('close', () => { clearInterval(heartbeat); unsubscribe(); streams.delete(res); });
          return;
        }
        const stop = /^\/api\/runs\/([^/]+)\/stop$/.exec(pathname);
        if (pathname !== '/api/runs' && pathname !== '/api/lab-runs' && pathname !== '/api/reset' && !stop) throw error(404, 'API route not found.');
        if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
        const body = await readJson(req);
        if (pathname === '/api/runs') return json(res, 201, runtime.start(body));
        if (pathname === '/api/lab-runs') {
          if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) throw error(400, 'Provide an empty JSON object.');
          return json(res, 201, await runtime.startLab());
        }
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) throw error(400, 'Provide an empty JSON object.');
        return json(res, 200, stop ? runtime.stop(stop[1]) : runtime.reset());
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { ...headers, Allow: 'GET, HEAD' });
        return res.end();
      }
      const file = resolve(root, `.${pathname === '/' ? '/index.html' : pathname}`);
      if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) throw error(403, 'Forbidden');
      const data = await readFile(file);
      res.writeHead(200, { ...headers, 'Content-Type': mime[extname(file)] || 'application/octet-stream' });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch (failure) {
      if (res.headersSent) return res.end();
      const status = failure.status ?? (['ENOENT', 'EISDIR'].includes(failure.code) ? 404 : 400);
      json(res, status, { error: failure.status ? failure.message : status === 404 ? 'Not found.' : 'Invalid request.' });
    }
  });
  let runtimeCloseTask;
  const closeRuntime = () => runtimeCloseTask ??= runtime.close();
  server.on('close', () => { for (const stream of streams) stream.end(); void closeRuntime(); });
  let shutdownTask;
  server.shutdown = () => {
    shutdownTask ??= (async () => {
      // Stop accepting EventSource reconnects before waiting for the lab child.
      const serverClosed = server.listening
        ? new Promise((resolveClose, rejectClose) => server.close(error => error ? rejectClose(error) : resolveClose()))
        : Promise.resolve();
      for (const stream of streams) stream.end();
      try { await closeRuntime(); }
      finally {
        server.closeAllConnections?.();
        await serverClosed;
      }
    })();
    return shutdownTask;
  };
  return server;
}
