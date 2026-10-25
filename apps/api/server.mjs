import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { createLocalRuntime } from '../application/local-runtime.mjs';
import { createAuthentication } from './auth.mjs';
import { getPlatform } from './platform.mjs';
import { reviewRunCheck } from '../../packages/history/check-sync.mjs';
import { redact } from '../../packages/contracts/index.mjs';

const root = fileURLToPath(new URL('../../agent-dashboard/dist/', import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const MAX_BODY = 8192;
const headers = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

function error(status, message) { return Object.assign(new Error(message), { status }); }
function json(res, status, data, extra = {}) {
  res.writeHead(status, { ...headers, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(redact(data)));
}

function reportFilename(value) {
  const name = String(value ?? 'ca3p-report.hwpx').toWellFormed().normalize('NFC')
    .replace(/[<>:"/\\|?*\u0000-\u001f\u007f]/g, '-').replace(/^[. ]+|[. ]+$/g, '');
  const stem = Array.from(name.replace(/\.hwpx$/i, '')).slice(0, 150).join('') || 'ca3p-report';
  return `${stem}.hwpx`;
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

export function createDashboardServer({ runtime = createLocalRuntime(), auth = createAuthentication({ enabled: false }), publicOrigins = [], platformProvider = getPlatform, ciResults = null } = {}) {
  const configured = publicOrigins.map(value => new URL(value));
  if (configured.some(url => url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/')) throw new Error('Public origins must be plain HTTPS origins.');
  if (configured.length && !auth.enabled) throw new Error('External dashboard access requires authentication.');
  const streams = new Set();
  const server = http.createServer(async (req, res) => {
    try {
      const port = server.address()?.port;
      const publicUrl = configured.find(url => url.host === req.headers.host);
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(req.headers.host) && !publicUrl) throw error(403, 'Use a loopback Host header.');
      const expectedOrigin = publicUrl?.origin ?? `http://${req.headers.host}`;
      const pathname = decodeURIComponent(new URL(req.url, expectedOrigin).pathname);
      if (['/healthz', '/api/health'].includes(pathname) && req.method === 'GET') return json(res, 200, { status: 'ok' });
      if (pathname.startsWith('/api/')) {
        if (req.headers.origin && req.headers.origin !== expectedOrigin) throw error(403, 'Cross-origin API access is not allowed.');
        if (req.headers['sec-fetch-site'] === 'cross-site') throw error(403, 'Cross-site API access is not allowed.');
        if (pathname === '/api/auth/session' && req.method === 'GET') return json(res, 200, auth.describe(req));
        if (pathname === '/api/auth/login' && req.method === 'POST') {
          const result = auth.login(req, await readJson(req), { secure: Boolean(publicUrl) });
          return json(res, 200, result.body, result.cookie ? { 'Set-Cookie': result.cookie } : {});
        }
        if (pathname === '/api/auth/logout' && req.method === 'POST') return json(res, 200, { authenticated: false }, { 'Set-Cookie': auth.logout(req) });
        const currentUser = auth.requireUser(req, { mutate: !['GET', 'HEAD'].includes(req.method) });
        const review = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/reviews\/([a-zA-Z0-9._-]+)$/.exec(pathname);
        if (review && req.method === 'POST') {
          const run = await runtime.getRun?.(review[1]);
          if (!run?.historyWrite?.checks?.some(check => check.check_id === review[2])) throw error(404, 'Run check not found.');
          const body = await readJson(req);
          if (!body || Object.keys(body).some(key => key !== 'note')) throw error(400, 'Provide a review note.');
          const check = await reviewRunCheck(review[2], { reviewer: currentUser.user.name, note: body.note,
            databasePath: run.manifest?.data?.caseDatabaseSourcePath,
            evidenceRoot: runtime.store?.path ? resolve(runtime.store.path, '..', 'artifacts') : undefined });
          runtime.store?.recordReview(run.id, check);
          return json(res, 200, { check });
        }
        const artifactMatch = /^\/api\/artifacts\/([a-f0-9]{64})$/.exec(pathname);
        if (artifactMatch && req.method === 'GET') {
          const artifact = runtime.store?.getArtifact(artifactMatch[1]);
          if (!artifact) throw error(404, 'Artifact not found.');
          if (artifact.kind === 'hwpx-report') throw error(404, 'Use the run report download.');
          const data = await readFile(artifact.path);
          if (createHash('sha256').update(data).digest('hex') !== artifact.sha256) throw error(409, 'Artifact integrity check failed.');
          // Stored evidence is immutable. Refuse legacy files that would require
          // redaction instead of silently changing their verified SHA-256 bytes.
          let parsed;
          try { parsed = JSON.parse(data.toString('utf8')); } catch { throw error(409, 'Artifact is not valid JSON.'); }
          if (JSON.stringify(redact(parsed)) !== JSON.stringify(parsed)) throw error(409, 'Artifact contains sensitive fields.');
          res.writeHead(200, { ...headers, 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="${artifact.id}.json"` });
          return res.end(data);
        }
        const reportMatch = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/report\.hwpx$/.exec(pathname);
        if (reportMatch && req.method === 'GET') {
          const run = await (runtime.store?.getRun?.(reportMatch[1]) ?? runtime.getRun?.(reportMatch[1]));
          if (!run) throw error(404, 'Run not found.');
          const document = run.reportDocument;
          if (document?.status !== 'ready') throw error(409, 'The HWPX report is not ready.');
          const artifact = typeof document.artifactId === 'string' && /^[a-f0-9]{64}$/.test(document.artifactId)
            ? runtime.store?.getArtifact(document.artifactId) : null;
          if (!artifact || artifact.runId !== run.id || artifact.kind !== 'hwpx-report') throw error(404, 'Report artifact not found.');
          const data = await readFile(artifact.path);
          if (data.length !== artifact.size || createHash('sha256').update(data).digest('hex') !== artifact.sha256) {
            throw error(409, 'Report integrity check failed.');
          }
          const filename = reportFilename(artifact.filename ?? document.filename);
          const encoded = encodeURIComponent(filename).replace(/['()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
          res.writeHead(200, { ...headers, 'Content-Type': 'application/hwp+zip', 'Content-Length': data.length,
            'Content-Disposition': `attachment; filename="ca3p-report.hwpx"; filename*=UTF-8''${encoded}` });
          return res.end(data);
        }
        if (pathname === '/api/platform' && req.method === 'GET') return json(res, 200, await platformProvider());
        if (pathname === '/api/ci-results' && req.method === 'GET') return json(res, 200,
          ciResults?.getSnapshot?.() ?? { source: 'none', status: 'unavailable', updatedAt: null, lastAttemptAt: null, runs: [] });
        if (pathname === '/api/models' && req.method === 'GET') return json(res, 200, { models: await runtime.listModels?.() ?? [] });
        if (pathname === '/api/comparisons' && req.method === 'GET') {
          const params = new URL(req.url, expectedOrigin).searchParams;
          if (!params.get('baseline') || !params.get('candidate')) throw error(400, 'Select baseline and candidate runs.');
          if (!runtime.compareRuns) throw error(503, 'Comparison service unavailable.');
          const kind = params.get('kind') ?? 'code';
          if (!['code', 'model', 'prompt', 'environment'].includes(kind)) throw error(400, 'Unsupported comparison kind.');
          return json(res, 200, await runtime.compareRuns(params.get('baseline'), params.get('candidate'), { kind }));
        }
        if (pathname === '/api/runs' && req.method === 'GET') {
          const params = new URL(req.url, expectedOrigin).searchParams;
          const limit = params.has('limit') ? Number(params.get('limit')) : 50;
          const offset = params.has('offset') ? Number(params.get('offset')) : 0;
          if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw error(400, 'limit must be between 1 and 200.');
          if (!Number.isSafeInteger(offset) || offset < 0) throw error(400, 'offset must be a non-negative integer.');
          const runs = await runtime.listRuns?.({ limit, offset, status: params.get('status') ?? undefined }) ?? [];
          return json(res, 200, Array.isArray(runs) ? { runs } : { ...runs, runs: runs.runs ?? runs.items ?? [] });
        }
        const detail = /^\/api\/runs\/([a-zA-Z0-9_-]+)(?:\/(export|events))?$/.exec(pathname);
        if (detail && req.method === 'GET') {
          const run = await runtime.getRun?.(detail[1]);
          if (!run) throw error(404, 'Run not found.');
          if (detail[2] === 'events') {
            const after = Number(new URL(req.url, expectedOrigin).searchParams.get('after') ?? 0);
            if (!Number.isSafeInteger(after) || after < 0) throw error(400, 'Invalid event cursor.');
            return json(res, 200, { events: (run.events ?? []).filter(event => (event.sequence ?? 0) > after), runId: run.id });
          }
          return json(res, 200, detail[2] === 'export' ? run : { run }, detail[2] === 'export' ? { 'Content-Disposition': `attachment; filename="${run.id}.json"` } : {});
        }
        if (pathname === '/api/state' || pathname === '/api/events') {
          if (req.method !== 'GET') return json(res, 405, { error: 'Use GET.' }, { Allow: 'GET' });
          if (pathname === '/api/state') return json(res, 200, runtime.getState());
          if (streams.size >= 20) throw error(429, 'Too many local event streams.');
          res.writeHead(200, { ...headers, 'Content-Type': 'text/event-stream; charset=utf-8', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
          res.flushHeaders();
          const send = state => {
            if (!auth.describe(req).authenticated) { res.end(); return; }
            if (!res.writableEnded && !res.destroyed) res.write(`event: state\ndata: ${JSON.stringify(redact(state))}\n\n`);
          };
          const unsubscribe = runtime.subscribe(send);
          streams.add(res);
          send(runtime.getState());
          const heartbeat = setInterval(() => {
            if (!auth.describe(req).authenticated) return res.end();
            if (!res.writableEnded && !res.destroyed) res.write(': heartbeat\n\n');
          }, 15000);
          heartbeat.unref();
          res.on('close', () => { clearInterval(heartbeat); unsubscribe(); streams.delete(res); });
          return;
        }
        const stop = /^\/api\/runs\/([^/]+)\/(?:stop|cancel)$/.exec(pathname);
        if (pathname !== '/api/runs' && pathname !== '/api/lab-runs' && pathname !== '/api/reset' && !stop) throw error(404, 'API route not found.');
        if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
        const body = await readJson(req);
        if (pathname === '/api/runs') return json(res, runtime.listRuns ? 202 : 201, await runtime.start(body));
        if (pathname === '/api/lab-runs') {
          if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['modelId', 'fixtureId', 'target'].includes(key))) throw error(400, 'Only modelId, fixtureId and target are accepted.');
          return json(res, runtime.listRuns ? 202 : 201, await runtime.startLab(body));
        }
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) throw error(400, 'Provide an empty JSON object.');
        return json(res, 200, await (stop ? runtime.stop(stop[1]) : runtime.reset()));
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
  const closeRuntime = () => runtimeCloseTask ??= Promise.all([runtime.close(), ciResults?.close?.()]);
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
