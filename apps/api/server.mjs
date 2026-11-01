import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { createAuthentication } from './auth.mjs';
import { getPlatform } from './platform.mjs';
import { createModuleManagement } from './module-management.mjs';
import { createDbManagement } from './db-management.mjs';
import { preflightExternalTarget } from '../application/external-target.mjs';
import { reviewRunCheck } from '../../packages/history/check-sync.mjs';
import { redact } from '../../packages/contracts/index.mjs';
import { deploymentPaused, deploymentStatus } from './deployment.mjs';
import { createWorkspaceChatRoutes } from './workspace-chat-routes.mjs';
import { createAttackTemplateRoutes } from './attack-template-routes.mjs';

const root = fileURLToPath(new URL('../../agent-dashboard/dist/', import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const MAX_BODY = 8192;
const GENERAL_REPORT_DOCUMENTS_SCHEMA_VERSION = 'general-report-documents/1';
const headers = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

function error(status, message) { return Object.assign(new Error(message), { status }); }
function json(res, status, data, extra = {}, { preserveSource = false } = {}) {
  res.writeHead(status, { ...headers, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(preserveSource ? data : redact(data)));
}

function reportFilename(value) {
  const name = String(value ?? 'ca3p-report.hwpx').toWellFormed().normalize('NFC')
    .replace(/[<>:"/\\|?*\u0000-\u001f\u007f]/g, '-').replace(/^[. ]+|[. ]+$/g, '');
  const stem = Array.from(name.replace(/\.hwpx$/i, '')).slice(0, 150).join('') || 'ca3p-report';
  return `${stem}.hwpx`;
}

async function sendHwpx(res, artifact, document) {
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

function readJson(req, maxBody = MAX_BODY) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw error(415, 'Use application/json.');
  if (Number(req.headers['content-length']) > maxBody) { req.resume(); throw error(413, 'Request body is too large.'); }
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
      if (bytes > maxBody) { cleanup(); req.resume(); reject(error(413, 'Request body is too large.')); }
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

export function createDashboardServer({ runtime, auth = createAuthentication({ enabled: false }), publicOrigins = [], platformProvider = getPlatform, ciResults = null,
  maintenanceCheck = deploymentPaused, deploymentStatusProvider = deploymentStatus, moduleManagement = null,
  dbManagement = null, targetPreflight = preflightExternalTarget, workspaceChat = null,
  templateCatalog = undefined } = {}) {
  if (!runtime) throw new TypeError('createDashboardServer requires a run service runtime.');
  const configured = publicOrigins.map(value => new URL(value));
  if (configured.some(url => url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/')) throw new Error('Public origins must be plain HTTPS origins.');
  if (configured.length && !auth.enabled) throw new Error('External dashboard access requires authentication.');
  const db = dbManagement ?? createDbManagement();
  const modules = moduleManagement ?? createModuleManagement({ runtime, platformProvider, dbManagement: db });
  const chatRoutes = createWorkspaceChatRoutes({ service: workspaceChat,
    runProvider: id => runtime.getRun?.(id), platformProvider });
  const templateRoutes = createAttackTemplateRoutes({ catalog: templateCatalog });
  let dbInit;
  let advisorySyncActive = false;
  const ensureDb = () => dbInit ??= Promise.resolve().then(() => db.bootstrap?.()).catch(failure => {
    dbInit = null;
    throw failure;
  });
  const streams = new Set();
  const preflightQuotas = new Map();
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
        if (!['GET', 'HEAD'].includes(req.method)) {
          let paused;
          try { paused = await maintenanceCheck(); }
          catch {
            return json(res, 503, { error: '배포 상태를 확인할 수 없습니다. 잠시 후 다시 실행하세요.' }, { 'Retry-After': '30' });
          }
          if (paused) return json(res, 503, { error: '배포를 적용하고 있습니다. 잠시 후 다시 실행하세요.' }, { 'Retry-After': '30' });
        }
        if (pathname === '/api/deployment' && req.method === 'GET') return json(res, 200, await deploymentStatusProvider());
        if (await chatRoutes.handle({ req, res, pathname, origin: expectedOrigin, currentUser, json, readJson })) return;
        if (await templateRoutes.handle({ req, res, pathname, origin: expectedOrigin, auth, json, readJson })) return;
        if (pathname === '/api/targets/preflight') {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body) || body.authorizationConfirmed !== true) {
            throw error(400, 'Confirm authorization before contacting an external target.');
          }
          const actor = currentUser.user.name;
          const now = Date.now();
          let quota = preflightQuotas.get(actor);
          if (!quota || now - quota.startedAt >= 60_000) {
            quota = { startedAt: now, count: 0, active: false };
            preflightQuotas.set(actor, quota);
          }
          if (quota.active || quota.count >= 10) {
            return json(res, 429, { error: '외부 대상 사전 점검 요청이 너무 많습니다. 잠시 후 다시 시도하세요.' },
              { 'Retry-After': String(Math.max(1, Math.ceil((60_000 - (now - quota.startedAt)) / 1000))) });
          }
          quota.count += 1;
          quota.active = true;
          try { return json(res, 200, await targetPreflight(body)); }
          finally { quota.active = false; }
        }
        if (pathname === '/api/db/status' && req.method === 'GET') {
          await ensureDb();
          return json(res, 200, await db.status());
        }
        if (pathname === '/api/db/settings') {
          await ensureDb();
          if (req.method === 'GET') return json(res, 200, await db.getSettings());
          if (req.method !== 'PATCH') return json(res, 405, { error: 'Use GET or PATCH.' }, { Allow: 'GET, PATCH' });
          auth.requireUser(req, { mutate: true, admin: true });
          const body = await readJson(req);
          if (!body || Array.isArray(body) || !body.settings || !Number.isInteger(body.expectedRevision)
            || Object.keys(body).some(key => !['settings', 'expectedRevision'].includes(key))) throw error(400, 'Invalid DB settings.');
          return json(res, 200, await db.saveSettings(body, currentUser.user.name));
        }
        if (['/api/db/advisories', '/api/db/advisories/matches'].includes(pathname) && req.method === 'GET') {
          await ensureDb();
          const params = new URL(req.url, expectedOrigin).searchParams;
          const query = Object.fromEntries(params);
          if (pathname.endsWith('/matches')) {
            if (Object.keys(query).some(key => !['targetId', 'ecosystem', 'package', 'version', 'cpe'].includes(key))) throw error(400, 'Invalid product query.');
            return json(res, 200, await db.queryAdvisories(query));
          }
          if (Object.keys(query).some(key => !['q', 'source', 'limit', 'offset'].includes(key))) throw error(400, 'Invalid advisory filters.');
          query.limit = params.has('limit') ? Number(params.get('limit')) : 50;
          query.offset = params.has('offset') ? Number(params.get('offset')) : 0;
          return json(res, 200, await db.listAdvisories(query));
        }
        if (pathname === '/api/db/advisories/sync') {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          if (advisorySyncActive) throw error(409, '외부 취약점 정보를 수집 중입니다. 완료 후 다시 시도하세요.');
          const body = await readJson(req);
          if (!body || Array.isArray(body) || Object.keys(body).some(key => !['targetId', 'ecosystem', 'package', 'version', 'cpe'].includes(key))) throw error(400, 'Invalid product query.');
          await ensureDb();
          advisorySyncActive = true;
          try { return json(res, 200, await db.syncAdvisories(body, currentUser.user.name)); }
          finally { advisorySyncActive = false; }
        }
        if (pathname === '/api/db/intakes') {
          await ensureDb();
          if (req.method === 'GET') {
            const params = new URL(req.url, expectedOrigin).searchParams;
            const filters = Object.fromEntries(['q', 'status', 'sort'].filter(key => params.has(key)).map(key => [key, params.get(key)]));
            filters.limit = params.has('limit') ? Number(params.get('limit')) : 50;
            filters.offset = params.has('offset') ? Number(params.get('offset')) : 0;
            return json(res, 200, await db.listIntakes(filters));
          }
          if (req.method === 'POST') {
            auth.requireUser(req, { mutate: true, admin: true });
            return json(res, 201, await db.stageUpload(req, { actor: currentUser.user.name }));
          }
          return json(res, 405, { error: 'Use GET or POST.' }, { Allow: 'GET, POST' });
        }
        const intakeAnalysis = /^\/api\/db\/intakes\/([a-f0-9]{64})\/analyze-local$/.exec(pathname);
        if (intakeAnalysis) {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          await ensureDb();
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body)
            || !/^[a-f0-9]{64}$/.test(body.expectedValidationSha)
            || Object.keys(body).some(key => key !== 'expectedValidationSha')) {
            throw error(400, 'Provide the current validation hash.');
          }
          return json(res, 200, await db.analyzeIntake(intakeAnalysis[1], body.expectedValidationSha,
            currentUser.user.name));
        }
        const intakePublish = /^\/api\/db\/intakes\/([a-f0-9]{64})\/publish$/.exec(pathname);
        if (intakePublish) {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          await ensureDb();
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body)
            || !/^[a-f0-9]{64}$/.test(body.expectedValidationSha)
            || Object.keys(body).some(key => !['readyOnly', 'expectedValidationSha'].includes(key))) {
            throw error(400, 'Invalid publish options.');
          }
          return json(res, 200, await db.publishIntake(intakePublish[1], body, currentUser.user.name));
        }
        const intake = /^\/api\/db\/intakes\/([a-f0-9]{64})$/.exec(pathname);
        if (intake) {
          await ensureDb();
          if (req.method === 'GET') return json(res, 200, await db.getIntake(intake[1]));
          auth.requireUser(req, { mutate: true, admin: true });
          if (req.method === 'PATCH') {
            const body = await readJson(req, 2_000_000);
            if (!body || typeof body !== 'object' || Array.isArray(body)
              || !/^[a-f0-9]{64}$/.test(body.expectedValidationSha)
              || !body.review || typeof body.review !== 'object' || Array.isArray(body.review)) {
              throw error(400, 'Provide a review and its current validation hash.');
            }
            return json(res, 200, await db.reviewIntake(intake[1], body.review,
              currentUser.user.name, body.expectedValidationSha));
          }
          if (req.method === 'DELETE') return json(res, 200, await db.deleteIntake(intake[1], currentUser.user.name));
          return json(res, 405, { error: 'Use GET, PATCH or DELETE.' }, { Allow: 'GET, PATCH, DELETE' });
        }
        if (pathname === '/api/db/cases' && req.method === 'GET') {
          await ensureDb();
          const params = new URL(req.url, expectedOrigin).searchParams;
          const filters = Object.fromEntries(['q', 'targetId', 'status', 'severity', 'vulnerabilityType', 'archived']
            .filter(key => params.has(key)).map(key => [key, params.get(key)]));
          if (params.has('archived')) {
            const archived = params.get('archived');
            if (!['true', 'false', 'all'].includes(archived)) throw error(400, 'Invalid archived filter.');
            filters.archived = archived === 'all' ? 'all' : archived === 'true';
          }
          filters.limit = params.has('limit') ? Number(params.get('limit')) : 50;
          filters.offset = params.has('offset') ? Number(params.get('offset')) : 0;
          if (!Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 200
            || !Number.isSafeInteger(filters.offset) || filters.offset < 0) throw error(400, 'Invalid case pagination.');
          return json(res, 200, await db.listCases(filters));
        }
        const caseVersions = /^\/api\/db\/cases\/([a-zA-Z0-9._:-]{1,160})\/versions$/.exec(pathname);
        if (caseVersions && req.method === 'GET') { await ensureDb(); return json(res, 200, await db.listCaseVersions(caseVersions[1])); }
        const caseRestore = /^\/api\/db\/cases\/([a-zA-Z0-9._:-]{1,160})\/restore$/.exec(pathname);
        if (caseRestore) {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          await ensureDb();
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) throw error(400, 'Provide an empty JSON object.');
          return json(res, 200, await db.restoreCase(caseRestore[1], currentUser.user.name));
        }
        const caseMatch = /^\/api\/db\/cases\/([a-zA-Z0-9._:-]{1,160})$/.exec(pathname);
        if (caseMatch) {
          await ensureDb();
          if (req.method === 'GET') return json(res, 200, await db.getCase(caseMatch[1]));
          auth.requireUser(req, { mutate: true, admin: true });
          if (req.method === 'PATCH') {
            const body = await readJson(req, 64_000);
            if (!body || typeof body !== 'object' || Array.isArray(body)
              || !body.patch || !Number.isInteger(body.expectedRevision)) throw error(400, 'Provide patch and expectedRevision.');
            return json(res, 200, await db.updateCase(caseMatch[1], body, currentUser.user.name));
          }
          if (req.method === 'DELETE') {
            const body = await readJson(req);
            if (!body || typeof body !== 'object' || Array.isArray(body)) throw error(400, 'Provide archive reason.');
            return json(res, 200, await db.archiveCase(caseMatch[1], body, currentUser.user.name));
          }
          return json(res, 405, { error: 'Use GET, PATCH or DELETE.' }, { Allow: 'GET, PATCH, DELETE' });
        }
        const review = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/reviews\/([a-zA-Z0-9._-]+)$/.exec(pathname);
        if (review && req.method === 'POST') {
          const body = await readJson(req);
          if (!body || Object.keys(body).some(key => key !== 'note')) throw error(400, 'Provide a review note.');
          const performReview = async () => {
            const run = await runtime.getRun?.(review[1]);
            if (!run?.historyWrite?.checks?.some(check => check.check_id === review[2])) throw error(404, 'Run check not found.');
            const check = await reviewRunCheck(review[2], { reviewer: currentUser.user.name, note: body.note,
              databasePath: run.manifest?.data?.caseDatabaseSourcePath,
              evidenceRoot: runtime.store?.path ? resolve(runtime.store.path, '..', 'artifacts') : undefined });
            runtime.store?.recordReview(run.id, check);
            return { check };
          };
          return json(res, 200, await (runtime.withMutationLock ? runtime.withMutationLock(performReview) : performReview()));
        }
        const approval = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/approvals\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})$/.exec(pathname);
        if (approval) {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body)
            || Object.keys(body).length !== 1 || !['approve', 'reject'].includes(body.decision)) {
            throw error(400, 'Provide an approval decision.');
          }
          if (typeof runtime.decideApproval !== 'function') throw error(503, 'Approval service is unavailable.');
          return json(res, 200, await runtime.decideApproval(approval[1], approval[2],
            body.decision, currentUser.user.name));
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
          return await sendHwpx(res, artifact, document);
        }
        const generalReportMatch = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/reports\/([a-f0-9]{64})\.hwpx$/.exec(pathname);
        if (generalReportMatch && req.method === 'GET') {
          const run = await (runtime.store?.getRun?.(generalReportMatch[1]) ?? runtime.getRun?.(generalReportMatch[1]));
          if (!run) throw error(404, 'Run not found.');
          if (run.report?.assessmentMode !== 'general') throw error(404, 'Report document not found.');
          const items = run.reportDocuments?.schemaVersion === GENERAL_REPORT_DOCUMENTS_SCHEMA_VERSION
            && Array.isArray(run.reportDocuments.items) ? run.reportDocuments.items : [];
          const linked = items.filter(item => item?.artifactId === generalReportMatch[2]);
          if (linked.length !== 1) throw error(404, 'Report document not found.');
          const [document] = linked;
          if (document.status !== 'ready') throw error(409, 'The HWPX report is not ready.');
          if (!Array.isArray(run.report?.findings)
            || !run.report.findings.some(finding => finding?.id === document.findingId && finding.status === 'confirmed')) {
            throw error(409, 'Report finding is not confirmed.');
          }
          const artifact = runtime.store?.getArtifact(generalReportMatch[2]);
          if (!artifact || artifact.runId !== run.id || artifact.kind !== 'hwpx-report'
            || artifact.findingId !== document.findingId || artifact.filename !== document.filename) {
            throw error(404, 'Report artifact not found.');
          }
          return await sendHwpx(res, artifact, document);
        }
        const previewMatch = /^\/api\/runs\/([a-zA-Z0-9_-]+)\/report-preview\/([a-zA-Z0-9][a-zA-Z0-9._:-]{0,71})$/.exec(pathname);
        if (previewMatch && req.method === 'GET') {
          const run = await (runtime.store?.getRun?.(previewMatch[1]) ?? runtime.getRun?.(previewMatch[1]));
          if (!run) throw error(404, 'Run not found.');
          const general = run.report?.assessmentMode === 'general';
          const document = general
            ? run.reportDocuments?.schemaVersion === GENERAL_REPORT_DOCUMENTS_SCHEMA_VERSION
              && Array.isArray(run.reportDocuments.items)
              ? run.reportDocuments.items.find(item => item?.findingId === previewMatch[2]) : null
            : previewMatch[2] === 'single' ? run.reportDocument : null;
          if (!document || document.status !== 'ready') throw error(404, 'Report preview not found.');
          if (general && (!Array.isArray(run.report?.findings)
            || !run.report.findings.some(finding => finding?.id === document.findingId && finding.status === 'confirmed'))) {
            throw error(409, 'Report finding is not confirmed.');
          }
          const htmlPreview = typeof document.previewHtmlArtifactId === 'string';
          const previewId = htmlPreview ? document.previewHtmlArtifactId : document.previewArtifactId;
          const artifact = typeof previewId === 'string' && /^[a-f0-9]{64}$/.test(previewId)
            ? runtime.store?.getArtifact(previewId) : null;
          if (!artifact || artifact.runId !== run.id
            || artifact.kind !== (htmlPreview ? 'report-preview-html' : 'report-preview')
            || (general && artifact.findingId !== document.findingId)
            || artifact.size > (htmlPreview ? 30_000_000 : 2_000_000)) throw error(404, 'Report preview not found.');
          const bytes = await readFile(artifact.path);
          if (bytes.length !== artifact.size || createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) {
            throw error(409, 'Report preview integrity check failed.');
          }
          let previewText;
          try { previewText = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
          catch { throw error(409, 'Report preview text is invalid.'); }
          return json(res, 200, { [htmlPreview ? 'html' : 'markdown']: previewText, filename: document.filename });
        }
        if (pathname === '/api/platform' && req.method === 'GET') return json(res, 200, await platformProvider());
        if (pathname === '/api/modules' && req.method === 'GET') return json(res, 200, await modules.list());
        if (pathname === '/api/modules/llm/loop-budget') {
          if (req.method === 'GET') return json(res, 200, await modules.loopBudget());
          if (req.method !== 'PUT') return json(res, 405, { error: 'Use GET or PUT.' }, { Allow: 'GET, PUT' });
          auth.requireUser(req, { mutate: true, admin: true });
          return json(res, 200, await modules.updateLoopBudget(await readJson(req)));
        }
        const moduleConfig = /^\/api\/modules\/([a-zA-Z0-9-]+)\/config$/.exec(pathname);
        if (moduleConfig) {
          if (req.method === 'GET') return json(res, 200, await modules.config(moduleConfig[1]));
          return json(res, 405, { error: 'This module has no live editable settings.' }, { Allow: 'GET' });
        }
        const moduleLogs = /^\/api\/modules\/([a-zA-Z0-9-]+)\/logs$/.exec(pathname);
        if (moduleLogs && req.method === 'GET') {
          const params = new URL(req.url, expectedOrigin).searchParams;
          const limit = params.has('limit') ? Number(params.get('limit')) : 100;
          const offset = params.has('offset') ? Number(params.get('offset')) : 0;
          return json(res, 200, await modules.logs(moduleLogs[1], { limit, offset, runId: params.get('runId') ?? undefined }));
        }
        if (pathname === '/api/ci-results' && req.method === 'GET') return json(res, 200,
          ciResults?.getSnapshot?.() ?? { source: 'none', status: 'unavailable', updatedAt: null, lastAttemptAt: null, runs: [] });
        if (pathname === '/api/models' && req.method === 'GET') return json(res, 200, { models: await runtime.listModels?.() ?? [] });
        if (pathname === '/api/experiment-reset') {
          if (req.method === 'GET') {
            if (!runtime.experimentResetPreview) throw error(503, 'Experiment reset is unavailable for this runtime.');
            return json(res, 200, await runtime.experimentResetPreview());
          }
          if (req.method !== 'POST') return json(res, 405, { error: 'Use GET or POST.' }, { Allow: 'GET, POST' });
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body) || body.confirmed !== true
            || Object.keys(body).some(key => key !== 'confirmed')) throw error(400, 'Confirm complete experiment deletion with confirmed: true.');
          if (!runtime.resetExperiment) throw error(503, 'Experiment reset is unavailable for this runtime.');
          return json(res, 200, await runtime.resetExperiment(body));
        }
        if (pathname === '/api/run-history/clear') {
          if (req.method !== 'POST') return json(res, 405, { error: 'Use POST.' }, { Allow: 'POST' });
          const body = await readJson(req);
          if (!body || typeof body !== 'object' || Array.isArray(body) || body.confirmed !== true
            || Object.keys(body).some(key => key !== 'confirmed')) throw error(400, 'Confirm run history deletion with confirmed: true.');
          if (!runtime.clearRunHistory) throw error(503, 'Run history clear is unavailable for this runtime.');
          return json(res, 200, await runtime.clearRunHistory(body));
        }
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
          if (Object.hasOwn(body, 'target') && !['vul-web2-daehan', 'vul-web2-wonchang'].includes(body.fixtureId)) {
            throw error(400, 'Only registered university fixtures accept a target origin.');
          }
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
      if (res.destroyed) return;
      if (res.headersSent) return res.end();
      const status = failure.status ?? (['ENOENT', 'EISDIR'].includes(failure.code) ? 404 : 400);
      json(res, status, { error: failure.status ? failure.message : status === 404 ? 'Not found.' : 'Invalid request.',
        ...(failure.details && typeof failure.code === 'string' ? { code: failure.code, details: failure.details } : {}) });
    }
  });
  let runtimeCloseTask;
  const closeRuntime = () => runtimeCloseTask ??= Promise.all([runtime.close(), ciResults?.close?.(), chatRoutes.close()]);
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
