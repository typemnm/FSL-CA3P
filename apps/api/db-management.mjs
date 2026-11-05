import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, open, rmdir, unlink } from 'node:fs/promises';
import { basename, delimiter, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PYTHON_SOURCE = join(ROOT, 'casper-db', 'src');
const MAX_REPORT_BYTES = 32_000_000;
const MAX_MULTIPART_BYTES = MAX_REPORT_BYTES + 1024 * 1024;
const MAX_BRIDGE_OUTPUT = 32 * 1024 * 1024;

export class DbManagementError extends Error {
  constructor(status, message, code, details) { super(message); this.status = status; this.code = code; this.details = details; }
}

const PUBLIC_ERRORS = new Set(['REPORT_TARGET_CONFLICT', 'DB_RECORD_NOT_FOUND', 'DB_REVISION_CONFLICT',
  'DB_STORAGE_CONFLICT', 'DB_INPUT_INVALID', 'REPORT_INPUT_INVALID', 'REPORT_READ_FAILED', 'REVIEW_INPUT_INVALID', 'REPORT_LLM_UNAVAILABLE']);

function reportName(value) {
  if (typeof value !== 'string') throw new DbManagementError(400, 'A report filename is required.');
  const name = basename(value.replaceAll('\\', '/')).normalize('NFC').replace(/[<>:"/\\|?*\u0000-\u001f\u007f]/g, '-')
    .replace(/^[. ]+|[. ]+$/g, '');
  if (!name || name.length > 180 || !['.hwp', '.hwpx'].includes(extname(name).toLowerCase())) {
    throw new DbManagementError(415, 'Upload a HWP or HWPX report.');
  }
  return name;
}

async function readLimited(req, limit) {
  const announced = Number(req.headers['content-length']);
  if (Number.isFinite(announced) && announced > limit) { req.resume(); throw new DbManagementError(413, 'Report upload exceeds 32 MB.'); }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) { req.resume(); throw new DbManagementError(413, 'Report upload exceeds 32 MB.'); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readMultipart(req) {
  const contentType = req.headers['content-type'] ?? '';
  if (!/^multipart\/form-data\s*;\s*boundary=/i.test(contentType)) {
    throw new DbManagementError(415, 'Use multipart/form-data.');
  }
  const body = await readLimited(req, MAX_MULTIPART_BYTES);
  let form;
  try {
    form = await new Request('http://localhost/upload', { method: 'POST',
      headers: { 'content-type': contentType }, body }).formData();
  } catch { throw new DbManagementError(400, 'Invalid multipart report upload.'); }
  const file = form.get('file');
  const targetId = form.get('targetId');
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    throw new DbManagementError(400, 'Provide a report file.');
  }
  if (typeof targetId !== 'string' || !targetId.trim() || targetId.length > 160) {
    throw new DbManagementError(400, 'Provide a targetId.');
  }
  const filename = reportName(file.name);
  if (file.size < 1 || file.size > MAX_REPORT_BYTES) throw new DbManagementError(413, 'Report must be between 1 byte and 32 MB.');
  const bytes = Buffer.from(await file.arrayBuffer());
  const localOcr = form.get('localOcr');
  const localLlm = form.get('localLlm');
  if (localLlm !== null && !['true', 'false'].includes(localLlm)) throw new DbManagementError(400, 'Invalid local LLM option.');
  const ocrLanguage = form.get('ocrLanguage');
  if (localOcr !== null && !['true', 'false'].includes(localOcr)) throw new DbManagementError(400, 'Invalid OCR option.');
  if (ocrLanguage !== null && !['ko', 'en', 'kor', 'eng', 'kor+eng'].includes(ocrLanguage)) throw new DbManagementError(400, 'Invalid OCR language.');
  return { filename, targetId: targetId.trim(), bytes,
    ...(localOcr === null ? {} : { localOcr: localOcr === 'true' }),
    ...(localLlm === null ? {} : { localLlm: localLlm === 'true' }),
    ...(ocrLanguage === null ? {} : { ocrLanguage }) };
}

function runBridge(input, { python, timeoutMs }) {
  return new Promise((resolveResult, reject) => {
    const command = python ?? process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
    const environment = { ...process.env, PYTHONPATH: [PYTHON_SOURCE, process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      PYTHONIOENCODING: 'utf-8' };
    if (['stage', 'analyze_local'].includes(input.operation)) {
      for (const key of Object.keys(environment)) {
        if (/(?:API_KEY|API_TOKEN|ACCESS_TOKEN|SECRET)$/i.test(key) || /^(?:HTTP|HTTPS|ALL)_PROXY$/i.test(key)) delete environment[key];
      }
    }
    const child = spawn(command, ['-m', 'casper_db.dashboard_api'], { cwd: ROOT, shell: false, windowsHide: true,
      env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    const outputChunks = [];
    let outputBytes = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolveResult(value);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(new DbManagementError(504, 'DB operation timed out.'));
    }, timeoutMs);
    child.stdout.on('data', chunk => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_BRIDGE_OUTPUT) {
        child.kill();
        return finish(new DbManagementError(502, 'DB response is too large.'));
      }
      outputChunks.push(chunk);
    });
    child.stderr.on('data', () => {});
    child.on('error', () => finish(new DbManagementError(503, 'DB processor is unavailable.')));
    child.on('close', code => {
      if (settled) return;
      if (code !== 0) return finish(new DbManagementError(502, 'DB processor failed.'));
      let parsed;
      try { parsed = JSON.parse(Buffer.concat(outputChunks).toString('utf8')); }
      catch { return finish(new DbManagementError(502, 'DB process returned invalid JSON.')); }
      if (parsed?.ok !== true) {
        const status = [400, 404, 409].includes(parsed?.status) ? parsed.status : 502;
        const reported = parsed?.public_error;
        if (PUBLIC_ERRORS.has(reported?.code) && typeof reported.message === 'string' && reported.message.length <= 1000) {
          return finish(new DbManagementError(status, reported.message, reported.code, reported.details));
        }
        const message = status === 404 ? 'DB record not found.' : status === 409
          ? 'DB record changed or cannot be removed.' : status === 400
            ? 'DB request was rejected. Check the report and fields.' : 'DB processor failed.';
        return finish(new DbManagementError(status, message));
      }
      finish(null, parsed.result);
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(input));
  });
}

export function createDbManagement({ casePath = process.env.CASPER_DB_PATH ?? join(ROOT, 'casper-db', 'data', 'cases.sqlite3'),
  workspacePath = process.env.CASPER_DB_INTAKE_WORKSPACE ?? join(dirname(resolve(casePath)), 'dashboard-intake'),
  python } = {}) {
  const configuredCasePath = resolve(casePath);
  const configuredWorkspacePath = resolve(workspacePath);
  const call = (operation, data = {}, timeoutMs = 30_000) => runBridge({
    ...data, case_path: configuredCasePath, workspace_path: configuredWorkspacePath, operation,
  }, { python, timeoutMs });
  return {
    casePath: configuredCasePath,
    workspacePath: configuredWorkspacePath,
    bootstrap: () => call('bootstrap'),
    status: () => call('status'),
    getSettings: () => call('get_settings'),
    saveSettings: (body, actor) => call('save_settings', { ...body, actor }),
    listAdvisories: filters => call('list_advisories', filters),
    queryAdvisories: query => call('query_advisories', query),
    syncAdvisories: (query, actor) => call('sync_advisories', { ...query, actor }, 610_000),
    listIntakes: async filters => {
      const result = await call('list_intakes', filters);
      // Existing integrations without filters retain their original response.
      return filters === undefined ? { intakes: result.intakes } : result;
    },
    getIntake: draftSha => call('get_intake', { draft_sha: draftSha }),
    stageUpload: async (req, { actor } = {}) => {
      const { filename, targetId, bytes, ...ocr } = await readMultipart(req);
      const uploadRoot = join(dirname(configuredWorkspacePath), '.dashboard-uploads');
      await mkdir(uploadRoot, { recursive: true });
      const folder = join(uploadRoot, randomUUID());
      await mkdir(folder);
      const sourcePath = join(folder, filename);
      try {
        const handle = await open(sourcePath, 'wx', 0o600);
        try { await handle.writeFile(bytes); } finally { await handle.close(); }
        return await call('stage', { source_path: sourcePath, target_id: targetId, actor, ...ocr }, 900_000);
      } catch (failure) {
        if (failure instanceof DbManagementError) throw failure;
        throw new DbManagementError(500, 'Report upload could not be stored.');
      } finally {
        await unlink(sourcePath).catch(() => {});
        await rmdir(folder).catch(() => {});
      }
    },
    reviewIntake: (draftSha, review, actor, expectedValidationSha) => call('review', {
      draft_sha: draftSha, review, actor, expectedValidationSha,
    }),
    analyzeIntake: (draftSha, expectedValidationSha, actor) => call('analyze_local', {
      draft_sha: draftSha, expectedValidationSha, actor,
    }, 900_000),
    publishIntake: (draftSha, { readyOnly = false, expectedValidationSha } = {}, actor) => call('publish', {
      draft_sha: draftSha, readyOnly, expectedValidationSha, actor,
    }, 60_000),
    deleteIntake: (draftSha, actor) => call('delete_intake', { draft_sha: draftSha, actor }),
    listCases: filters => call('list_cases', filters),
    getCase: caseId => call('get_case', { case_id: caseId }),
    listCaseVersions: caseId => call('get_case_versions', { case_id: caseId }),
    listAudit: filters => call('list_audit', filters),
    updateCase: (caseId, { patch, expectedRevision }, actor) => call('update_case', { case_id: caseId, patch, expectedRevision, actor }),
    archiveCase: (caseId, { reason, expectedRevision } = {}, actor) => call('archive_case', { case_id: caseId, reason, expectedRevision, actor }),
    restoreCase: (caseId, actor) => call('restore_case', { case_id: caseId, actor }),
  };
}
