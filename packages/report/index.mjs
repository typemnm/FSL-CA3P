import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import configuration from '../../agent/src/deepseek-config.js';
import modelDefinitions from '../../agent/src/model-definitions.js';

const PYTHON_ROOT = fileURLToPath(new URL('./py/src/', import.meta.url));
const MAX_PROCESS_OUTPUT = 1_000_000;
const MAX_DOCUMENT_BYTES = 20_000_000;
const MAX_PREVIEW_BYTES = 2_000_000;
const MAX_HTML_PREVIEW_BYTES = 30_000_000;
const DEFAULT_TIMEOUT_MS = 300_000;
const FINDING_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
// Runs without a language model (rule-only) write with the configured default DeepSeek model.
const RULE_ONLY_MODELS = new Set([undefined, 'rule-baseline']);
const hash = value => createHash('sha256').update(value).digest('hex');
const failure = (code, message) => Object.assign(new Error(message), { code });

function terminate(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill.exe', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => child.kill());
    killer.once('exit', code => { if (code) child.kill(); });
  } else {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
  }
}

/** The report agent is bounded here, including its Python/Node/browser descendants. */
export function executeReportProcess({ command, args, input, env, signal,
  timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_PROCESS_OUTPUT }) {
  if (signal?.aborted) return Promise.reject(failure('REPORT_CANCELLED', '보고서 생성을 취소했습니다.'));
  return new Promise((resolveResult, reject) => {
    let child;
    try {
      child = spawn(command, args, { env, detached: process.platform !== 'win32', windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'] });
    } catch { reject(failure('REPORT_PROCESS_UNAVAILABLE', '보고서 실행 환경을 확인하세요.')); return; }
    const stdout = []; let bytes = 0; let problem = null;
    const stop = error => { if (!problem) problem = error; terminate(child); };
    const abort = () => stop(failure('REPORT_CANCELLED', '보고서 생성을 취소했습니다.'));
    const timer = setTimeout(() => stop(failure('REPORT_TIMEOUT', '보고서 생성 제한 시간을 초과했습니다.')), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    const accept = (chunk, output) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) stop(failure('REPORT_OUTPUT_LIMIT', '보고서 실행 출력 제한을 초과했습니다.'));
      else if (output) stdout.push(chunk);
    };
    child.stdout.on('data', chunk => accept(chunk, true));
    child.stderr.on('data', chunk => accept(chunk, false));
    child.stdin.on('error', () => {});
    child.on('error', () => { problem ??= failure('REPORT_PROCESS_UNAVAILABLE', '보고서 실행 환경을 확인하세요.'); });
    child.once('close', code => {
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (problem) reject(problem);
      else resolveResult({ code, stdout: Buffer.concat(stdout).toString('utf8') });
    });
    child.stdin.end(input);
    if (signal?.aborted) abort();
  });
}

async function readVerifiedFile(directory, name, entry, maxBytes) {
  if (!entry || entry.name !== name || !Number.isSafeInteger(entry.size) || entry.size < 1
    || entry.size > maxBytes || !/^sha256:[a-f0-9]{64}$/.test(entry.sha256)) {
    throw failure('REPORT_INVALID_OUTPUT', '보고서 산출물 정보를 확인할 수 없습니다.');
  }
  const path = join(directory, name);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== entry.size
    || dirname(await realpath(path)) !== await realpath(directory)) {
    throw failure('REPORT_INVALID_OUTPUT', '보고서 산출물 경계가 올바르지 않습니다.');
  }
  const bytes = await readFile(path);
  if (bytes.length !== entry.size || `sha256:${hash(bytes)}` !== entry.sha256) {
    throw failure('REPORT_INVALID_OUTPUT', '보고서 산출물 무결성을 확인할 수 없습니다.');
  }
  return bytes;
}

/** The id a legacy `report.finding` is reported under. Mirrors legacy_finding_id() in Python. */
function legacyFindingId(finding) {
  for (const key of ['findingId', 'id']) {
    if (typeof finding?.[key] === 'string' && FINDING_ID.test(finding[key])) return finding[key];
  }
  return 'finding';
}

/** The run's own DeepSeek model, or the configured default for rule-only runs. Other models
 * (a local LLM) are refused rather than silently sent to an external provider. */
function resolveSettings({ modelId, env, envFile }) {
  const own = modelDefinitions.DEEPSEEK_MODELS.includes(modelId);
  if (!own && !RULE_ONLY_MODELS.has(modelId)) return null;
  return configuration.resolveDeepSeekOptions({ env: own ? { ...env, DEEPSEEK_MODEL: modelId } : env,
    ...(envFile !== undefined ? { envFile } : {}) });
}

/** Runs the Python report agent; public results never contain paths or credentials. */
export async function generateReportDocument({ run, storePath, historyPath, envFile, env = process.env,
  findingId, verificationDir, signal, timeoutMs = DEFAULT_TIMEOUT_MS, execute = executeReportProcess } = {}) {
  if (run?.mode === 'core-fixture' || run?.simulated) {
    return { status: 'skipped', errorCode: 'FIXTURE_SKIPPED', message: '코어 fixture는 HWPX 보고서를 생성하지 않습니다.' };
  }
  if (!run?.report || !['completed', 'failed'].includes(run.report.status)) {
    return { status: 'skipped', errorCode: 'NO_FINAL_REPORT', message: '최종 검사 보고서가 없습니다.' };
  }
  const general = run.report.assessmentMode === 'general';
  let selectedFinding;
  if (general) {
    const matches = Array.isArray(run.report.findings) && typeof findingId === 'string'
      ? run.report.findings.filter(item => item?.id === findingId) : [];
    if (matches.length !== 1 || matches[0].status !== 'confirmed'
      || !Array.isArray(matches[0].evidenceIds)
      || matches[0].evidenceIds.some(id => typeof id !== 'string')) {
      return { status: 'failed', errorCode: 'REPORT_INVALID_SELECTION',
        message: '확정된 범용 finding을 하나 선택해야 합니다.' };
    }
    selectedFinding = matches[0];
  } else if (findingId !== undefined) {
    return { status: 'failed', errorCode: 'REPORT_INVALID_SELECTION',
      message: '이 보고서 형식은 finding 선택을 지원하지 않습니다.' };
  }
  const source = general ? selectedFinding : run.report.finding;
  const expectedId = general ? findingId : legacyFindingId(source);
  const sourceStatus = general ? 'confirmed' : source?.status ?? null;
  const sourceEvidence = general ? selectedFinding.evidenceIds
    : Array.isArray(source?.evidenceRefs) ? source.evidenceRefs.filter(id => typeof id === 'string') : [];
  let settings;
  try { settings = resolveSettings({ modelId: run.modelId, env, envFile }); }
  catch { settings = null; }
  if (!settings) {
    return { status: 'unavailable', errorCode: 'REPORT_NOT_CONFIGURED',
      message: '이 실행의 모델로 보고서를 작성할 LLM 설정이 필요합니다.' };
  }
  try {
    if (signal?.aborted) throw failure('REPORT_CANCELLED', '보고서 생성을 취소했습니다.');
    const output = join(dirname(resolve(storePath)), 'reports', hash(run.id), randomUUID());
    await mkdir(output, { recursive: true, mode: 0o700 });
    const trigger = { schemaVersion: 'report-trigger-1.0', runId: run.id,
      sources: { run: { kind: 'run-store', location: resolve(storePath) },
        history: historyPath ? { kind: 'casper-db', location: resolve(historyPath) } : { kind: 'none' },
        ...(verificationDir ? { verification: { kind: 'handoff-dir', location: resolve(verificationDir) } } : {}) },
      output: { dir: output }, ...(general ? { options: { findingId } } : {}) };
    const childEnv = { ...env, PYTHONPATH: PYTHON_ROOT, PYTHONIOENCODING: 'utf-8',
      DEEPSEEK_BASE_URL: settings.baseUrl, DEEPSEEK_API_KEY: settings.apiKey, DEEPSEEK_MODEL: settings.model };
    const result = await execute({ command: env.CA3P_REPORT_PYTHON || env.CASPER_DB_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),
      args: ['-m', 'ca3p_report', 'run', '--trigger', '-'], input: JSON.stringify(trigger), env: childEnv, signal, timeoutMs });
    if (signal?.aborted) throw failure('REPORT_CANCELLED', '보고서 생성을 취소했습니다.');
    let response;
    try { response = JSON.parse(result.stdout.trim()); }
    catch { throw failure('REPORT_INVALID_OUTPUT', '보고서 모듈의 응답이 올바르지 않습니다.'); }
    if (result.code !== 0 || response.ok !== true) {
      const source = response?.error?.code === 'SOURCE_INVALID'
        && typeof response.error.message === 'string'
        && /^[a-z][a-z0-9 .:-]{0,199}$/u.test(response.error.message)
        ? response.error.message : null;
      throw failure(result.code === 8 ? 'REPORT_LLM_FAILED' : 'REPORT_GENERATION_FAILED',
        source ?? 'HWPX 보고서 생성에 실패했습니다.');
    }
    const name = response.reportFilename;
    if (response.schemaVersion !== 'report-result-1.0' || response.runId !== run.id || response.stage !== 'reported'
      || response.findingId !== expectedId
      || typeof name !== 'string' || !/^[^<>:"/\\|?*\u0000-\u001f]{1,120}\.hwpx$/u.test(name)
      || name.includes('..') || !Array.isArray(response.files)) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서 실행 식별자 또는 파일명이 올바르지 않습니다.');
    }
    const reportDir = join(output, 'report');
    const reportInfo = await lstat(reportDir);
    if (!reportInfo.isDirectory() || reportInfo.isSymbolicLink()
      || await realpath(reportDir) !== join(await realpath(output), 'report')) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서 출력 디렉터리가 올바르지 않습니다.');
    }
    const modelBytes = await readVerifiedFile(reportDir, 'report-model.json', response.files.find(item => item.name === 'report-model.json'), 2_000_000);
    let model;
    try { model = JSON.parse(modelBytes.toString('utf8')); }
    catch { throw failure('REPORT_INVALID_OUTPUT', '보고서 모델의 형식이 올바르지 않습니다.'); }
    if (model?.run?.run_id !== run.id) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서 내용의 실행 식별자가 일치하지 않습니다.');
    }
    const evidenceIds = model.sourceEvidenceIds;
    if (model.sourceFindingId !== expectedId
      || model.run.status !== run.report.status
      || !Array.isArray(model.findings) || model.findings.length !== 1
      || model.findings[0]?.finding_id !== expectedId
      || model.findings[0].verdict !== (sourceStatus === 'confirmed' ? 'confirmed' : 'unverified')
      || !Array.isArray(evidenceIds) || (sourceEvidence.length > 0 && !evidenceIds.length)
      || new Set(evidenceIds).size !== evidenceIds.length
      || evidenceIds.some(id => typeof id !== 'string' || !sourceEvidence.includes(id))) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서의 finding 또는 증거 참조가 원본과 일치하지 않습니다.');
    }
    const bytes = await readVerifiedFile(reportDir, name, response.files.find(item => item.name === name), MAX_DOCUMENT_BYTES);
    if (bytes.length < 4 || !bytes.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
      throw failure('REPORT_INVALID_OUTPUT', 'HWPX 파일 형식이 올바르지 않습니다.');
    }
    const previewEntry = response.files.find(item => item.name === 'report.md');
    const previewBytes = previewEntry
      ? await readVerifiedFile(reportDir, 'report.md', previewEntry, MAX_PREVIEW_BYTES)
      : null;
    const previewMarkdown = previewBytes?.toString('utf8') ?? null;
    if (previewBytes && (!previewMarkdown || !Buffer.from(previewMarkdown, 'utf8').equals(previewBytes))) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서 미리보기 형식이 올바르지 않습니다.');
    }
    const htmlEntry = response.files.find(item => item.name === 'report.html');
    const htmlBytes = htmlEntry
      ? await readVerifiedFile(reportDir, 'report.html', htmlEntry, MAX_HTML_PREVIEW_BYTES)
      : null;
    const previewHtml = htmlBytes?.toString('utf8') ?? null;
    if (htmlBytes && (!previewHtml || !Buffer.from(previewHtml, 'utf8').equals(htmlBytes))) {
      throw failure('REPORT_INVALID_OUTPUT', '보고서 HTML 미리보기 형식이 올바르지 않습니다.');
    }
    return { status: 'ready', ...(general ? { findingId } : {}),
      filename: name, bytes, sha256: hash(bytes), size: bytes.length, previewMarkdown, previewHtml };
  } catch (error) {
    const known = typeof error?.code === 'string' && /^REPORT_[A-Z_]+$/.test(error.code);
    return { status: 'failed', errorCode: known ? error.code : 'REPORT_GENERATION_FAILED',
      message: known ? error.message : 'HWPX 보고서 생성에 실패했습니다.' };
  }
}
