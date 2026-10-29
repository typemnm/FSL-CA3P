import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../packages/run-store/index.mjs';
import { createIdorRuntime } from '../application/idor-runtime.mjs';
import { createGeneralRuntime } from '../application/general-runtime.mjs';
import { createExternalRuntime } from '../application/external-runtime.mjs';
import { digest } from '../../packages/contracts/index.mjs';
import { syncRunChecks } from '../../packages/history/check-sync.mjs';
import { PROJECT_ROOT, treeDigest } from '../../packages/contracts/manifest.mjs';
import { join } from 'node:path';
import { generateReportDocument } from '../../packages/report/index.mjs';

const GENERAL_DOCUMENTS_SCHEMA_VERSION = 'general-report-documents/1';

function generalDocumentsStatus(items) {
  if (!items.length || items.every(item => item.status === 'skipped')) return 'skipped';
  if (items.some(item => item.status === 'waiting' || item.status === 'generating')) return 'generating';
  if (items.every(item => item.status === 'ready')) return 'ready';
  if (items.some(item => item.status === 'ready')) return 'partial';
  if (items.every(item => item.status === 'unavailable')) return 'unavailable';
  return 'failed';
}

function storeReportPreviews(store, runId, document, findingId) {
  const artifacts = {};
  for (const [field, kind, filename, contentType, maxBytes, idField] of [
    ['previewMarkdown', 'report-preview', 'report.md', 'text/markdown; charset=utf-8', 2_000_000, 'previewArtifactId'],
    ['previewHtml', 'report-preview-html', 'report.html', 'text/html; charset=utf-8', 30_000_000, 'previewHtmlArtifactId'],
  ]) {
    if (typeof document[field] !== 'string') continue;
    const bytes = Buffer.from(document[field], 'utf8');
    if (!bytes.length || bytes.length > maxBytes) throw new Error('Invalid report preview size.');
    const artifact = store.writeBinaryArtifact(runId, kind, bytes, {
      filename, ...(findingId ? { findingId } : {}), contentType,
      provenance: 'report-agent-generated',
    });
    artifacts[idField] = artifact.id;
  }
  return artifacts;
}

export async function runWorker({ storePath, owner = `worker-${randomUUID()}`,
  pollMs = 150, leaseMs = 15_000, heartbeatMs = 1000, envFile, env = process.env,
  reportGenerator = generateReportDocument,
  idorRuntimeFactory = createIdorRuntime, generalRuntimeFactory = createGeneralRuntime,
  externalRuntimeFactory = createExternalRuntime, externalRequestImpl,
  generalPlannerFactory, generalFetchImpl, generalIdorProbe, generalBoardFactory } = {}) {
  const store = createRunRepository({ path: storePath });
  let stopping = false; let runtime = null; let activeLease = null; let activeController = null; let busy = false; let timer; let shutdownTask;
  const notify = () => { if (process.connected) process.send({ type: 'state' }); };
  const cancel = runId => { if (activeLease?.runId === runId) {
    activeController?.abort();
    if (runtime) { try { runtime.stop(runId); } catch { /* Already terminal. */ } }
  } };
  async function tick() {
    if (busy || stopping) return;
    busy = true;
    let lease;
    try {
      lease = store.claimNext(owner, { leaseMs });
      if (!lease) return;
      activeLease = lease;
      const externalRun = lease.mode === 'external-general';
      const generalLab = lease.mode === 'local-lab-general' || externalRun;
      const idorLab = lease.options.testProfile === 'known_record_idor_read';
      // Runs queued before the single stored-XSS/BOLA check was retired have no runtime left.
      if (!generalLab && !(lease.mode === 'local-lab-rule' && idorLab)) {
        throw Object.assign(new Error('This run mode was retired. Start a general assessment instead.'), { code: 'RETIRED_MODE' });
      }
      const frozen = store.getRun(lease.runId).manifest;
      for (const [name, value] of Object.entries(frozen.modules ?? {})) {
        if (treeDigest(join(PROJECT_ROOT, name)) !== value.contentDigest) {
          throw Object.assign(new Error('Module content changed after this run was queued. Create a new run.'), { code: 'CONDITION_CHANGED' });
        }
      }
      for (const [field, path] of [['contractDigest', 'packages/contracts'], ['modelRegistryDigest', 'packages/models']]) {
        if (frozen.shared?.[field] && treeDigest(join(PROJECT_ROOT, path)) !== frozen.shared[field]) {
          throw Object.assign(new Error('Shared execution conditions changed after this run was queued.'), { code: 'CONDITION_CHANGED' });
        }
      }
      if (lease.options.caseSnapshot && treeDigest(lease.options.caseSnapshot.path) !== lease.options.caseSnapshot.fileDigest) {
        throw Object.assign(new Error('Historical-case snapshot changed after preparation.'), { code: 'CASE_SNAPSHOT_CHANGED' });
      }
      const controller = new AbortController();
      activeController = controller;
      if (lease.mode === 'local-lab-general'
        && (lease.options.testProfile !== 'general' || lease.modelId === 'rule-baseline')) {
        throw Object.assign(new Error('General assessment requires its own profile and a registered model.'), { code: 'INVALID_GENERAL_RUN' });
      }
      if (externalRun && (lease.options.testProfile !== 'external-read-only' || lease.modelId !== 'rule-baseline'
        || lease.options.fixtureId !== null)) {
        throw Object.assign(new Error('External observation requires its read-only profile.'), { code: 'INVALID_EXTERNAL_RUN' });
      }
      let persistenceError = null;
      const historyProvider = () => store.listRuns({ limit: 50 }).items
        .filter(item => item.id !== lease.runId && (externalRun
          ? item.mode === 'external-general' && item.manifest?.target?.origin === lease.options.scope.origin
          : (item.fixtureId ?? item.manifest?.target?.fixtureId) === lease.options.fixtureId))
        .slice(0, 20).map(item => {
          const findings = Array.isArray(item.report?.findings) ? item.report.findings
            : item.report?.finding ? [item.report.finding] : [];
          return { runId: item.id, mode: item.mode, status: item.status,
            modelId: item.modelId, completedAt: item.completedAt ?? null,
            findings: findings.map(finding => ({ category: finding.category ?? finding.cwe ?? null,
              status: finding.status ?? null, evidenceCount: Array.isArray(finding.evidenceIds)
                ? finding.evidenceIds.length : null })) };
        });
      runtime = (externalRun ? externalRuntimeFactory : generalLab ? generalRuntimeFactory
        : idorRuntimeFactory)({ fixtureId: lease.options.fixtureId,
        targetOrigin: lease.options.target,
        ...(externalRun ? { targetUrl: lease.options.target, scope: lease.options.scope,
          ...(externalRequestImpl ? { requestImpl: externalRequestImpl } : {}) } : {}),
        caseSnapshot: lease.options.caseSnapshot,
        unavailableInputs: lease.options.unavailableInputs ?? [],
        ...(generalLab && !externalRun ? { limits: lease.options.loopBudget } : {}),
        historyProvider,
        cleanupRegistryPath: join(dirname(store.path), 'lab-sessions'),
        ...(generalPlannerFactory ? { plannerFactory: generalPlannerFactory } : {}),
        ...(generalFetchImpl ? { fetchImpl: generalFetchImpl } : {}),
        ...(generalIdorProbe ? { idorProbe: generalIdorProbe } : {}),
        ...(generalBoardFactory ? { boardFactory: generalBoardFactory } : {}),
        modelId: lease.modelId,
        env, ...(envFile ? { envFile } : {}), signal: controller.signal,
        onModelCall(metadata) { store.recordModelCall(lease, metadata); notify(); },
        runIdFactory: () => lease.runId,
        async beforeProbe(probe) {
          store.assertLease(lease);
          const method = String(probe?.method || 'GET').toUpperCase();
          if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return null;
          const actionId = digest({ probeId: probe.id ?? probe.probeId ?? null,
            iteration: probe.iteration, tool: probe.tool, session: probe.session,
            method, url: probe.url, bodyDigest: probe.payloadDigest ?? digest(probe.body ?? null) });
          store.reserveAction(lease, { actionId, request: probe });
          return actionId;
        },
        async afterProbe(probe, result, reservation) {
          store.assertLease(lease, { allowCancelled: true });
          if (reservation) store.completeAction(lease, reservation, {
            status: result?.status ?? 'completed', evidenceId: result?.evidenceId ?? null,
          });
        },
      });
      let resolveTerminal;
      const terminal = new Promise(resolve => { resolveTerminal = resolve; });
      const detach = runtime.subscribe(({ run }) => {
        if (!run.id) return;
        // Keep the public run active until report evidence and historical-case
        // checks have been stored. A terminal status must describe a complete run.
        const terminalState = ['completed', 'failed', 'stopped', 'cancelled', 'interrupted'].includes(run.status);
        try { store.saveState(lease, { ...run, status: terminalState ? 'running' : run.status, modelId: lease.modelId }); notify(); }
        catch (error) {
          persistenceError = error; controller.abort(error); cancel(lease.runId); resolveTerminal(); return;
        }
        if (terminalState) resolveTerminal();
      });
      const heartbeat = setInterval(() => {
        try {
          const result = store.heartbeat(lease, { leaseMs });
          if (result.cancelRequested) { controller.abort(); cancel(lease.runId); }
        } catch (error) {
          persistenceError = error; controller.abort(error); cancel(lease.runId); resolveTerminal();
        }
      }, heartbeatMs);
      try {
        await runtime.startLab();
        await terminal;
        if (persistenceError) throw persistenceError;
        const final = runtime.getState().run;
        const status = final.status === 'stopped' ? 'cancelled' : final.status;
        let finalState = { ...final, status, modelId: lease.modelId };
        if (final.report) {
          const artifact = store.writeArtifact(lease.runId, 'run-report', final.report, { contentType: 'application/json', provenance: 'verified-run-report' });
          let historyWrite;
          try { historyWrite = idorLab || generalLab
            ? { status: 'skipped', checks: [], message: generalLab
              ? '범용 점검 결과는 실행 이력과 JSON에 저장됩니다. 단일 XSS 사례 동기화는 수행하지 않습니다.'
              : 'IDOR 결과는 실행 이력과 JSON에 저장됩니다. XSS 과거 사례 DB에는 기록하지 않습니다.' }
            : await syncRunChecks(final, { artifact, storePath: store.path,
              databasePath: lease.options.caseSnapshot?.sourcePath }); }
          catch (error) { historyWrite = { status: 'failed', checks: [], error: error.message }; }
          finalState = { ...finalState, historyWrite };
        }
        // Persist the core JSON before the report collector opens its read-only DB.
        // The lease/heartbeat and local board stay alive through document capture.
        const startedAt = new Date().toISOString();
        if (generalLab) {
          const confirmed = Array.isArray(final.report?.findings)
            ? final.report.findings.filter(finding => finding?.status === 'confirmed') : [];
          const items = confirmed.map(finding => ({ findingId: finding.id, status: 'waiting' }));
          const documents = { schemaVersion: GENERAL_DOCUMENTS_SCHEMA_VERSION, status: 'generating',
            startedAt, items };
          finalState.reportDocuments = documents;
          const saveProgress = () => { documents.status = generalDocumentsStatus(items);
            store.saveState(lease, { ...finalState, status: 'running' }); notify(); };
          const ids = items.map(item => item.findingId);
          const validIds = ids.every(id => typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,71}$/u.test(id))
            && new Set(ids).size === ids.length;
          if (!final.report) {
            documents.status = 'skipped'; documents.errorCode = 'NO_FINAL_REPORT';
            documents.message = '최종 검사 결과가 없어 HWPX를 생성하지 않았습니다.';
          } else if (status === 'cancelled' || controller.signal.aborted) {
            for (const item of items) { item.status = 'skipped'; item.errorCode = 'RUN_STOPPED'; }
            documents.status = 'skipped'; documents.errorCode = 'RUN_STOPPED';
            documents.message = '취소된 점검의 HWPX 생성을 생략했습니다.';
          } else if (!items.length) {
            documents.status = 'skipped'; documents.errorCode = 'NO_CONFIRMED_FINDINGS';
            documents.message = '확정된 취약점이 없어 HWPX를 생성하지 않았습니다.';
          } else if (!validIds) {
            for (const item of items) { item.status = 'failed'; item.errorCode = 'INVALID_FINDING_SELECTION'; }
            documents.status = 'failed'; documents.errorCode = 'INVALID_FINDING_SELECTION';
            documents.message = '확정 결과의 식별자가 올바르지 않아 HWPX를 생성하지 않았습니다.';
          } else {
            saveProgress();
            for (const item of items) {
              if (controller.signal.aborted) {
                item.status = 'skipped'; item.errorCode = 'REPORT_CANCELLED';
                continue;
              }
              item.status = 'generating'; item.startedAt = new Date().toISOString();
              saveProgress();
              let document;
              try {
                document = await reportGenerator({ run: finalState, findingId: item.findingId,
                  storePath: store.path, historyPath: lease.options.caseSnapshot?.sourcePath,
                  envFile, env, signal: controller.signal });
                if (document?.status === 'ready' && controller.signal.aborted) document = {
                  status: 'failed', errorCode: 'REPORT_CANCELLED', message: '보고서 생성을 취소했습니다.',
                };
                if (document?.status === 'ready') {
                  const previews = storeReportPreviews(store, lease.runId, document, item.findingId);
                  const binary = store.writeBinaryArtifact(lease.runId, 'hwpx-report', document.bytes, {
                    filename: document.filename, findingId: item.findingId,
                    contentType: 'application/hwp+zip', provenance: 'report-agent-generated',
                  });
                  if (items.some(other => other !== item && other.status === 'ready' && other.artifactId === binary.id)) {
                    throw new Error('Two selected findings produced the same HWPX bytes.');
                  }
                  document = { status: 'ready', artifactId: binary.id,
                    ...previews, filename: document.filename,
                    message: 'HWPX 보고서 초안이 준비되었습니다. 내려받은 뒤 검토하세요.' };
                } else document = { status: ['failed', 'unavailable', 'skipped'].includes(document?.status) ? document.status : 'failed',
                  message: document?.message, errorCode: document?.errorCode ?? 'REPORT_GENERATION_FAILED' };
              } catch {
                // A document failure must not change the inspection or other documents.
                document = { status: 'failed', errorCode: 'REPORT_GENERATION_FAILED',
                  message: 'HWPX 보고서 생성에 실패했습니다.' };
              }
              Object.assign(item, document, { completedAt: new Date().toISOString() });
              saveProgress();
            }
          }
          documents.completedAt = new Date().toISOString();
          documents.status = generalDocumentsStatus(items);
          // Empty selections and invalid IDs have no item state to derive from.
          if (!items.length || !validIds) documents.status = !items.length ? 'skipped' : 'failed';
        } else {
          finalState.reportDocument = { status: 'generating', startedAt, message: 'HWPX 보고서를 작성하고 있습니다.' };
          store.saveState(lease, { ...finalState, status: 'running' }); notify();
          let document;
          try {
            if (idorLab) document = { status: 'skipped', errorCode: 'IDOR_DOCUMENT_UNSUPPORTED', message: 'IDOR 실습은 실행 이력과 JSON 보고서를 제공합니다. HWPX 생성과 모델 API 호출은 수행하지 않습니다.' };
            else if (status === 'cancelled' || !final.report) document = { status: 'skipped', errorCode: 'RUN_STOPPED', message: '중지했거나 최종 보고서가 없어 문서를 생성하지 않습니다.' };
            else document = await reportGenerator({ run: finalState, storePath: store.path,
              historyPath: lease.options.caseSnapshot?.sourcePath, envFile, env, signal: controller.signal });
            if (document.status === 'ready' && controller.signal.aborted) document = {
              status: 'failed', errorCode: 'REPORT_CANCELLED', message: '보고서 생성을 취소했습니다.',
            };
            if (document.status === 'ready') {
              const previews = storeReportPreviews(store, lease.runId, document);
              const binary = store.writeBinaryArtifact(lease.runId, 'hwpx-report', document.bytes, {
                filename: document.filename, contentType: 'application/hwp+zip', provenance: 'report-agent-generated',
              });
              document = { status: 'ready', artifactId: binary.id,
                ...previews, filename: document.filename,
                message: 'HWPX 보고서 초안이 준비되었습니다. 내려받은 뒤 검토하세요.' };
            } else document = { status: ['failed', 'unavailable', 'skipped'].includes(document.status) ? document.status : 'failed',
              message: document.message, errorCode: document.errorCode };
          } catch {
            // Document errors must not change the inspection's finding or status.
            document = { status: 'failed', errorCode: 'REPORT_GENERATION_FAILED', message: 'HWPX 보고서 생성에 실패했습니다.' };
          }
          finalState.reportDocument = { ...document, startedAt, completedAt: new Date().toISOString() };
        }
        store.saveState(lease, finalState);
        store.finish(lease, status);
        notify();
      } finally {
        clearInterval(heartbeat); detach(); controller.abort(); await runtime.close(); runtime = null;
      }
    } catch (error) {
      if (lease) {
        try {
          const state = store.getRun(lease.runId);
          store.saveState(lease, { ...state, status: 'failed', error: `${error.code ?? 'WORKER_FAILURE'}: ${error.message}` });
          store.finish(lease, 'failed');
        } catch { store.interruptOwner(owner, `${error.code ?? 'WORKER_FAILURE'}: ${error.message}`); }
      }
      notify();
    } finally {
      activeLease = null; activeController = null; busy = false;
      if (!stopping) timer = setTimeout(tick, pollMs);
    }
  }
  const onMessage = message => {
    if (message?.type === 'cancel') cancel(message.runId);
    if (message?.type === 'wake' && !busy) { clearTimeout(timer); void tick(); }
    if (message?.type === 'shutdown') void shutdown();
  };
  function shutdown() {
    if (shutdownTask) return shutdownTask;
    shutdownTask = (async () => {
    stopping = true; clearTimeout(timer);
    if (activeLease) { store.requestCancel(activeLease.runId); cancel(activeLease.runId); }
    while (busy) await new Promise(resolve => setTimeout(resolve, 25));
    process.off('message', onMessage); store.close();
    if (process.connected) process.disconnect();
    })();
    return shutdownTask;
  }
  process.on('message', onMessage);
  void tick();
  return { shutdown, store, owner };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argument = name => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
  const settings = JSON.parse(process.env.CA3P_WORKER_OPTIONS ?? '{}');
  const worker = await runWorker({ ...settings, storePath: argument('--store') ?? process.env.CA3P_STORE_PATH,
    owner: argument('--owner'), envFile: process.env.CA3P_MODEL_ENV_FILE });
  process.once('SIGTERM', () => { void worker.shutdown(); });
  process.once('SIGINT', () => { void worker.shutdown(); });
  process.once('disconnect', () => { void worker.shutdown(); });
}
