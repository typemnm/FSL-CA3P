import { fork } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRunRepository, DEFAULT_STORE_PATH } from '../../packages/run-store/index.mjs';
import { createRunManifest } from '../../packages/contracts/manifest.mjs';
import { emptyRun, RUN_MODES, ACTIVE_STATUSES, redact } from '../../packages/contracts/index.mjs';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import { normalizeExternalTarget, resolvePublicAddresses, verifyExternalPreflightToken } from './external-target.mjs';
import { compareRunRecords } from '../../packages/evaluation/index.mjs';
import { listModels as registryModels } from '../../packages/models/registry.mjs';
import { prepareCaseSnapshot } from './case-snapshot.mjs';
import { importLegacyRuns } from './import-legacy.mjs';
import { prepareExperimentCleanup, prepareHistoryReset } from './experiment-cleanup.mjs';
import { prepareRunFileCleanup } from './experiment-files.mjs';
import { targetResetObligationsForRuns } from './experiment-targets.mjs';

const fault = (status, message) => Object.assign(new Error(message), { status });
const workerFile = fileURLToPath(new URL('../worker/worker.mjs', import.meta.url));
const IDOR_FIXTURES = Object.freeze({
  'vul-web2-daehan': 'http://127.0.0.1:4101',
  'vul-web2-wonchang': 'http://127.0.0.1:4102',
});
const UNIVERSITY_ORIGIN_ENV = Object.freeze({
  'vul-web2-daehan': 'CA3P_DAEHAN_ORIGIN',
  'vul-web2-wonchang': 'CA3P_WONCHANG_ORIGIN',
});

/** API-side application service. It never runs the lab in the HTTP process. */
export function createRunService({ storePath = DEFAULT_STORE_PATH, autoStartWorker = true,
  pollMs = 100, workerOptions = {}, envFile, env = process.env, defaultDelayMs = 0, importLegacy = true,
  experimentCleanupFactory = prepareExperimentCleanup, experimentFileOptions = {}, workerShutdownMs = 10_000 } = {}) {
  const universityOrigins = Object.freeze(Object.fromEntries(Object.entries(IDOR_FIXTURES)
    .map(([fixtureId, fallback]) => [fixtureId,
      validateUniversityOrigin(env[UNIVERSITY_ORIGIN_ENV[fixtureId]] ?? fallback)])));
  const store = createRunRepository({ path: storePath });
  store.recoverExpired();
  store.recoverAbandonedExperimentOperation();
  const instanceId = randomUUID(); const listeners = new Set();
  function latestInteractiveRunId() {
    let offset = 0;
    while (true) {
      const page = store.listRuns({ limit: 200, offset });
      const recent = page.items.find(item => RUN_MODES.includes(item.mode));
      if (recent) return recent.id;
      offset += page.items.length;
      if (offset >= page.total) return null;
    }
  }
  let selectedRunId = latestInteractiveRunId();
  let idleRun = emptyRun(); let child = null; let closing = false; let closed = false; let resetting = false;
  let lastRevision = ''; let closeTask; let resetTask; let restartTimer; let restartDelay = 200;
  const mutationTasks = new Set();
  const owner = `worker-${randomUUID()}`;
  function listModels() { return registryModels({ envFile, env }); }
  function getState() {
    const selected = selectedRunId ? store.getRun(selectedRunId) : null;
    const run = selected && RUN_MODES.includes(selected.mode) ? selected : idleRun;
    const models = listModels(); const remote = models.find(model => model.provider === 'deepseek' && model.available);
    const experiment = store.experimentState();
    return { run, mode: run.mode, instanceId, experiment: { epoch: experiment.epoch, lastResetAt: experiment.lastResetAt, status: experiment.status },
      experimentReset: experiment, lab: { available: true, model: 'rule-baseline', provider: 'rules',
      remoteAvailable: Boolean(remote), generalSupported: true, generalAvailable: Boolean(remote),
      externalSupported: true, externalAvailable: true, targetOrigins: universityOrigins, models } };
  }
  function publish(force = false) {
    if (closed) return;
    const state = getState(); const revision = JSON.stringify(state);
    if (!force && revision === lastRevision) return;
    lastRevision = revision;
    for (const listener of listeners) { try { listener(state); } catch { /* Subscriber failure does not stop the queue. */ } }
  }
  function ensureWorker() {
    if (child || closing || resetting || store.experimentState().status !== 'ready' || !autoStartWorker) return;
    child = fork(workerFile, ['--store', store.path, '--owner', owner], {
      env: { ...env, ...(envFile ? { CA3P_MODEL_ENV_FILE: envFile } : {}),
        CA3P_WORKER_OPTIONS: JSON.stringify(workerOptions) },
      execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true,
    });
    child.on('message', message => { if (message?.type === 'state') { restartDelay = 200; publish(); } });
    child.on('error', () => { /* The exit path records interrupted jobs. */ });
    child.once('exit', () => {
      child = null;
      store.interruptOwner(owner, closing ? 'Service closed before the run completed.' : 'Worker exited unexpectedly. Start a new isolated run.');
      publish(true);
      if (!closing && !resetting && store.experimentState().status === 'ready' && autoStartWorker) {
        restartTimer = setTimeout(ensureWorker, restartDelay); restartTimer.unref();
        restartDelay = Math.min(restartDelay * 2, 5000);
      }
    });
  }
  const poller = setInterval(() => { if (!closing) { store.recoverExpired(); publish(); } }, pollMs);
  poller.unref();
  ensureWorker();
  const ready = importLegacy && store.experimentState().epoch === 0 && store.experimentState().status === 'ready' ? importLegacyRuns(store).then(result => {
    if (!selectedRunId && !closing) selectedRunId = latestInteractiveRunId();
    publish(); return result;
  }).catch(() => ({ imported: 0, errors: [{ code: 'LEGACY_IMPORT_FAILED' }] })) : Promise.resolve({ imported: 0, errors: [] });

  async function start(body = {}) {
    if (closing || closed) throw fault(503, 'Run service is closed.');
    if (resetting || store.experimentState().status !== 'ready') throw fault(409, '실험 초기화 또는 검토가 진행 중이거나 초기화 재시도가 필요합니다.');
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['mode', 'modelId', 'target', 'delayMs', 'testProfile', 'fixtureId',
        'scope', 'preflightToken', 'authorizationConfirmed'].includes(key))) {
      throw fault(400, 'Unsupported run options.');
    }
    if (body.mode === 'external-general') {
      if (body.fixtureId !== undefined || body.testProfile !== undefined || body.delayMs !== undefined
        || body.authorizationConfirmed !== true) throw fault(400, 'Confirm the external target and use the external profile.');
      const modelId = body.modelId ?? 'rule-baseline';
      if (modelId !== 'rule-baseline') throw fault(400, 'Initial external observation requires rule-baseline.');
      const { normalizedUrl, scope } = normalizeExternalTarget(body);
      if (!verifyExternalPreflightToken(body.preflightToken, normalizedUrl, scope)) {
        throw fault(400, 'External target preflight expired or changed. Check the target again.');
      }
      await resolvePublicAddresses(new URL(normalizedUrl).hostname);
      const id = `run-${randomUUID()}`;
      const options = { mode: body.mode, modelId, target: normalizedUrl, scope,
        testProfile: 'external-read-only', fixtureId: null, delayMs: 0 };
      const manifest = createRunManifest({ runId: id, mode: body.mode, modelId, options,
        model: listModels().find(item => item.id === modelId), env });
      const experiment = store.experimentState();
      manifest.experiment = { epoch: experiment.epoch, lastResetAt: experiment.lastResetAt,
        previousRunCount: store.listRuns({ limit: 1 }).total };
      const state = { ...emptyRun(), id, coreRunId: id, status: 'queued', mode: body.mode, modelId,
        assessmentMode: 'general', target: redact(normalizedUrl), targetKind: 'external',
        targetContacted: false, simulated: false, testProfile: 'external-read-only', fixtureId: null, manifest };
      store.createRun({ id, mode: body.mode, modelId, manifest, state, options });
      selectedRunId = id; ensureWorker(); publish(true); child?.send({ type: 'wake' });
      return getState();
    }
    if (body.scope !== undefined || body.preflightToken !== undefined || body.authorizationConfirmed !== undefined) {
      throw fault(400, 'External target options require external-general mode.');
    }
    const fixtureId = body.fixtureId ?? 'vul-web-1';
    if (typeof fixtureId !== 'string') throw fault(400, 'Choose a registered local fixture.');
    const idorOrigin = Object.hasOwn(universityOrigins, fixtureId) ? universityOrigins[fixtureId] : null;
    if (fixtureId !== 'vul-web-1' && !idorOrigin) throw fault(400, 'Choose a registered local fixture.');
    const mode = body.mode ?? (idorOrigin ? 'local-lab-rule'
      : body.modelId && body.modelId !== 'rule-baseline' ? 'local-lab-deepseek' : 'core-fixture');
    if (!RUN_MODES.includes(mode)) throw fault(400, 'Unsupported run mode.');
    const general = mode === 'local-lab-general';
    const modelId = body.modelId ?? (mode === 'local-lab-deepseek' || general ? 'deepseek-flash' : 'rule-baseline');
    if (idorOrigin && !general && (mode !== 'local-lab-rule' || modelId !== 'rule-baseline')) {
      throw fault(400, 'University fixtures support only the rule baseline known-record IDOR check.');
    }
    const model = listModels().find(item => item.id === modelId);
    if (!model) throw fault(400, 'Choose a registered model.');
    if (!model.available) throw fault(503, 'Selected model is unavailable. Configure server credentials before starting.');
    if ((mode === 'core-fixture' || mode === 'local-lab-rule') && modelId !== 'rule-baseline') throw fault(400, 'Rule or fixture mode requires rule-baseline.');
    if (mode === 'local-lab-deepseek' && modelId === 'rule-baseline') throw fault(400, 'DeepSeek mode requires a registered DeepSeek model.');
    if (general && model.provider !== 'deepseek') throw fault(400, 'General assessment requires a registered DeepSeek model.');
    if (mode !== 'core-fixture' && !idorOrigin && body.target !== undefined) throw fault(400, 'The board lab does not accept a target URL.');
    const delayMs = body.delayMs ?? defaultDelayMs;
    if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 3000) throw fault(400, 'delayMs must be 0..3000.');
    const testProfile = body.testProfile ?? (general ? 'general' : idorOrigin ? 'known_record_idor_read'
      : mode === 'core-fixture' ? 'agent_cross_user_delete_canary' : 'stored_xss_canary');
    if (general ? testProfile !== 'general'
      : idorOrigin ? testProfile !== 'known_record_idor_read'
      : !['stored_xss_canary', 'agent_cross_user_delete_canary'].includes(testProfile)
        || (mode === 'core-fixture' && testProfile !== 'agent_cross_user_delete_canary')) throw fault(400, 'Unsupported fixture test profile.');
    let target = idorOrigin ? validateUniversityOrigin(body.target === undefined ? idorOrigin : body.target) : 'https://demo.ca3p.local';
    if (mode === 'core-fixture' && body.target !== undefined) {
      try {
        if (typeof body.target !== 'string' || body.target.length > 2048) throw new Error();
        const url = new URL(body.target.trim());
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
        target = url.href;
      } catch { throw fault(400, 'Provide a valid HTTP(S) display URL without credentials.'); }
    }
    const id = `run-${randomUUID()}`;
    const options = { mode, modelId, target, delayMs: mode === 'core-fixture' ? delayMs : 0, testProfile, fixtureId };
    if (general) {
      options.loopBudget = store.getGeneralLoopBudget();
      try { options.caseSnapshot = prepareCaseSnapshot({ runId: id, storePath: store.path, fixtureId, env }); }
      catch (failure) {
        if (failure.code !== 'CASE_SNAPSHOT_UNAVAILABLE') throw failure;
        options.unavailableInputs = ['casper-db'];
      }
    } else if (mode !== 'core-fixture' && !idorOrigin) {
      options.caseSnapshot = prepareCaseSnapshot({ runId: id, storePath: store.path, fixtureId, env });
    }
    const manifest = createRunManifest({ runId: id, mode, modelId, options, model, env });
    const experiment = store.experimentState();
    manifest.experiment = { epoch: experiment.epoch, lastResetAt: experiment.lastResetAt,
      previousRunCount: store.listRuns({ limit: 1 }).total };
    if (options.caseSnapshot) {
      manifest.data.caseSnapshotDigest = options.caseSnapshot.contentDigest;
      manifest.data.knowledgeSnapshotDigest = options.caseSnapshot.knowledgeDigest;
      manifest.data.knowledgeSnapshotFileDigest = options.caseSnapshot.fileDigest;
      manifest.data.caseRevisions = options.caseSnapshot.caseRevisions;
      manifest.data.caseStoreMigration = options.caseSnapshot.schemaVersion;
      manifest.data.caseDatabaseSourcePath = options.caseSnapshot.sourcePath;
    }
    const state = { ...emptyRun(), id, coreRunId: id, status: 'queued', mode, modelId,
      ...(general ? { assessmentMode: 'general' } : {}),
      target: mode === 'core-fixture' || idorOrigin ? target : 'http://127.0.0.1/',
      simulated: mode === 'core-fixture', testProfile, fixtureId, manifest };
    store.createRun({ id, mode, modelId, manifest, state, options });
    selectedRunId = id; ensureWorker(); publish(true);
    child?.send({ type: 'wake' });
    return getState();
  }
  function stop(id) {
    if (closing || closed) throw fault(503, 'Run service is closed.');
    store.requestCancel(id); selectedRunId = id;
    child?.send({ type: 'cancel', runId: id }); publish(true); return getState();
  }
  function reset() {
    if (resetting || store.experimentState().status !== 'ready') throw fault(409, '실험 초기화를 완료한 뒤 화면을 초기화하세요.');
    if (ACTIVE_STATUSES.includes(getState().run.status)) throw fault(409, 'Stop the active run before resetting.');
    selectedRunId = null; idleRun = emptyRun(); publish(true); return getState();
  }
  function experimentResetPreview() {
    const control = store.experimentState();
    return { ...control, runCount: store.listRuns({ limit: 1 }).total,
      pendingTargetResetCount: store.pendingTargetResets().length,
      canReset: !closing && !closed && !resetting && ['ready', 'failed'].includes(control.status) && store.activeRunCount() === 0,
      deletes: ['실행 이력과 비교 결과', '이벤트·모델 호출·검토 기록', 'JSON·HWPX·촬영 및 보고서 작업 파일', '실행별 사례 DB snapshot과 연결된 재검증 기록', '관리 대상 실습 웹사이트 상태'],
      preserves: ['로그인 계정과 API 설정', '검토된 사례·카탈로그·소스 코드'],
      limitations: ['브라우저에서 내려받은 파일, 다른 탭의 메모리, 외부 API 제공자 기록과 운영체제·외부 서버 로그는 앱이 삭제할 수 없습니다.'] };
  }
  async function withMutationLock(operation) {
    if (closing || closed || resetting) throw fault(409, '실험 초기화 중에는 검토를 저장할 수 없습니다.');
    const token = `api-${process.pid}-mutation-${randomUUID()}`;
    store.beginExperimentMutation(token);
    const task = Promise.resolve().then(operation);
    mutationTasks.add(task);
    try { return await task; }
    finally { mutationTasks.delete(task); store.endExperimentMutation(token); publish(true); ensureWorker(); }
  }
  async function stopIdleWorker() {
    clearTimeout(restartTimer);
    if (!child) return;
    const exiting = child;
    await new Promise((resolveExit, rejectExit) => {
      const exited = () => { clearTimeout(timer); resolveExit(); };
      const timer = setTimeout(() => {
        exiting.removeListener('exit', exited);
        rejectExit(fault(503, '실습 프로세스 정리를 기다리고 있습니다. 잠시 후 초기화를 다시 시도하세요.'));
      }, workerShutdownMs);
      exiting.once('exit', exited);
      try { exiting.send({ type: 'shutdown' }); }
      catch (failure) { clearTimeout(timer); exiting.removeListener('exit', exited); rejectExit(failure); }
    });
  }
  async function performExperimentReset(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.confirmed !== true
      || Object.keys(body).some(key => key !== 'confirmed')) throw fault(400, '전체 실험 기록 삭제를 명시적으로 확인하세요.');
    if (closing || closed) throw fault(503, 'Run service is closed.');
    if (resetting) throw fault(409, '다른 실험 초기화가 진행 중입니다.');
    resetting = true;
    const token = `api-${process.pid}-reset-${randomUUID()}`;
    let locked = false;
    try {
      await ready;
      store.beginExperimentReset(token); locked = true; publish(true);
      const runs = []; let offset = 0;
      while (true) {
        const page = store.listRuns({ limit: 200, offset }); runs.push(...page.items); offset += page.items.length;
        if (offset >= page.total) break;
      }
      await stopIdleWorker();
      // Quiesce the worker before validating participants: terminal publication
      // can precede its final browser/process teardown by a few milliseconds.
      const files = await prepareRunFileCleanup({ ...experimentFileOptions, runs, storePath: store.path });
      const cleanup = await experimentCleanupFactory({ runs: [...runs, ...store.pendingTargetResets()], storePath: store.path, env });
      const summary = await cleanup.execute();
      const fileSummary = await files.execute();
      const result = store.completeExperimentReset(token, { ...summary, runFiles: fileSummary });
      selectedRunId = null; idleRun = emptyRun();
      const state = { ...getState(), experimentReset: { ...store.experimentState(), ...result, status: 'completed' } };
      publish(true); return state;
    } catch (failure) {
      if (locked) store.failExperimentReset(token);
      publish(true);
      const known = ['UNSAFE_EXPERIMENT_FILES', 'EXPERIMENT_HISTORY_RESET_BLOCKED', 'EXPERIMENT_TARGET_RESET_BLOCKED'].includes(failure.code);
      throw locked ? fault(failure.status ?? 503, `전체 초기화를 완료하지 못했습니다. 새 실행은 차단되며 초기화를 다시 시도해야 합니다.${known ? ` ${failure.message}` : ''}`) : failure;
    } finally { resetting = false; ensureWorker(); }
  }
  function resetExperiment(body) {
    if (resetTask) return Promise.reject(fault(409, '다른 실험 초기화가 진행 중입니다.'));
    resetTask = performExperimentReset(body).finally(() => { resetTask = null; });
    return resetTask;
  }
  async function performRunHistoryClear(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.confirmed !== true
      || Object.keys(body).some(key => key !== 'confirmed')) throw fault(400, '실행 기록 삭제를 명시적으로 확인하세요.');
    if (closing || closed) throw fault(503, 'Run service is closed.');
    if (resetting) throw fault(409, '다른 초기화가 진행 중입니다.');
    resetting = true;
    const token = `api-${process.pid}-reset-${randomUUID()}`;
    let locked = false;
    try {
      await ready;
      const { previousStatus } = store.beginExperimentReset(token); locked = true; publish(true);
      const runs = []; let offset = 0;
      while (true) {
        const page = store.listRuns({ limit: 200, offset }); runs.push(...page.items); offset += page.items.length;
        if (offset >= page.total) break;
      }
      await stopIdleWorker();
      const files = await prepareRunFileCleanup({ ...experimentFileOptions, runs, storePath: store.path });
      const history = await prepareHistoryReset({ runs, env });
      const historyResult = await history.execute();
      const fileResult = await files.execute();
      const result = store.completeRunHistoryClear(token, {
        newTargetObligations: targetResetObligationsForRuns(runs), wasFailed: previousStatus === 'failed',
        summary: { history: historyResult, runFiles: fileResult },
      });
      selectedRunId = null; idleRun = emptyRun();
      const state = { ...getState(), historyClear: { ...result, status: 'completed' } };
      publish(true); return state;
    } catch (failure) {
      if (locked) store.failExperimentReset(token);
      publish(true);
      const known = ['UNSAFE_EXPERIMENT_FILES', 'EXPERIMENT_HISTORY_RESET_BLOCKED'].includes(failure.code);
      throw locked ? fault(failure.status ?? 503, `실행 기록 삭제를 완료하지 못했습니다. 초기화를 다시 시도해야 합니다.${known ? ` ${failure.message}` : ''}`) : failure;
    } finally { resetting = false; ensureWorker(); }
  }
  function clearRunHistory(body) {
    if (resetTask) return Promise.reject(fault(409, '다른 초기화가 진행 중입니다.'));
    resetTask = performRunHistoryClear(body).finally(() => { resetTask = null; });
    return resetTask;
  }
  function close() {
    if (closeTask) return closeTask;
    closing = true; clearInterval(poller); clearTimeout(restartTimer);
    closeTask = (async () => {
      await resetTask?.catch(() => {});
      await Promise.allSettled([...mutationTasks]);
      if (child) {
        const exiting = child;
        const exited = new Promise(resolve => exiting.once('exit', resolve));
        exiting.send({ type: 'shutdown' });
        const timer = setTimeout(() => exiting.kill('SIGTERM'), 5000); timer.unref();
        const force = setTimeout(() => exiting.kill('SIGKILL'), 8000); force.unref();
        await exited; clearTimeout(timer); clearTimeout(force);
      }
      await ready;
      closed = true; listeners.clear(); store.close();
    })();
    return closeTask;
  }
  return { getState, start, startLab: ({ modelId = 'rule-baseline', ...options } = {}) => start({ ...options,
    modelId, mode: modelId === 'rule-baseline' ? 'local-lab-rule' : 'local-lab-deepseek' }),
    stop, reset, resetExperiment, clearRunHistory, experimentResetPreview, withMutationLock, close, listModels, store, ready,
    getGeneralLoopBudget: () => store.getGeneralLoopBudget(),
    setGeneralLoopBudget: limits => store.setGeneralLoopBudget(limits),
    importLegacyRuns: options => withMutationLock(() => importLegacyRuns(store, options)),
    listRuns: filters => store.listRuns(filters), getRun: id => store.getRun(id),
    compareRuns: (base, candidate, options) => compareRunRecords(store.getRun(base), store.getRun(candidate), options),
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); } };
}
