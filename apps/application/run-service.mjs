import { fork } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRunRepository, DEFAULT_STORE_PATH } from '../../packages/run-store/index.mjs';
import { createRunManifest } from '../../packages/contracts/manifest.mjs';
import { emptyRun, RUN_MODES, ACTIVE_STATUSES } from '../../packages/contracts/index.mjs';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import { compareRunRecords } from '../../packages/evaluation/index.mjs';
import { listModels as registryModels } from '../../packages/models/registry.mjs';
import { prepareCaseSnapshot } from './case-snapshot.mjs';
import { importLegacyRuns } from './import-legacy.mjs';

const fault = (status, message) => Object.assign(new Error(message), { status });
const workerFile = fileURLToPath(new URL('../worker/worker.mjs', import.meta.url));
const IDOR_FIXTURES = Object.freeze({
  'vul-web2-daehan': 'http://127.0.0.1:4101',
  'vul-web2-wonchang': 'http://127.0.0.1:4102',
});

/** API-side application service. It never runs the lab in the HTTP process. */
export function createRunService({ storePath = DEFAULT_STORE_PATH, autoStartWorker = true,
  pollMs = 100, workerOptions = {}, envFile, env = process.env, defaultDelayMs = 0, importLegacy = true } = {}) {
  const store = createRunRepository({ path: storePath });
  store.recoverExpired();
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
  let idleRun = emptyRun(); let child = null; let closing = false; let closed = false;
  let lastRevision = ''; let closeTask; let restartTimer; let restartDelay = 200;
  const owner = `worker-${randomUUID()}`;
  function listModels() { return registryModels({ envFile, env }); }
  function getState() {
    const selected = selectedRunId ? store.getRun(selectedRunId) : null;
    const run = selected && RUN_MODES.includes(selected.mode) ? selected : idleRun;
    const models = listModels(); const remote = models.find(model => model.provider === 'deepseek' && model.available);
    return { run, mode: run.mode, instanceId, lab: { available: true, model: 'rule-baseline', provider: 'rules',
      remoteAvailable: Boolean(remote), models } };
  }
  function publish(force = false) {
    if (closed) return;
    const state = getState(); const revision = JSON.stringify(state);
    if (!force && revision === lastRevision) return;
    lastRevision = revision;
    for (const listener of listeners) { try { listener(state); } catch { /* Subscriber failure does not stop the queue. */ } }
  }
  function ensureWorker() {
    if (child || closing || !autoStartWorker) return;
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
      if (!closing && autoStartWorker) {
        restartTimer = setTimeout(ensureWorker, restartDelay); restartTimer.unref();
        restartDelay = Math.min(restartDelay * 2, 5000);
      }
    });
  }
  const poller = setInterval(() => { if (!closing) { store.recoverExpired(); publish(); } }, pollMs);
  poller.unref();
  ensureWorker();
  const ready = importLegacy ? importLegacyRuns(store).then(result => {
    if (!selectedRunId && !closing) selectedRunId = latestInteractiveRunId();
    publish(); return result;
  }).catch(() => ({ imported: 0, errors: [{ code: 'LEGACY_IMPORT_FAILED' }] })) : Promise.resolve({ imported: 0, errors: [] });

  async function start(body = {}) {
    if (closing || closed) throw fault(503, 'Run service is closed.');
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['mode', 'modelId', 'target', 'delayMs', 'testProfile', 'fixtureId'].includes(key))) {
      throw fault(400, 'Unsupported run options.');
    }
    const fixtureId = body.fixtureId ?? 'vul-web-1';
    if (typeof fixtureId !== 'string') throw fault(400, 'Choose a registered local fixture.');
    const idorOrigin = Object.hasOwn(IDOR_FIXTURES, fixtureId) ? IDOR_FIXTURES[fixtureId] : null;
    if (fixtureId !== 'vul-web-1' && !idorOrigin) throw fault(400, 'Choose a registered local fixture.');
    const mode = body.mode ?? (idorOrigin ? 'local-lab-rule'
      : body.modelId && body.modelId !== 'rule-baseline' ? 'local-lab-deepseek' : 'core-fixture');
    if (!RUN_MODES.includes(mode)) throw fault(400, 'Unsupported run mode.');
    const modelId = body.modelId ?? (mode === 'local-lab-deepseek' ? 'deepseek-flash' : 'rule-baseline');
    if (idorOrigin && (mode !== 'local-lab-rule' || modelId !== 'rule-baseline')) {
      throw fault(400, 'University fixtures support only the rule baseline known-record IDOR check.');
    }
    const model = listModels().find(item => item.id === modelId);
    if (!model) throw fault(400, 'Choose a registered model.');
    if (!model.available) throw fault(503, 'Selected model is unavailable. Configure server credentials before starting.');
    if ((mode === 'core-fixture' || mode === 'local-lab-rule') && modelId !== 'rule-baseline') throw fault(400, 'Rule or fixture mode requires rule-baseline.');
    if (mode === 'local-lab-deepseek' && modelId === 'rule-baseline') throw fault(400, 'DeepSeek mode requires a registered DeepSeek model.');
    if (mode !== 'core-fixture' && !idorOrigin && body.target !== undefined) throw fault(400, 'The board lab does not accept a target URL.');
    const delayMs = body.delayMs ?? defaultDelayMs;
    if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 3000) throw fault(400, 'delayMs must be 0..3000.');
    const testProfile = body.testProfile ?? (idorOrigin ? 'known_record_idor_read'
      : mode === 'core-fixture' ? 'agent_cross_user_delete_canary' : 'stored_xss_canary');
    if (idorOrigin ? testProfile !== 'known_record_idor_read'
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
    if (mode !== 'core-fixture' && !idorOrigin) options.caseSnapshot = prepareCaseSnapshot({ runId: id, storePath: store.path, env });
    const manifest = createRunManifest({ runId: id, mode, modelId, options, model, env });
    if (options.caseSnapshot) {
      manifest.data.caseSnapshotDigest = options.caseSnapshot.contentDigest;
      manifest.data.caseRevisions = options.caseSnapshot.caseRevisions;
      manifest.data.caseStoreMigration = options.caseSnapshot.schemaVersion;
      manifest.data.caseDatabaseSourcePath = options.caseSnapshot.sourcePath;
    }
    const state = { ...emptyRun(), id, coreRunId: id, status: 'queued', mode, modelId,
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
    if (ACTIVE_STATUSES.includes(getState().run.status)) throw fault(409, 'Stop the active run before resetting.');
    selectedRunId = null; idleRun = emptyRun(); publish(true); return getState();
  }
  function close() {
    if (closeTask) return closeTask;
    closing = true; clearInterval(poller); clearTimeout(restartTimer);
    closeTask = (async () => {
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
    stop, reset, close, listModels, store, ready,
    importLegacyRuns: options => importLegacyRuns(store, options),
    listRuns: filters => store.listRuns(filters), getRun: id => store.getRun(id),
    compareRuns: (base, candidate, options) => compareRunRecords(store.getRun(base), store.getRun(candidate), options),
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); } };
}
