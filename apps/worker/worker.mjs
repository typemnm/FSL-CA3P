import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../packages/run-store/index.mjs';
import { createLocalRuntime } from '../application/local-runtime.mjs';
import { createModelReasoning } from '../../packages/models/registry.mjs';
import { digest } from '../../packages/contracts/index.mjs';
import { startLocalLab } from '../../packages/adapters/local-lab-gateway.mjs';
import { syncRunChecks } from '../../packages/history/check-sync.mjs';
import { PROJECT_ROOT, treeDigest } from '../../packages/contracts/manifest.mjs';
import { join } from 'node:path';

export async function runWorker({ storePath, owner = `worker-${randomUUID()}`,
  pollMs = 150, leaseMs = 15_000, heartbeatMs = 1000, envFile } = {}) {
  const store = createRunRepository({ path: storePath });
  let stopping = false; let runtime = null; let activeLease = null; let busy = false; let timer; let shutdownTask;
  const notify = () => { if (process.connected) process.send({ type: 'state' }); };
  const cancel = runId => { if (activeLease?.runId === runId && runtime) { try { runtime.stop(runId); } catch { /* Already terminal. */ } } };
  async function tick() {
    if (busy || stopping) return;
    busy = true;
    let lease;
    try {
      lease = store.claimNext(owner, { leaseMs });
      if (!lease) return;
      activeLease = lease;
      const frozen = store.getRun(lease.runId).manifest;
      for (const [name, value] of Object.entries(frozen.modules ?? {})) {
        if (treeDigest(join(PROJECT_ROOT, name)) !== value.contentDigest) {
          throw Object.assign(new Error('Module content changed after this run was queued. Create a new run.'), { code: 'CONDITION_CHANGED' });
        }
      }
      for (const [field, path] of [['contractDigest', 'packages/contracts'], ['lockDigest', 'xss-parser/package-lock.json'], ['modelRegistryDigest', 'packages/models']]) {
        if (frozen.shared?.[field] && treeDigest(join(PROJECT_ROOT, path)) !== frozen.shared[field]) {
          throw Object.assign(new Error('Shared execution conditions changed after this run was queued.'), { code: 'CONDITION_CHANGED' });
        }
      }
      if (lease.options.caseSnapshot && treeDigest(lease.options.caseSnapshot.path) !== lease.options.caseSnapshot.fileDigest) {
        throw Object.assign(new Error('Historical-case snapshot changed after preparation.'), { code: 'CASE_SNAPSHOT_CHANGED' });
      }
      const controller = new AbortController();
      const engine = await createModelReasoning(lease.modelId, { signal: controller.signal,
        ...(envFile ? { envFile } : {}), onModelCall(metadata) {
          store.recordModelCall(lease, metadata); notify();
        } });
      let persistenceError = null;
      runtime = createLocalRuntime({ defaultDelayMs: lease.options.delayMs,
        runIdFactory: () => lease.runId, labMode: lease.mode,
        labTestProfile: lease.options.testProfile,
        labConfigProvider: () => ({ provider: lease.modelId === 'rule-baseline' ? 'rules' : 'deepseek', model: lease.modelId }),
        labReasoningFactory: () => engine,
        labFactory: options => startLocalLab({ ...options, casperDatabasePath: lease.options.caseSnapshot?.path }),
        async beforeExchange(request) {
          store.assertLease(lease, { allowCancelled: request.receiver === 'pentest-db' && request.payload.operation === 'finalize' });
          if (request.receiver === 'attack-module' && ['POST', 'DELETE'].includes(request.payload.curl?.method)) {
            const command = request.payload.curl;
            const target = new URL(command.url);
            const actionId = digest({ iteration: request.iteration, session: request.payload.session,
              method: command.method, path: target.pathname });
            store.reserveAction(lease, { actionId, request });
            return actionId;
          }
        },
        async afterExchange(request, response, reservation) {
          store.assertLease(lease, { allowCancelled: true });
          if (reservation) store.completeAction(lease, reservation, response);
        },
      });
      let resolveTerminal;
      const terminal = new Promise(resolve => { resolveTerminal = resolve; });
      const detach = runtime.subscribe(({ run }) => {
        if (!run.id) return;
        // Keep the public run active until report evidence and historical-case
        // checks have been stored. A terminal status must describe a complete run.
        const terminalState = ['completed', 'failed', 'stopped'].includes(run.status);
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
        if (lease.mode === 'core-fixture') runtime.start({ target: lease.options.target, delayMs: lease.options.delayMs });
        else await runtime.startLab();
        await terminal;
        if (persistenceError) throw persistenceError;
        const final = runtime.getState().run;
        const status = final.status === 'stopped' ? 'cancelled' : final.status;
        let finalState = { ...final, status, modelId: lease.modelId };
        if (final.report) {
          const artifact = store.writeArtifact(lease.runId, 'run-report', final.report, { contentType: 'application/json', provenance: 'verified-run-report' });
          let historyWrite;
          try { historyWrite = await syncRunChecks(final, { artifact, storePath: store.path,
            databasePath: lease.options.caseSnapshot?.sourcePath }); }
          catch (error) { historyWrite = { status: 'failed', checks: [], error: error.message }; }
          finalState = { ...finalState, historyWrite };
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
      activeLease = null; busy = false;
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
