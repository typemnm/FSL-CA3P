// Test helper: store one synthetic run through the real pentest-db and run-store writers so
// the Python collectors are checked against the actual storage code, not a copy of it.
// Reads {runId, events, report, reportsDir?, storePath?, legacyStorePath?, failedAppend?}
// as JSON on stdin.
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const require = createRequire(import.meta.url);
const { createEnvelope } = require(`${root}agent/src/protocol.js`);
const { createPentestDb } = await import(pathToFileURL(join(root, 'packages/adapters/integrations/pentest-db.mjs')));

const spec = JSON.parse(readFileSync(0, 'utf8'));
const { runId } = spec;

function storageRequest(iteration, payload) {
  return createEnvelope({ runId, iteration, sender: 'agent', receiver: 'pentest-db',
    type: 'storage.request', payload });
}

const requests = spec.events.map(event => storageRequest(event.iteration,
  { operation: 'append', event: { stage: event.stage, request: event.request, response: event.response } }));
if (spec.report) requests.push(storageRequest(spec.report.iterations ?? 1, { operation: 'finalize', report: spec.report }));

// Always store through the real adapter: its replies are what the runtime records.
const pentestDb = createPentestDb({ reportsDir: spec.reportsDir ?? mkdtempSync(join(tmpdir(), 'report-test-')) });
const replies = [];
for (const request of requests) replies.push(JSON.parse(await pentestDb.exchange(JSON.stringify(request))));

const { createRunRepository } = spec.storePath || spec.legacyStorePath
  ? await import(pathToFileURL(join(root, 'packages/run-store/index.mjs'))) : {};

if (spec.storePath) {
  const repository = createRunRepository({ path: spec.storePath });
  repository.createRun({ id: runId, mode: 'local-lab-rule', modelId: 'rule-baseline',
    manifest: { schemaVersion: '1.0', runId }, state: { id: runId } });
  const lease = repository.claimNext('report-test-worker');
  // Same shape as appendEvent() in apps/application/local-runtime.mjs: every exchange becomes a
  // runtime event, including other modules and failed exchanges, which the collector must drop.
  const events = [];
  const add = event => events.push({ id: `${runId}:event-${events.length + 1}`,
    time: new Date(Date.UTC(2026, 9, 20, 0, 0, events.length)).toISOString(), ...event });
  requests.forEach((request, index) => {
    add({ module: 'attack', type: 'info', source: 'test', stage: 'execute_curl', title: 'unrelated',
      request: { receiver: 'attack-module', payload: { operation: 'execute_curl' } }, response: {} });
    add({ module: 'pentest', type: index === requests.length - 1 && spec.report ? 'success' : 'info',
      source: 'test', stage: request.payload.event?.stage ?? 'finalize', title: 'storage',
      iteration: request.iteration, correlationId: request.correlationId, request, response: replies[index] });
  });
  if (spec.failedAppend) {
    const request = storageRequest(1, { operation: 'append',
      event: { stage: 'loop.never_stored', request: {}, response: {} } });
    add({ module: 'pentest', type: 'error', source: 'test', stage: 'append', title: 'pentest-db 실패',
      iteration: 1, correlationId: request.correlationId, request,
      response: { sender: 'agent_gateway', receiver: 'agent', type: 'module.error',
        payload: { error: { code: 'GATEWAY_FAILURE', message: 'disk full' } } } });
  }
  repository.saveState(lease, { id: runId, status: 'completed', mode: 'local-lab-rule',
    report: spec.report ?? null, events });
  repository.finish(lease, 'completed');
  repository.close();
}

if (spec.legacyStorePath) {
  // The exact path apps/application/import-legacy.mjs takes: readRun() into importLegacyRun().
  const repository = createRunRepository({ path: spec.legacyStorePath });
  repository.importLegacyRun(await pentestDb.readRun(runId));
  repository.close();
}
