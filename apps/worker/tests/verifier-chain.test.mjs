import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunService } from '../../application/run-service.mjs';
import { createGeneralRuntime } from '../../application/general-runtime.mjs';
import { generateReportDocument } from '../../../packages/report/index.mjs';
import { digest } from '../../../packages/contracts/index.mjs';
import { runWorker } from '../worker.mjs';

const FINDING_ID = 'finding:h-access';
const PROBE_ID = 'p-access';

async function waitFor(check) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('verifier chain run did not finish');
}

// The planner proposes only the registered board canary; the verifier is the scripted model under test.
function canaryPlanner() {
  return { async propose(context) {
    const modelMetadata = { provider: 'deepseek', requestedModel: 'deepseek-flash',
      status: 'completed', usage: { prompt_tokens: 8, completion_tokens: 3 } };
    if (context.iteration > 1) return { done: true, hypotheses: [], probes: [], modelMetadata };
    return { done: false, hypotheses: [{ id: 'h-access', category: 'access_control',
      asset: '/api/posts/:id', rationale: 'Bob-owned post delete by Alice should be denied.',
      evidenceIds: [context.evidence[0].id] }],
    probes: [{ id: PROBE_ID, hypothesisId: 'h-access', tool: 'known_cross_user_delete_canary', input: {} }],
    modelMetadata };
  } };
}

function zipEntries(path) {
  const python = process.env.CA3P_REPORT_PYTHON;
  const script = 'import sys, zipfile; print("\\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))';
  return execFileSync(python, ['-I', '-c', script, path], { encoding: 'utf8' }).split('\n').filter(Boolean);
}

// Runs the real service and worker on a fresh vul-web-1 board; the verifier model is the only scripted part.
async function runChain(t, verifierModel) {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'verifier-chain-'));
  const storePath = join(directory, 'runs.sqlite');
  const env = { ...process.env, DEEPSEEK_API_KEY: 'synthetic-test-only' };
  const reportCalls = [];
  let service; let worker;
  try {
    service = createRunService({ storePath, autoStartWorker: false, importLegacy: false, envFile: null, env });
    const queued = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-flash', fixtureId: 'vul-web-1' });
    const id = queued.run.id;
    worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 20, env,
      generalPlannerFactory: canaryPlanner,
      generalRuntimeFactory: options => createGeneralRuntime({ ...options, verifierModel }),
      reportGenerator: options => { reportCalls.push(options); return generateReportDocument(options); } });
    const final = await waitFor(() => { const run = service.getRun(id); return run.status === 'completed' && run; });
    return { id, final, storePath, worker, reportCalls, verificationRoot: join(dirname(storePath), 'artifacts', digest(id), 'verifications') };
  } catch (error) {
    await worker?.shutdown(); worker = null;
    throw error;
  } finally {
    t.after(async () => {
      await worker?.shutdown();
      await service?.close();
      rmSync(directory, { recursive: true, force: true });
    });
  }
}

function assertConfirmedWithHwpx(result) {
  const { final, verificationRoot, reportCalls, worker } = result;
  assert.equal(final.report.findings.find(item => item.id === FINDING_ID).status, 'confirmed');
  const verificationDir = join(verificationRoot, PROBE_ID);
  assert.ok(existsSync(join(verificationDir, 'verification.json')));
  assert.equal(reportCalls.length, 1);
  assert.equal(reportCalls[0].verificationDir, verificationDir);
  assert.equal(final.reportDocuments.status, 'ready', JSON.stringify(final.reportDocuments));
  const item = final.reportDocuments.items[0];
  assert.deepEqual([item.findingId, item.status], [FINDING_ID, 'ready']);
  return worker.store.getArtifact(item.artifactId).path;
}

test('a confirmed AI verdict reaches the HWPX report through the verification handoff', { timeout: 120_000 }, async t => {
  const verifierModel = { async completeJson({ userPayload }) {
    assert.equal(userPayload.round, 1);
    return { value: { verdict: 'valid', reason: `Alice DELETE of Bob's post returned HTTP ${userPayload.attack.response.status}.` },
      metadata: { model: 'scripted' } };
  } };
  const result = await runChain(t, verifierModel);
  const hwpx = assertConfirmedWithHwpx(result);
  assert.match(hwpx, /\.hwpx$/);
  assert.ok(existsSync(hwpx));
});

test('a browser visit by the verifier puts a screenshot into the HWPX as a BinData image', { timeout: 120_000 }, async t => {
  const verifierModel = { async completeJson({ userPayload }) {
    if (!userPayload.browserObservation) {
      return { value: { verdict: 'unknown', reason: 'Needs the rendered page as alice.',
        browser: { path: '/', role: 'alice' } }, metadata: { model: 'scripted' } };
    }
    return { value: { verdict: 'valid', reason: 'Observed the rendered board page as alice.' },
      metadata: { model: 'scripted' } };
  } };
  const result = await runChain(t, verifierModel);
  const hwpx = assertConfirmedWithHwpx(result);
  const handoff = join(result.verificationRoot, PROBE_ID);
  assert.ok(existsSync(join(handoff, 'images')));
  const entries = zipEntries(hwpx);
  assert.ok(entries.some(name => name.startsWith('BinData/')), JSON.stringify(entries));
});
