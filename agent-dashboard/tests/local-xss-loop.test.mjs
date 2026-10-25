import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test from 'node:test';
import orchestrator from '../../agent/src/orchestrator.js';
import deepSeek from '../../agent/src/deepseek-reasoning-engine.js';
import { startLocalLab } from '../local-lab-gateway.mjs';
import { createLocalRuntime } from '../local-runtime.mjs';

const { runOnce } = orchestrator;
const { DeepSeekReasoningEngine, STORED_XSS_ACTION_CATALOG_ID } = deepSeek;

async function browserAvailable() {
  try {
    const { chromium } = await import('../../xss-parser/node_modules/playwright/index.mjs');
    return existsSync(process.env.XSS_PARSER_BROWSER_PATH || chromium.executablePath());
  } catch { return false; }
}

function waitFor(runtime, predicate, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { unsubscribe(); reject(new Error('XSS lab did not finish.')); }, timeoutMs);
    const unsubscribe = runtime.subscribe(state => {
      if (!predicate(state)) return;
      clearTimeout(timer);
      unsubscribe();
      resolve(state);
    });
  });
}

test('one local Agent loop posts a bounded XSS canary and confirms browser execution',
  { timeout: 60_000 }, async t => {
    if (!await browserAvailable()) {
      t.skip('Playwright Chromium is not installed.');
      return;
    }
    const lab = await startLocalLab();
    t.after(() => lab.close());
    let modelCalls = 0;
    let approvedCurl;
    const reasoningEngine = new DeepSeekReasoningEngine({
      curlMode: true,
      client: { async completeJson({ userPayload }) {
        modelCalls += 1;
        approvedCurl = userPayload.allowedCurl;
        assert.deepEqual(userPayload.allowedActionCatalogIds,
          [STORED_XSS_ACTION_CATALOG_ID]);
        return {
          value: { state: 'act', candidateId: 'candidate-0',
            actionCatalogId: STORED_XSS_ACTION_CATALOG_ID, curl: approvedCurl },
          metadata: { model: 'deepseek-flash', finishReason: 'stop' },
        };
      } },
    });
    const { report } = await runOnce({
      gateway: lab.gateway,
      targetOrigin: lab.origin,
      targetApplication: 'owned-local-board',
      testProfile: 'stored_xss_canary',
      reasoningEngine,
    });
    assert.equal(modelCalls, 1);
    assert.equal(report.status, 'completed');
    assert.equal(report.testProfile, 'stored_xss_canary');
    assert.equal(report.finding.cwe, 'CWE-79');
    assert.equal(report.finding.status, 'confirmed');
    assert.equal(report.finding.checks.executed, true);
    assert.equal(report.finding.checks.postIdMatches, true);
    assert.equal(report.finding.checks.markerMatches, true);
    assert.equal(report.metrics.requestCount, 2);
    assert.equal(report.metrics.parserRuns, 2);
    assert.equal(approvedCurl.method, 'POST');
    assert.equal(approvedCurl.url, `${lab.origin}/api/posts`);
    assert.equal(approvedCurl.body.title.endsWith(report.finding.marker), true);
    const posts = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
    assert.equal(posts.posts.filter(post => post.title === approvedCurl.body.title).length, 1);
    assert.equal(report.referenceContext.pentestDb.available, true);
    await lab.close();
    await assert.rejects(fetch(`${lab.origin}/api/posts`));
  });

test('the dashboard local-lab action presents the one-pass XSS finding and module trace',
  { timeout: 60_000 }, async t => {
    if (!await browserAvailable()) {
      t.skip('Playwright Chromium is not installed.');
      return;
    }
    const runtime = createLocalRuntime({
      defaultDelayMs: 0,
      labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash', possibleRetries: 0 }),
      labReasoningFactory: () => new DeepSeekReasoningEngine({
        curlMode: true,
        client: { async completeJson({ userPayload }) {
          return { value: { state: 'act', candidateId: 'candidate-0',
            actionCatalogId: STORED_XSS_ACTION_CATALOG_ID, curl: userPayload.allowedCurl },
          metadata: { model: 'deepseek-flash', finishReason: 'stop' } };
        } },
      }),
    });
    t.after(() => runtime.close());
    const started = await runtime.startLab();
    assert.equal(started.run.testProfile, 'stored_xss_canary');
    const { run } = await waitFor(runtime, state => ['completed', 'failed'].includes(state.run.status));
    assert.equal(run.status, 'completed', run.error);
    assert.equal(run.report.finding.status, 'confirmed');
    assert.equal(run.reviewItems[0].vulnerabilityConfirmed, true);
    assert.match(run.reviewItems[0].title, /XSS/);
    assert.equal(run.events.filter(event => event.source === 'attack-module/curl').length, 2);
    assert.equal(run.events.filter(event => event.source === 'xss-parser/browser').length, 2);
    assert.equal(run.events.length, 19);
    assert.equal(run.events.some(event => event.stage === 'loop.think'), true);
    assert.equal(run.events.some(event => event.stage === 'loop.reflect'), true);
  });
