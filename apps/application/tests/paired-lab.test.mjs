import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createLocalRuntime } from '../local-runtime.mjs';
import { startLocalLab } from '../../../packages/adapters/local-lab-gateway.mjs';
import { evaluateCases } from '../../../packages/evaluation/index.mjs';
import reasoning from '../../../agent/src/reasoning-engine.js';

test('paired isolated boards distinguish browser-executed XSS from text rendering', { timeout: 90_000 }, async t => {
  const require = createRequire(new URL('../../../xss-parser/package.json', import.meta.url));
  let browser;
  try { browser = process.env.XSS_PARSER_BROWSER_PATH ?? require('playwright').chromium.executablePath(); }
  catch { /* Required CI mode fails below. */ }
  if (!browser || !existsSync(browser)) {
    if (process.env.CA3P_REQUIRE_BROWSER === '1') assert.fail('Required Chromium is missing.');
    t.skip('Chromium is not installed.'); return;
  }
  async function run(safeMode) {
    const runtime = createLocalRuntime({ defaultDelayMs: 0, labMode: 'local-lab-rule',
      labConfigProvider: () => ({ provider: 'rules', model: 'rule-baseline' }),
      labReasoningFactory: () => new reasoning.RuleReasoningEngine(),
      labFactory: ({ profile }) => startLocalLab({ profile, safeMode }),
    });
    t.after(() => runtime.close());
    await runtime.startLab();
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      const state = runtime.getState().run;
      if (['completed', 'failed', 'stopped'].includes(state.status)) return state;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.fail('Paired board timed out.');
  }
  const vulnerable = await run(false);
  const patched = await run(true);
  assert.equal(vulnerable.status, 'completed', vulnerable.error);
  assert.equal(patched.status, 'completed', patched.error);
  assert.equal(vulnerable.report.finding.status, 'confirmed');
  assert.equal(vulnerable.report.finding.checks.executed, true);
  assert.equal(patched.report.finding.status, 'not_confirmed');
  assert.equal(patched.report.finding.checks.executed, false);
  assert.equal(patched.targetContacted, true);
  const quality = evaluateCases([
    { vulnerable: true, result: 'confirmed' },
    { vulnerable: false, result: 'not_reproduced' },
  ]);
  assert.equal(quality.precision, 1);
  assert.equal(quality.endToEndRecall, 1);
  assert.equal(quality.coverage, 1);
});
