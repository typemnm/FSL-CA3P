import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { PROJECT_ROOT } from '../../../packages/contracts/manifest.mjs';
import { createRunService } from '../run-service.mjs';

test('credential-free rule lab confirms actual browser execution and freezes matching case snapshots',
  { timeout: 60_000 }, async t => {
    const require = createRequire(new URL('../../../xss-parser/package.json', import.meta.url));
    let browser;
    try { browser = process.env.XSS_PARSER_BROWSER_PATH ?? require('playwright').chromium.executablePath(); } catch { /* Required mode fails below. */ }
    const python = process.env.CASPER_DB_PYTHON ?? join(PROJECT_ROOT, '.venv/bin/python');
    const pythonReady = spawnSync(python, ['-c', 'import sys; assert sys.version_info >= (3, 11)'],
      { timeout: 10_000, stdio: 'ignore' }).status === 0;
    if (!browser || !existsSync(browser) || !pythonReady) {
      if (process.env.CA3P_REQUIRE_BROWSER === '1') assert.fail('Required Chromium and CASPER Python environment are missing.');
      t.skip('Chromium or CASPER Python is not installed.'); return;
    }
    const directory = mkdtempSync(join(tmpdir(), 'ca3p-rule-lab-test-'));
    const env = { ...process.env, CASPER_DB_PYTHON: python, CASPER_DB_PATH: join(directory, 'cases.sqlite'), DEEPSEEK_API_KEY: '' };
    const service = createRunService({ storePath: join(directory, 'runs.sqlite'), envFile: null, env });
    t.after(async () => { await service.close(); rmSync(directory, { recursive: true, force: true }); });
    async function execute() {
      const started = await service.startLab({ modelId: 'rule-baseline' });
      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline) {
        const run = service.getRun(started.run.id);
        if (['completed', 'failed', 'interrupted'].includes(run.status)) return run;
        await new Promise(resolve => setTimeout(resolve, 40));
      }
      assert.fail('Rule lab timed out.');
    }
    const first = await execute();
    assert.equal(first.status, 'completed', first.error);
    assert.equal(first.simulated, false); assert.equal(first.targetContacted, true);
    assert.equal(first.report.finding.status, 'confirmed'); assert.equal(first.report.finding.checks.executed, true);
    assert.equal(first.modelCalls.length, 0); assert.equal(first.id, first.report.runId);
    assert.equal(first.historyWrite?.status, 'not-applicable', 'terminal state must wait for case sync');
    assert.ok(first.artifacts.some(item => item.kind === 'run-report'), 'terminal state must include stored report evidence');
    assert.equal(service.store.listActions(first.id).filter(item => item.status === 'completed').length, 1);
    const second = await execute(); assert.equal(second.status, 'completed', second.error);
    assert.equal(first.manifest.data.caseSnapshotDigest, second.manifest.data.caseSnapshotDigest);
    const comparison = service.compareRuns(first.id, second.id);
    assert.equal(comparison.comparable, true, JSON.stringify(comparison.conditions.filter(item => !item.equal)));
    assert.equal(comparison.findingTransition.after, 'confirmed');
    assert.ok(first.manifest.environment.browserVersion);
  });
