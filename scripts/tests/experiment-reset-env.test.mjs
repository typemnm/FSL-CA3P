import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  applyHostExperimentResetEnv, ensureExperimentResetTokens, hostExperimentResetTargets, parseResetEnv,
} from '../experiment-reset-env.mjs';

test('token file is created once and reused for host dashboard reset targets', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ca3p-reset-env-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runtimeDir = join(root, 'runtime');
  const first = await ensureExperimentResetTokens(runtimeDir);
  const second = await ensureExperimentResetTokens(runtimeDir);
  assert.equal(first.daehan, second.daehan);
  assert.equal(first.wonchang, second.wonchang);
  assert.match(first.daehan, /^[A-Za-z0-9._~+/-]{32,512}$/);
  const env = {};
  assert.equal(await applyHostExperimentResetEnv(env, runtimeDir), true);
  assert.deepEqual(JSON.parse(env.CA3P_EXPERIMENT_RESET_TARGETS), hostExperimentResetTargets(first));
  env.CA3P_EXPERIMENT_RESET_TARGETS = '{"keep":true}';
  assert.equal(await applyHostExperimentResetEnv(env, runtimeDir), false);
  assert.equal(env.CA3P_EXPERIMENT_RESET_TARGETS, '{"keep":true}');
  const parsed = parseResetEnv(await readFile(first.path, 'utf8'));
  assert.equal(parsed.CA3P_DAEHAN_RESET_TOKEN, first.daehan);
});

test('host reset env is left unset when the token file is missing', async t => {
  const runtimeDir = await mkdtemp(join(tmpdir(), 'ca3p-reset-env-missing-'));
  t.after(() => rm(runtimeDir, { recursive: true, force: true }));
  const env = {};
  assert.equal(await applyHostExperimentResetEnv(env, runtimeDir), false);
  assert.equal(env.CA3P_EXPERIMENT_RESET_TARGETS, undefined);
});
