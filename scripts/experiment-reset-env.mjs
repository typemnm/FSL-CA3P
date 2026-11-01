import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const TOKEN = /^[A-Za-z0-9._~+/-]{32,512}$/u;
export const RESET_ENV_NAME = 'experiment-reset.env';

export function resetEnvPath(runtimeDir) {
  return join(runtimeDir, RESET_ENV_NAME);
}

export function parseResetEnv(text) {
  const values = {};
  for (const line of String(text).split(/\r?\n/u)) {
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    values[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return values;
}

export function hostExperimentResetTargets(tokens) {
  return {
    'vul-web2-daehan': {
      origin: 'http://127.0.0.1:54101',
      targetOrigin: 'http://127.0.0.1:4101',
      token: tokens.daehan,
    },
    'vul-web2-wonchang': {
      origin: 'http://127.0.0.1:54102',
      targetOrigin: 'http://127.0.0.1:4102',
      token: tokens.wonchang,
    },
  };
}

function tokenOrNew(value) {
  return TOKEN.test(value ?? '') ? value : randomBytes(32).toString('base64url');
}

export async function ensureExperimentResetTokens(runtimeDir) {
  await mkdir(runtimeDir, { recursive: true, mode: 0o700 });
  await chmod(runtimeDir, 0o700);
  const path = resetEnvPath(runtimeDir);
  let existing = {};
  try { existing = parseResetEnv(await readFile(path, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const daehan = tokenOrNew(existing.CA3P_DAEHAN_RESET_TOKEN);
  const wonchang = tokenOrNew(existing.CA3P_WONCHANG_RESET_TOKEN);
  if (daehan !== existing.CA3P_DAEHAN_RESET_TOKEN || wonchang !== existing.CA3P_WONCHANG_RESET_TOKEN) {
    await writeFile(path, `CA3P_DAEHAN_RESET_TOKEN=${daehan}\nCA3P_WONCHANG_RESET_TOKEN=${wonchang}\n`, { mode: 0o600 });
    await chmod(path, 0o600);
  }
  return { daehan, wonchang, path };
}

export async function applyHostExperimentResetEnv(env, runtimeDir) {
  if (env.CA3P_EXPERIMENT_RESET_TARGETS) return false;
  let text;
  try { text = await readFile(resetEnvPath(runtimeDir), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  const parsed = parseResetEnv(text);
  if (!TOKEN.test(parsed.CA3P_DAEHAN_RESET_TOKEN ?? '') || !TOKEN.test(parsed.CA3P_WONCHANG_RESET_TOKEN ?? '')) {
    return false;
  }
  env.CA3P_EXPERIMENT_RESET_TARGETS = JSON.stringify(hostExperimentResetTargets({
    daehan: parsed.CA3P_DAEHAN_RESET_TOKEN, wonchang: parsed.CA3P_WONCHANG_RESET_TOKEN,
  }));
  return true;
}
