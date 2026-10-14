import { spawn } from 'node:child_process';
import { access, mkdir } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../casper-db/', import.meta.url));
const PYTHON_SOURCE = join(ROOT, 'src');
const DEFAULT_DB = join(ROOT, 'data', 'cases.sqlite3');
const MAX_OUTPUT_BYTES = 1_000_000;
const MAX_OBSERVATIONS = 48;
const PYTHON_CODE = String.raw`
import json, sys
from pathlib import Path
from casper_db.repository import CaseStore, initialize_database
from casper_db.matching import assess_observation

request = json.load(sys.stdin)
db = Path(request['database'])
if not db.exists():
    initialize_database(db)
store = CaseStore(db)
target_id = request['targetId']
cases = store.list_for_target(target_id)
assessments = [assess_observation(store, item).model_dump() for item in request['observations']]
json.dump({'targetId': target_id, 'readyCaseCount': len(cases), 'assessments': assessments}, sys.stdout, ensure_ascii=False)
`;

function absoluteDatabasePath(value) {
  if (value === undefined) return DEFAULT_DB;
  if (typeof value !== 'string' || !isAbsolute(value)) {
    throw new Error('CASPER_DB_PATH must be an absolute path.');
  }
  return resolve(value);
}

/** Translate only explicit parser API hints to historical-case lookup locations. */
export function observationsFromParser(report, { targetId = 'vul-web-1', origin } = {}) {
  if (!report || !Array.isArray(report.pages) || typeof origin !== 'string') {
    throw new TypeError('A parser report and exact target origin are required.');
  }
  const allowed = new URL(origin);
  const seen = new Set();
  const observations = [];
  for (const page of report.pages) {
    for (const behavior of page.behaviors || []) {
      for (const api of behavior.api || []) {
        if (!api || typeof api.url !== 'string' || typeof api.method !== 'string') continue;
        let url;
        try { url = new URL(api.url); } catch { continue; }
        if (url.origin !== allowed.origin || /[{}]/u.test(url.pathname)) continue;
        const method = api.method.toUpperCase();
        if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue;
        const fields = [];
        for (const key of api.bodyKeys || []) {
          if (typeof key === 'string' && key.length > 0) fields.push([key, 'body']);
        }
        for (const key of url.searchParams.keys()) fields.push([key, 'query']);
        for (const [parameter, parameter_location] of fields) {
          const item = { target_id: targetId, endpoint: url.pathname, method, parameter, parameter_location };
          const id = JSON.stringify(item);
          if (seen.has(id)) continue;
          seen.add(id);
          observations.push(item);
          if (observations.length >= MAX_OBSERVATIONS) return observations;
        }
      }
    }
  }
  return observations;
}

function runPython(input, { python, signal } = {}) {
  const command = python || process.env.CASPER_DB_PYTHON || 'python';
  return new Promise((resolveOutput, rejectOutput) => {
    const child = spawn(command, ['-c', PYTHON_CODE], {
      cwd: ROOT,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONPATH: PYTHON_SOURCE },
      signal,
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    child.stdout.on('data', chunk => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) child.kill();
      else stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      if (Buffer.concat(stderr).length < 8192) stderr.push(chunk);
    });
    child.on('error', error => rejectOutput(new Error(`casper-db Python process failed: ${error.message}`)));
    child.on('close', code => {
      if (outputBytes > MAX_OUTPUT_BYTES) return rejectOutput(new Error('casper-db output exceeded 1 MB.'));
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString('utf8').slice(-2000);
        return rejectOutput(new Error(`casper-db lookup failed: ${detail || `exit ${code}`}`));
      }
      try { resolveOutput(JSON.parse(Buffer.concat(stdout).toString('utf8'))); }
      catch { rejectOutput(new Error('casper-db returned invalid JSON.')); }
    });
    child.stdin.end(JSON.stringify(input));
  });
}

export async function matchCasperHistory({ report, origin, targetId = 'vul-web-1', databasePath, python, signal } = {}) {
  const observations = observationsFromParser(report, { targetId, origin });
  const database = absoluteDatabasePath(databasePath ?? process.env.CASPER_DB_PATH);
  try { await access(database); }
  catch { await mkdir(dirname(database), { recursive: true }); }
  const result = await runPython({ database, targetId, observations }, { python, signal });
  if (!result || result.targetId !== targetId || !Array.isArray(result.assessments)
    || result.assessments.length !== observations.length || !Number.isInteger(result.readyCaseCount)) {
    throw new Error('casper-db response does not match the parser lookup contract.');
  }
  return { source: 'casper-db', targetId, readyCaseCount: result.readyCaseCount, observations, assessments: result.assessments };
}
