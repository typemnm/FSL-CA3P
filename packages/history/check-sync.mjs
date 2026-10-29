import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const resultProgram = String.raw`
import json,sys
from pathlib import Path
from casper_db.repository import CaseStore
from casper_db.evidence import inspect_evidence
from casper_db.retest import import_retest_results
r=json.load(sys.stdin)
root=Path(r['evidenceRoot'])
if inspect_evidence(root,[r['artifactReference']])[0].sha256 != r['artifactSha256']:
    raise ValueError('run artifact changed before import')
store=CaseStore(Path(r['database']),evidence_root=root)
json.dump(import_retest_results(store,r['results'],apply=True),sys.stdout,ensure_ascii=False)
`;

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}

function pythonJson(code, input, { python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'), signal } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(python, ['-c', code], { cwd: root, shell: false, signal,
      env: { ...process.env, PYTHONPATH: join(root, 'casper-db/src'),
        PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '', bytes = 0;
    child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 1024 * 1024) child.kill(); else output += chunk; });
    child.stderr.resume();
    child.once('error', () => reject(new Error('과거 사례 저장용 Python 실행에 실패했습니다.')));
    child.once('close', code => {
      if (code !== 0 || bytes > 1024 * 1024) return reject(new Error('과거 사례 check 저장에 실패했습니다.'));
      try { resolveResult(JSON.parse(output)); } catch { reject(new Error('Invalid case history response.')); }
    });
    child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify(input));
  });
}

export async function syncRunChecks(run, { artifact, storePath, databasePath, python } = {}) {
  if (!run || run.simulated || !run.report || !artifact?.path) return { status: 'not-applicable', checks: [] };
  const evidenceRoot = resolve(process.env.CASPER_EVIDENCE_ROOT ?? join(dirname(resolve(storePath ?? '.runtime/runs.sqlite')), 'artifacts'));
  const reference = relative(evidenceRoot, resolve(artifact.path)).split('\\').join('/');
  if (reference.startsWith('../') || reference.startsWith('/') || reference.includes(':')) throw new Error('Case evidence must stay inside the artifact root.');
  const database = resolve(databasePath ?? process.env.CASPER_DB_PATH ?? join(root, 'casper-db/data/cases.sqlite3'));
  if (run.report.caseChecks !== undefined) {
    const results = run.report.caseChecks;
    if (results?.schema_version !== 'casper-check-results-1' || results.run_id !== run.id || !Array.isArray(results.results)) {
      throw new Error('Run caseChecks must identify this run and a supported result contract.');
    }
    if ((await stat(artifact.path)).size > 5_000_000) throw new Error('Run artifact exceeds 5 MB.');
    const bytes = await readFile(artifact.path);
    const saved = JSON.parse(bytes.toString('utf8'));
    const report = saved.report ?? saved;
    if (report.runId !== run.id || JSON.stringify(canonical(report.caseChecks)) !== JSON.stringify(canonical(results))) {
      throw new Error('Case results do not match the stored run artifact.');
    }
    const bound = { ...results, results: results.results.map(item => ({ ...item,
      evidence_refs: [...new Set([...(item.evidence_refs ?? []), reference])],
    })) };
    return pythonJson(resultProgram, { database, evidenceRoot, results: bound,
      artifactReference: reference, artifactSha256: createHash('sha256').update(bytes).digest('hex') }, { python });
  }
  return { status: 'not-applicable', checks: [], reason: 'no-explicit-results' };
}

export async function reviewRunCheck(checkId, { reviewer, note, databasePath, evidenceRoot, python } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(checkId) || typeof note !== 'string' || !note.trim() || note.length > 4000) throw Object.assign(new Error('검토 ID와 사유를 확인하세요.'), { status: 400 });
  return pythonJson(String.raw`
import json,sys
from pathlib import Path
from casper_db.repository import CaseStore
r=json.load(sys.stdin)
store=CaseStore(Path(r['database']),evidence_root=Path(r['evidenceRoot']))
value=store.review_check(r['checkId'],reviewer=r['reviewer'],note=r['note'])
json.dump(value.model_dump(),sys.stdout)
`, { checkId, reviewer, note, database: resolve(databasePath ?? process.env.CASPER_DB_PATH ?? join(root, 'casper-db/data/cases.sqlite3')),
    evidenceRoot: resolve(evidenceRoot ?? process.env.CASPER_EVIDENCE_ROOT ?? '.runtime/artifacts') }, { python });
}
