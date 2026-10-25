import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const program = String.raw`
import json, sys
from pathlib import Path
from casper_db.repository import CaseStore, ConflictError
request=json.load(sys.stdin)
store=CaseStore(Path(request['database']), evidence_root=Path(request['evidenceRoot']))
saved=[]
for row in request['checks']:
    try:
        value=store.add_check(row)
    except ConflictError:
        value=store.get_check(row['check_id'])
        for field in ('run_id','case_id','case_revision','result','evidence_refs'):
            if getattr(value,field)!=row[field]:
                raise ValueError('Conflicting history sync')
    saved.append(value.model_dump())
json.dump({'status':'synced','checks':saved},sys.stdout)
`;

function pythonJson(code, input, { python = process.env.CASPER_DB_PYTHON ?? 'python', signal } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(python, ['-c', code], { cwd: root, shell: false, signal,
      env: { ...process.env, PYTHONPATH: join(root, 'casper-db/src') }, stdio: ['pipe', 'pipe', 'pipe'] });
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
  const history = (run.events ?? []).find(event => event.module === 'casper' && Array.isArray(event.response?.payload?.assessments));
  if (!history) return { status: 'not-applicable', checks: [] };
  const evidenceRoot = resolve(process.env.CASPER_EVIDENCE_ROOT ?? join(dirname(resolve(storePath ?? '.runtime/runs.sqlite')), 'artifacts'));
  const reference = relative(evidenceRoot, resolve(artifact.path)).split('\\').join('/');
  if (reference.startsWith('../') || reference.startsWith('/') || reference.includes(':')) throw new Error('Case evidence must stay inside the artifact root.');
  const rows = [];
  for (const assessment of history.response.payload.assessments) {
    const observed = assessment.observation;
    // Only the exact location actually verified by this bounded XSS profile may be linked.
    if (observed?.endpoint !== '/api/posts' || observed.method !== 'POST' || observed.parameter !== 'content'
      || observed.parameter_location !== 'body' || run.report.testProfile !== 'stored_xss_canary') continue;
    for (const match of assessment.matches ?? []) {
      if (match.decision !== 'retest_candidate' || match.changed_fields?.length || !/xss/i.test(match.vulnerability_type ?? '')) continue;
      const result = run.report.finding?.status === 'confirmed' ? 'confirmed'
        : run.report.finding?.status === 'not_confirmed' && run.report.progress?.verificationCompleted ? 'not_reproduced' : 'inconclusive';
      rows.push({ check_id: `CHECK-${hash(`${run.id}:${match.case_id}:${match.case_revision}`).slice(0, 48)}`,
        run_id: run.id, case_id: match.case_id, case_revision: match.case_revision,
        ...observed, observed_at: run.report.completedAt ?? new Date().toISOString(), result,
        observation: `격리된 실습 대상의 ${run.report.testProfile} 검증 결과. 사람의 검토는 별도로 수행합니다.`,
        source: 'tool', evidence_refs: [reference] });
    }
  }
  if (!rows.length) return { status: 'not-applicable', checks: [] };
  return pythonJson(program, { database: resolve(databasePath ?? process.env.CASPER_DB_PATH ?? join(root, 'casper-db/data/cases.sqlite3')),
    evidenceRoot, checks: rows }, { python });
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
