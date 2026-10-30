import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import { prepareLabSessionCleanup } from '../../packages/adapters/lab-session-registry.mjs';

const UNIVERSITY_FIXTURES = new Set(['vul-web2-daehan', 'vul-web2-wonchang']);
// Old board runs remain readable and their private process residue may still need cleanup.
const HISTORICAL_ISOLATED_FIXTURES = new Set(['vul-web-1', 'scripted-contract-fixture']);
const REQUIRED_SCOPES = ['database', 'sessions', 'process', 'files'];
const RESET_PATH = '/_ca3p/experiment-reset';
const fault = (status, message) => Object.assign(new Error(message), { status, code: 'EXPERIMENT_TARGET_RESET_BLOCKED' });

function isReadOnlyExternalRun(run) {
  if (run.mode !== 'external-general' || run.fixtureId !== null
    || run.targetKind !== 'external' || run.simulated !== false) return false;
  if (run.testProfile === 'external-read-only') return run.modelId === 'rule-baseline';
  return run.testProfile === 'external-general'
    && ['deepseek-flash', 'deepseek-v4-pro'].includes(run.modelId)
    && run.manifest?.execution?.inspectionMode === 'external-general'
    && Array.isArray(run.manifest?.policy?.methods)
    && run.manifest.policy.methods.length > 0
    && run.manifest.policy.methods.every(method => ['GET', 'HEAD'].includes(method));
}

/** Keep only the target facts needed by a later full reset after run history is removed. */
export function targetResetObligationsForRuns(runs = []) {
  const obligations = [];
  for (const run of runs) {
    if (run.mode === 'core-fixture' || run.simulated === true || isReadOnlyExternalRun(run)) continue;
    const fixtureId = run.fixtureId ?? run.manifest?.target?.fixtureId;
    if (UNIVERSITY_FIXTURES.has(fixtureId)) {
      obligations.push({ fixtureId,
        manifest: { target: { fixtureId, origin: run.manifest?.target?.origin } },
        coreTargetOrigin: run.coreTargetOrigin, target: run.target,
        report: { target: { origin: run.report?.target?.origin } } });
    } else if (!HISTORICAL_ISOLATED_FIXTURES.has(fixtureId) && run.targetContacted === true) {
      obligations.push({ fixtureId: fixtureId ?? null, targetContacted: true });
    }
  }
  return obligations;
}

function managementOrigin(value) {
  if (typeof value !== 'string' || value !== value.trim() || value.length > 256) throw new Error();
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
  if (url.protocol === 'http:') return validateUniversityOrigin(value);
  if (url.protocol !== 'https:') throw new Error();
  return url.origin;
}

async function boundedJson(response) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > 8192)) throw new Error();
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) throw new Error();
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8192) throw new Error();
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/** Preflight only. Never derive a destructive management destination from a run URL. */
export async function prepareTargetReset({ runs = [], env = process.env, fetchImpl = fetch, cleanupRegistryPath } = {}) {
  if (!Array.isArray(runs) || typeof fetchImpl !== 'function') throw fault(400, 'Invalid experiment target reset request.');
  const touched = new Map();
  for (const run of runs) {
    if (run.mode === 'core-fixture' || run.simulated === true || isReadOnlyExternalRun(run)) continue;
    const fixtureId = run.fixtureId ?? run.manifest?.target?.fixtureId;
    if (UNIVERSITY_FIXTURES.has(fixtureId)) {
      const origins = [run.manifest?.target?.origin, run.coreTargetOrigin, run.target, run.report?.target?.origin]
        .filter(value => value !== undefined && value !== null);
      try {
        if (!origins.length) throw new Error();
        const recorded = touched.get(fixtureId) ?? new Set();
        for (const value of origins) recorded.add(validateUniversityOrigin(value));
        touched.set(fixtureId, recorded);
      } catch { throw fault(409, `${fixtureId} 실행의 실제 대상 주소를 확인할 수 없어 초기화를 중단했습니다.`); }
    }
    else if (!HISTORICAL_ISOLATED_FIXTURES.has(fixtureId) && run.targetContacted === true) {
      throw fault(409, '접촉한 외부 대상의 초기화 방법이 등록되지 않았습니다. 운영자가 관리하는 실습 대상만 초기화할 수 있습니다.');
    }
  }
  let settings = {};
  if (touched.size) {
    try {
      settings = JSON.parse(env.CA3P_EXPERIMENT_RESET_TARGETS ?? '{}');
      if (!settings || typeof settings !== 'object' || Array.isArray(settings)
        || Object.keys(settings).some(key => !UNIVERSITY_FIXTURES.has(key))) throw new Error();
    } catch { throw fault(409, '대학 실습 초기화 관리 설정을 확인하세요.'); }
  }
  const plans = [...touched.keys()].sort().map(fixtureId => {
    try {
      const value = settings[fixtureId];
      if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).some(key => !['origin', 'targetOrigin', 'token'].includes(key))
        || typeof value.token !== 'string' || !/^[A-Za-z0-9._~+/-]{32,512}$/.test(value.token)) throw new Error();
      const targetOrigin = validateUniversityOrigin(value.targetOrigin);
      if (touched.get(fixtureId).size !== 1 || !touched.get(fixtureId).has(targetOrigin)) {
        throw fault(409, `${fixtureId} 실행 대상과 관리 훅의 초기화 대상이 다르거나 여러 대상의 기록이 섞여 있습니다.`);
      }
      return { fixtureId, targetOrigin, url: `${managementOrigin(value.origin)}${RESET_PATH}`, token: value.token };
    } catch (error) {
      if (error.code === 'EXPERIMENT_TARGET_RESET_BLOCKED') throw error;
      throw fault(409, `${fixtureId}의 전체 초기화 관리 훅이 설정되지 않았습니다. 운영자에게 문의하세요.`);
    }
  });
  const labs = await prepareLabSessionCleanup(cleanupRegistryPath);
  let execution;
  return { execute() {
    execution ??= (async () => {
      const targets = [];
      for (const plan of plans) {
        try {
          const response = await fetchImpl(plan.url, {
            method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
            signal: AbortSignal.timeout(10_000),
            headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${plan.token}` },
            body: JSON.stringify({ confirmation: 'reset-experiment-target', fixtureId: plan.fixtureId, targetOrigin: plan.targetOrigin }),
          });
          if (response.status !== 200 || response.redirected || response.url && response.url !== plan.url) throw new Error();
          const result = await boundedJson(response);
          if (result.status !== 'clean' || result.fixtureId !== plan.fixtureId || result.targetOrigin !== plan.targetOrigin || !Array.isArray(result.scopes)
            || REQUIRED_SCOPES.some(scope => !result.scopes.includes(scope))) throw new Error();
          targets.push({ fixtureId: plan.fixtureId, status: 'clean', scopes: [...REQUIRED_SCOPES] });
        } catch { throw fault(503, `${plan.fixtureId} 전체 초기화를 확인하지 못했습니다. 다음 실험 전에 관리 훅과 대상 상태를 확인하세요.`); }
      }
      const localLabs = await labs.execute();
      return { status: 'clean', targets, localLabs };
    })();
    return execution;
  } };
}
