import { redact } from '../../packages/contracts/index.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, GENERAL_LOOP_BUDGET_CAPS,
  validateGeneralLoopBudgetPayload } from '../../packages/contracts/general-loop-budget.mjs';

const MODULES = Object.freeze([
  { id: 'attack', name: 'Attack Module', manifestId: 'attack-module', eventIds: ['attack-module', 'attack'] },
  { id: 'web-parser', name: 'Web Parser', manifestId: 'xss-parser', eventIds: ['web-parser', 'xss-parser', 'parser'] },
  { id: 'guardrail', name: 'Guardrail', manifestId: 'guardrail', eventIds: ['guardrail'] },
  { id: 'llm', name: 'LLM', manifestId: 'models', eventIds: ['llm', 'model', 'deepseek'] },
  { id: 'db', name: 'DB', manifestId: 'casper-db', eventIds: ['casper-db', 'db', 'knowledge'] },
]);

const fault = (status, message) => Object.assign(new Error(message), { status });
function definition(id) {
  const found = MODULES.find(item => item.id === id);
  if (!found) throw fault(404, 'Module not found.');
  return found;
}
function manifestModule(platform, item) {
  return platform?.modules?.find(module => module.id === item.manifestId) ?? null;
}
function pageItems(page) {
  if (Array.isArray(page)) return page;
  return page?.runs ?? page?.items ?? [];
}
function safeLog(event, run) {
  const guardrail = event.module === 'guardrail' && event.response?.payload;
  const ruleId = typeof guardrail?.ruleId === 'string' && /^[a-zA-Z0-9._:-]{1,80}$/.test(guardrail.ruleId)
    ? guardrail.ruleId : null;
  const reason = typeof guardrail?.reason === 'string'
    ? redact(guardrail.reason).replace(/[\u0000-\u001f]/gu, ' ').slice(0, 180) : null;
  return {
    id: typeof event.id === 'string' ? event.id : `${run.id}-${event.sequence ?? 0}`,
    runId: run.id,
    sequence: event.sequence ?? null,
    module: event.module ?? null,
    stage: event.stage ?? null,
    status: event.status ?? null,
    title: event.title ?? null,
    createdAt: event.createdAt ?? event.time ?? event.timestamp ?? event.at ?? run.startedAt ?? null,
    ...(ruleId ? { ruleId } : {}),
    ...(reason ? { reason, detail: `${ruleId ? `${ruleId}: ` : ''}${reason}` } : {}),
    ...(typeof guardrail?.decision === 'string' ? { decision: guardrail.decision } : {}),
    ...(typeof event.correlationId === 'string' && /^[a-zA-Z0-9._:-]{1,128}$/.test(event.correlationId)
      ? { correlationId: event.correlationId } : {}),
  };
}
function belongsTo(event, item) {
  const fields = [event.module, event.source].filter(value => typeof value === 'string').map(value => value.toLowerCase());
  return fields.some(value => item.eventIds.some(id => value === id || value.startsWith(`${id}/`) || value.startsWith(`${id}.`)));
}

export function createModuleManagement({ runtime, platformProvider, dbManagement = null }) {
  if (!runtime || typeof platformProvider !== 'function') throw new Error('Module management requires runtime and platform provider.');
  return {
    async loopBudget() {
      if (typeof runtime.getGeneralLoopBudget !== 'function') throw fault(503, 'General loop budget is unavailable.');
      return { limits: await runtime.getGeneralLoopBudget(),
        defaults: GENERAL_LOOP_BUDGET_DEFAULTS, caps: GENERAL_LOOP_BUDGET_CAPS };
    },
    async updateLoopBudget(body) {
      const limits = validateGeneralLoopBudgetPayload(body);
      if (typeof runtime.setGeneralLoopBudget !== 'function') throw fault(503, 'General loop budget is unavailable.');
      return { limits: await runtime.setGeneralLoopBudget(limits),
        defaults: GENERAL_LOOP_BUDGET_DEFAULTS, caps: GENERAL_LOOP_BUDGET_CAPS };
    },
    async list() {
      const platform = await platformProvider();
      return { modules: MODULES.map(item => {
        const current = manifestModule(platform, item);
        return { id: item.id, name: item.name, integrationId: item.manifestId,
          status: current?.status ?? 'unavailable', version: current?.version ?? null,
          contentDigest: current?.contentDigest ?? null, editable: false,
          statusMeaning: 'integration-manifest',
        };
      }) };
    },
    async config(id) {
      const item = definition(id);
      const platform = await platformProvider();
      const current = manifestModule(platform, item);
      if (!current) throw fault(503, 'Module configuration is unavailable.');
      const config = {
        integrationId: item.manifestId,
        status: current.status,
        version: current.version ?? null,
        path: current.path ?? null,
        layer: current.layer ?? null,
        dependencies: current.dependencies ?? [],
        contentDigest: current.contentDigest ?? null,
        sourceRevision: platform?.source?.commitSha ?? null,
      };
      if (id === 'web-parser') config.runtimeModuleId = 'web-parser';
      if (id === 'llm') config.models = await runtime.listModels?.() ?? [];
      return { config, revision: current.contentDigest ?? platform?.source?.commitSha ?? null,
        editable: false, source: 'deployment',
        message: '현재 적용된 모듈 설정입니다. 실행 중 설정 변경은 지원하지 않습니다.' };
    },
    async logs(id, { limit = 100, offset = 0, runId } = {}) {
      const item = definition(id);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100
        || !Number.isSafeInteger(offset) || offset < 0 || offset > 5000) {
        throw fault(400, 'Invalid log pagination.');
      }
      if (id === 'db' && !runId && typeof dbManagement?.listAudit === 'function') {
        const audit = await dbManagement.listAudit({ limit, offset });
        return { logs: (audit.logs ?? []).map((entry, index) => ({
          id: `db-audit-${offset + index + 1}`, runId: null, module: 'db',
          stage: entry.action, status: 'completed', title: entry.action,
          actor: entry.actor, caseId: entry.caseId ?? null, draftSha: entry.draftSha ?? null,
          createdAt: entry.recordedAt,
        })), total: audit.total ?? 0, truncated: false };
      }
      let runs;
      if (runId) {
        if (!/^[a-zA-Z0-9_-]{1,128}$/.test(runId)) throw fault(400, 'Invalid run ID.');
        const run = await runtime.getRun?.(runId);
        runs = run ? [run] : [];
      } else {
        runs = [];
        for (let page = 0; page < 5; page += 1) {
          const current = pageItems(await runtime.listRuns?.({ limit: 200, offset: page * 200 }));
          runs.push(...current);
          if (current.length < 200) break;
        }
      }
      const logs = [];
      for (const run of runs) {
        for (const event of run.events ?? []) {
          if (belongsTo(event, item)) logs.push(safeLog(event, run));
        }
        if (id === 'llm') for (const [index, call] of (run.modelCalls ?? []).entries()) {
          logs.push({ id: `${run.id}-model-${index + 1}`, runId: run.id, sequence: index + 1,
            module: 'llm', stage: 'model.call', status: call.status ?? null,
            title: call.requestedModel ?? call.reportedModel ?? 'Model call',
            createdAt: call.createdAt ?? run.startedAt ?? null,
            latencyMs: Number.isFinite(call.latencyMs) ? call.latencyMs : null,
            usage: call.usage && typeof call.usage === 'object' ? {
              prompt_tokens: call.usage.prompt_tokens ?? null,
              completion_tokens: call.usage.completion_tokens ?? null,
              total_tokens: call.usage.total_tokens ?? null,
            } : null,
            errorCode: call.error?.code ?? null });
        }
      }
      logs.sort((a, b) => String(b.createdAt ?? '').localeCompare(String(a.createdAt ?? ''))
        || String(b.runId).localeCompare(String(a.runId)) || (b.sequence ?? 0) - (a.sequence ?? 0));
      return { logs: logs.slice(offset, offset + limit), total: logs.length,
        truncated: !runId && runs.length >= 1000 };
    },
  };
}
