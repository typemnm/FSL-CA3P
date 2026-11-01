import { createHash } from 'node:crypto';
import { createAttackTool } from '../../../attack-tool/server.mjs';
import { createAttackToolClient } from '../../../attack-tool/client.mjs';
export { renderTemplate, verifyTemplate, templateExecutionSupport, projectTemplateResponse, listTemplates } from '../../../attack-tool/templates.mjs';
export { bindTemplate, idGroups, rankTemplate } from '../../../attack-tool/bind-template.mjs';

/** One run owns two ports; each vulnerability worker has its own authenticated principal. */
export async function createAttackToolBridge({ authorize, execute, runId, targetOrigin, ports = [0, 0], templateCatalog } = {}) {
  if (typeof authorize !== 'function' || typeof execute !== 'function') throw new TypeError('Attack-tool requires policy and executor ports.');
  const daemon = await createAttackTool({ ports, timeoutMs: 120_000,
    ...(templateCatalog ? { catalog: templateCatalog } : {}) });
  const clients = new Map();
  const agentIds = [];
  let closed = false;
  return {
    endpoints: daemon.endpoints, agentIds, templates: daemon.templates, metrics: daemon.metrics,
    async execute({ probe, hypothesis, signal }) {
      if (closed) throw new Error('Attack-tool bridge is closed.');
      const category = hypothesis?.category;
      if (typeof category !== 'string' || category.length > 128) throw new TypeError('Vulnerability worker requires a category.');
      let client = clients.get(category);
      if (!client) {
        const agentId = 'attack-' + createHash('sha256').update(runId + ':' + category).digest('hex').slice(0, 24);
        const credentials = daemon.registerPrincipal({ agentId, runId, portIndex: clients.size % ports.length,
          authorize: async (input, context) => {
            if (input.hypothesis.category !== category) return { allowed: false, reason: 'worker_category_mismatch' };
            return authorize({ ...input, target: { origin: targetOrigin }, signal: context.signal });
          }, execute: (input, context) => execute({ ...input, signal: context.signal }) });
        client = createAttackToolClient({ ...credentials, endpoint: daemon.endpoints[credentials.portIndex], timeoutMs: 125_000 });
        clients.set(category, client); agentIds.push(agentId);
      }
      return client.call('execute_probe', { probe, hypothesis }, { signal });
    },
    async close() { closed = true; await daemon.close(); clients.clear(); },
  };
}
