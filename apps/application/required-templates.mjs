import { listTemplates, templateExecutionSupport, bindTemplate, rankTemplate } from '../../packages/adapters/integrations/attack-tool.mjs';

const SQLI_IDS = ['search-sqli-template', 'comment-sqli-template', 'union-sqli-template', 'sqli-like-tautology'];
const SQLI_RANK = Object.fromEntries(SQLI_IDS.map((id, index) => [id, index]));

function slug(value) {
  return String(value).replace(/[^A-Za-z0-9]+/gu, '-').replace(/^-|-$/gu, '').slice(0, 40);
}

export function librariesFromInventory(inventory = {}) {
  const names = [];
  for (const entry of inventory.referenceSources ?? []) {
    for (const dep of entry.dependencies ?? []) names.push(String(dep.name ?? dep).toLowerCase());
    for (const id of entry.artifactIds ?? []) names.push(String(id).toLowerCase());
  }
  return names;
}

export function bindRequiredTemplates({ templates = listTemplates(), paths = [], forms = [], libraries = [] } = {}) {
  const libs = new Set(libraries.map(name => String(name).toLowerCase()));
  const executable = templates.filter(template => templateExecutionSupport(template).supported)
    .sort((left, right) => rankTemplate(left) - rankTemplate(right)
      || (SQLI_RANK[left.templateId] ?? 50) - (SQLI_RANK[right.templateId] ?? 50)
      || left.templateId.localeCompare(right.templateId));
  const bound = [];
  const sqliPaths = new Set();
  const xssPaths = new Set();
  for (const template of executable) {
    const library = template.dependency?.library?.toLowerCase();
    if (library === 'json5' && libs.size && !libs.has('json5')) continue;
    for (const binding of bindTemplate(template, { paths, forms })) {
      if (SQLI_IDS.includes(template.templateId)) {
        if (sqliPaths.has(binding.path)) continue;
        sqliPaths.add(binding.path);
      }
      if (template.templateId === 'reflected-xss-query-template') {
        if (xssPaths.has(binding.path)) continue;
        xssPaths.add(binding.path);
      }
      bound.push({ template, binding });
    }
  }
  return bound;
}

export function buildRequiredTemplatePlan({
  templates, paths, forms, libraries, evidenceId, usedProbeIds = [], remainingProbes,
} = {}) {
  const used = new Set(usedProbeIds);
  const bound = bindRequiredTemplates({ templates, paths, forms, libraries });
  const destructive = bound.filter(({ template }) => rankTemplate(template) >= 2);
  const rest = bound.filter(({ template }) => rankTemplate(template) < 2);
  const budget = Number.isSafeInteger(remainingProbes) ? remainingProbes : bound.length;
  const reserved = Math.min(1, destructive.length, Math.max(0, budget));
  const selected = [...rest.slice(0, Math.max(0, budget - reserved)), ...destructive.slice(0, reserved)];
  const hypotheses = [];
  const probes = [];
  const requiredIds = [];
  for (const { template, binding } of selected) {
    const suffix = slug(binding.path);
    const hypothesisId = `req-${template.templateId}-${suffix}`.slice(0, 64);
    const probeId = `reqp-${template.templateId}-${suffix}`.slice(0, 64);
    if (used.has(probeId)) continue;
    requiredIds.push(template.templateId);
    hypotheses.push({
      id: hypothesisId,
      category: template.attackType.name,
      asset: binding.path,
      rationale: `Required ${template.attackType.name} template bound to observed ${binding.path}.`,
      evidenceIds: [evidenceId],
    });
    probes.push({
      id: probeId,
      hypothesisId,
      tool: 'execute_attack_template',
      input: {
        templateId: template.templateId,
        payload: binding.payload,
        ...(binding.path ? { path: binding.path } : {}),
        ...(binding.baselinePath ? { baselinePath: binding.baselinePath } : {}),
        ...(binding.baselinePayload ? { baselinePayload: binding.baselinePayload } : {}),
        ...(binding.followUpPath ? { followUpPath: binding.followUpPath } : {}),
      },
    });
  }
  return { hypotheses, probes, requiredIds: [...new Set(requiredIds)] };
}
