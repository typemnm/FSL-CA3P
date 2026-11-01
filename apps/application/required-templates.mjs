import { listTemplates, templateExecutionSupport, bindTemplate, rankTemplate } from '../../packages/adapters/integrations/attack-tool.mjs';

function slug(value) {
  return String(value).replace(/[^A-Za-z0-9]+/gu, '-').replace(/^-|-$/gu, '').slice(0, 40);
}

export function bindRequiredTemplates({ templates = listTemplates(), paths = [], forms = [] } = {}) {
  const executable = templates.filter(template => templateExecutionSupport(template).supported)
    .sort((left, right) => rankTemplate(left) - rankTemplate(right) || left.templateId.localeCompare(right.templateId));
  const bound = [];
  for (const template of executable) {
    if (template.templateId === 'sqli-like-tautology'
      && bound.some(item => item.template.templateId === 'search-sqli-template')) continue;
    for (const binding of bindTemplate(template, { paths, forms })) {
      bound.push({ template, binding });
    }
  }
  return bound;
}

export function buildRequiredTemplatePlan({ templates, paths, forms, evidenceId, usedProbeIds = [] }) {
  const used = new Set(usedProbeIds);
  const hypotheses = [];
  const probes = [];
  const requiredIds = [];
  for (const { template, binding } of bindRequiredTemplates({ templates, paths, forms })) {
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
