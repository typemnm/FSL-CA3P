import { listTemplates, templateExecutionSupport } from '../../attack-tool/templates.mjs';

const DESTRUCTIVE = template => template.verify?.mode === 'statusSequence'
  && String(template.request?.packet?.path ?? '').includes('/delete');
const WRITES = template => template.request?.packet?.method === 'POST' || template.verify?.mode === 'statusSequence';

export function requiredTemplatesFor(fixtureId, templates = listTemplates()) {
  const executable = templates.filter(template => templateExecutionSupport(template).supported
    && (!Array.isArray(template.fixtures) || template.fixtures.includes(fixtureId)));
  const skip = new Set();
  if (executable.some(item => item.templateId === 'search-sqli-template')) skip.add('sqli-like-tautology');
  return executable.filter(item => !skip.has(item.templateId)).sort((left, right) => {
    const rank = item => (DESTRUCTIVE(item) ? 2 : WRITES(item) ? 1 : 0);
    return rank(left) - rank(right) || left.templateId.localeCompare(right.templateId);
  });
}

export function buildRequiredTemplatePlan({ fixtureId, templates, evidenceId, usedProbeIds = [] }) {
  const required = requiredTemplatesFor(fixtureId, templates);
  const used = new Set(usedProbeIds);
  const hypotheses = [];
  const probes = [];
  for (const template of required) {
    const hypothesisId = `req-${template.templateId}`.slice(0, 64);
    const probeId = `reqp-${template.templateId}`.slice(0, 64);
    if (used.has(probeId)) continue;
    hypotheses.push({
      id: hypothesisId,
      category: template.attackType.name,
      asset: template.target.endpoint,
      rationale: `Required catalog template ${template.templateId}.`,
      evidenceIds: [evidenceId],
    });
    probes.push({
      id: probeId,
      hypothesisId,
      tool: 'execute_attack_template',
      input: { templateId: template.templateId, payload: template.payloads[0] },
    });
  }
  return { hypotheses, probes, requiredIds: required.map(item => item.templateId) };
}
