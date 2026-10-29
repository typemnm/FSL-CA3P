import { defaultTemplateCatalog, templateRevision, templateExecutionSupport } from '../../packages/adapters/integrations/attack-templates.mjs';

const describe = template => ({ template, executionSupport: templateExecutionSupport(template),
  revision: templateRevision(template) });

export function createAttackTemplateManagement({ catalog = defaultTemplateCatalog } = {}) {
  return {
    list(filters) {
      const templates = catalog.list(filters);
      return { templates, total: templates.length,
        executionSupport: Object.fromEntries(templates.map(template => [template.templateId, templateExecutionSupport(template)])),
        revisions: Object.fromEntries(templates.map(template => [template.templateId, templateRevision(template)])) };
    },
    get(id) {
      const template = catalog.get(id);
      if (!template) throw Object.assign(new Error('템플릿을 찾을 수 없습니다.'), { status: 404 });
      return describe(template);
    },
    import(input) { return catalog.import(input); },
    async update(id, template, expectedRevision) {
      const result = await catalog.update(id, template, { expectedRevision });
      return describe(result.template);
    },
    remove(id, expectedRevision) { return catalog.remove(id, { expectedRevision }); },
  };
}
