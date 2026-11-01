import test from 'node:test';
import assert from 'node:assert/strict';
import { listTemplates } from '../../../attack-tool/templates.mjs';
import { buildRequiredTemplatePlan, requiredTemplatesFor } from '../required-templates.mjs';

test('required daehan templates are executable, skip tautology, and put featured delete last', () => {
  const required = requiredTemplatesFor('vul-web2-daehan');
  const ids = required.map(item => item.templateId);
  assert.ok(ids.includes('search-sqli-template'));
  assert.ok(ids.includes('json5-inherited-filter-template'));
  assert.ok(ids.includes('access-control-idor-template'));
  assert.ok(ids.includes('partner-html-idor-template'));
  assert.ok(ids.includes('student-request-idor-template'));
  assert.ok(ids.includes('diag-config-disclosure-template'));
  assert.ok(ids.includes('notices-sqli-template'));
  assert.ok(ids.includes('admin-import-unsigned-template'));
  assert.ok(ids.includes('json5-parse-error-template'));
  assert.ok(ids.includes('unauth-featured-post-delete-template'));
  assert.equal(ids.includes('sqli-like-tautology'), false);
  assert.equal(ids.includes('wonchang-staff-idor-template'), false);
  assert.equal(ids.at(-1), 'unauth-featured-post-delete-template');
});

test('required wonchang templates include staff IDOR and SnakeYAML and omit JSON5', () => {
  const ids = requiredTemplatesFor('vul-web2-wonchang').map(item => item.templateId);
  assert.ok(ids.includes('wonchang-staff-idor-template'));
  assert.ok(ids.includes('staff-html-idor-template'));
  assert.ok(ids.includes('snakeyaml-type-tag-template'));
  assert.equal(ids.includes('json5-inherited-filter-template'), false);
  assert.equal(ids.includes('access-control-idor-template'), false);
  assert.equal(ids.at(-1), 'unauth-featured-post-delete-template');
});

test('required plan uses catalog payloads and existing evidence', () => {
  const plan = buildRequiredTemplatePlan({
    fixtureId: 'vul-web2-daehan', templates: listTemplates(), evidenceId: 'page-1',
  });
  assert.ok(plan.probes.length >= 8);
  assert.equal(plan.hypotheses.length, plan.probes.length);
  assert.ok(plan.probes.every(item => item.tool === 'execute_attack_template' && item.input.payload));
  assert.ok(plan.hypotheses.every(item => item.evidenceIds[0] === 'page-1'));
});
