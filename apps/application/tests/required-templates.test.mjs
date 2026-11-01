import test from 'node:test';
import assert from 'node:assert/strict';
import { bindTemplate, idGroups } from '../../../attack-tool/bind-template.mjs';
import { listTemplates } from '../../../attack-tool/templates.mjs';
import { buildRequiredTemplatePlan } from '../required-templates.mjs';

test('id groups come from observed numeric detail paths, not fixture names', () => {
  const groups = idGroups([
    '/api/admissions/partner/applications/1',
    '/api/admissions/partner/applications/3',
    '/api/mypage/requests/1',
    '/api/mypage/requests/2',
    '/about',
  ]);
  assert.deepEqual(groups.map(item => item.pattern).sort(), [
    '/api/admissions/partner/applications/:id',
    '/api/mypage/requests/:id',
  ]);
});

test('SQLi and IDOR templates bind only to matching observed surfaces', () => {
  const templates = Object.fromEntries(listTemplates().map(item => [item.templateId, item]));
  const daehan = {
    paths: [
      '/api/search', '/notices', '/login', '/schedule', '/admin/import', '/_diag/config',
      '/admissions/partner', '/api/admissions/partner/applications/1',
      '/api/admissions/partner/applications/3', '/api/mypage/requests/1', '/api/mypage/requests/2',
      '/admin/posts/1/delete', '/',
    ],
    forms: [{ path: '/notices', method: 'GET', fields: ['q'] }],
  };
  const sqli = bindTemplate(templates['search-sqli-template'], daehan).map(item => item.path).sort();
  assert.deepEqual(sqli, ['/api/search', '/notices']);
  const partner = bindTemplate(templates['access-control-idor-template'], daehan);
  assert.equal(partner.length, 1);
  assert.equal(partner[0].payload, '3');
  assert.equal(partner[0].baselinePayload, '1');
  const staff = bindTemplate(templates['wonchang-staff-idor-template'], daehan);
  assert.equal(staff.length, 0);
  const wonchang = {
    paths: [
      '/api/search', '/_diag/config', '/admin/schedule/preview', '/staff/mobile',
      '/api/staff/mobile/cases/1', '/api/staff/mobile/cases/3',
      '/api/mypage/requests/1', '/api/mypage/requests/2', '/admin/posts/1/delete', '/',
    ],
    forms: [],
  };
  assert.equal(bindTemplate(templates['access-control-idor-template'], wonchang).length, 0);
  assert.equal(bindTemplate(templates['wonchang-staff-idor-template'], wonchang).length, 1);
  assert.equal(bindTemplate(templates['query-idor-template'], wonchang)[0].path, '/staff/mobile');
});

test('required plan skips templates whose surfaces were not observed', () => {
  const plan = buildRequiredTemplatePlan({
    templates: listTemplates(),
    evidenceId: 'page-1',
    paths: ['/api/search', '/_diag/config', '/'],
    forms: [],
  });
  assert.ok(plan.requiredIds.includes('search-sqli-template'));
  assert.ok(plan.requiredIds.includes('diag-config-disclosure-template'));
  assert.equal(plan.requiredIds.includes('access-control-idor-template'), false);
  assert.equal(plan.requiredIds.includes('wonchang-staff-idor-template'), false);
  assert.ok(plan.hypotheses.every(item => item.evidenceIds[0] === 'page-1'));
});
