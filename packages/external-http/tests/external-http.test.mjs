import test from 'node:test';
import assert from 'node:assert/strict';
import { externalScopeRejectionReason, requestExternalHttp } from '../index.mjs';

test('shared scope permits only the selected origin and path subtree', () => {
  const scope = { origin: 'https://example.com', pathPrefix: '/audit' };
  assert.equal(externalScopeRejectionReason('https://example.com/audit', scope), null);
  assert.equal(externalScopeRejectionReason('https://example.com/audit/page', scope), null);
  assert.equal(externalScopeRejectionReason('https://example.com/auditor', scope), 'out_of_scope_path');
  assert.equal(externalScopeRejectionReason('https://other.example.com/audit', scope), 'out_of_scope_origin');
  assert.equal(externalScopeRejectionReason('https://example.com/audit?token=secret', scope), 'credential_query');
});

test('shared HTTP client rejects a private address even when the origin matches', async () => {
  const scope = { origin: 'http://127.0.0.1:4101', pathPrefix: '/' };
  await assert.rejects(requestExternalHttp('http://127.0.0.1:4101/', { scope, responseType: 'buffer' }),
    { code: 'EXTERNAL_ADDRESS_BLOCKED' });
});
