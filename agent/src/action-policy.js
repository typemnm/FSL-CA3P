'use strict';

const STAGE_RULES = new Map([
  ['setup.attacker_session', { method: 'GET', path: '/api/session', session: 'attacker' }],
  ['setup.fixture_session', { method: 'POST', path: '/api/session', session: 'fixture' }],
  ['setup.canary_post', { method: 'POST', path: '/api/posts', session: 'fixture' }],
  ['loop.observe', { method: 'GET', path: '/api/posts', session: 'attacker' }],
  ['loop.act', { method: 'DELETE', path: null, session: 'attacker' }],
  ['loop.verify', { method: 'GET', path: '/api/posts', session: 'attacker' }],
]);

class ActionPolicy {
  constructor({ targetOrigin, maxRequests = 8 }) {
    this.allowed = new URL(targetOrigin);
    this.maxRequests = maxRequests;
    this.requestCount = 0;
    this.deleteConstraint = null;

    const loopbackHosts = new Set(['127.0.0.1', '[::1]', '::1']);
    if (this.allowed.protocol !== 'http:' || !loopbackHosts.has(this.allowed.hostname)) {
      throw new Error('MVP target must be an explicit HTTP loopback address');
    }
    if (this.allowed.username || this.allowed.password || this.allowed.pathname !== '/') {
      throw new Error('targetOrigin must contain only scheme, loopback host, and port');
    }
  }

  bindDeleteTarget({ resourceId, ownerId }) {
    const normalizedResourceId = String(resourceId);
    const normalizedOwnerId = String(ownerId);
    if (!/^\d+$/.test(normalizedResourceId) || normalizedOwnerId.length === 0) {
      throw new Error('DELETE target requires a numeric resourceId and non-empty ownerId');
    }
    if (this.deleteConstraint) throw new Error('DELETE target is already bound for this run');
    this.deleteConstraint = {
      path: `/api/posts/${normalizedResourceId}`,
      ownerId: normalizedOwnerId,
    };
  }

  authorize(stage, input) {
    if (!input || input.operation !== 'http_request') {
      throw new Error('Only catalogued HTTP requests may be sent to the Web Explorer');
    }
    const stageRule = STAGE_RULES.get(stage);
    if (!stageRule) throw new Error(`Unknown Web Explorer stage: ${stage}`);
    const method = String(input.method || '').toUpperCase();
    const target = new URL(input.path, this.allowed);
    for (const [key, value] of Object.entries(input.query || {})) {
      target.searchParams.append(key, String(value));
    }

    if (target.origin !== this.allowed.origin) throw new Error('Target origin is outside the exact allowed scope');
    if (target.username || target.password || target.hash) throw new Error('URL credentials and fragments are forbidden');
    if (method !== stageRule.method
      || input.session !== stageRule.session
      || (stageRule.path !== null && target.pathname !== stageRule.path)) {
      throw new Error(`HTTP action does not match the allowed action for ${stage}`);
    }

    const queryKeys = Array.from(target.searchParams.keys());
    if (method === 'DELETE') {
      if (queryKeys.length !== 1 || queryKeys[0] !== 'authorId' || !target.searchParams.get('authorId')) {
        throw new Error('DELETE requests require exactly one non-empty authorId parameter');
      }
      if (!this.deleteConstraint) throw new Error('DELETE target has not been bound by the agent');
      if (input.session !== 'attacker'
        || target.pathname !== this.deleteConstraint.path
        || target.searchParams.get('authorId') !== this.deleteConstraint.ownerId) {
        throw new Error('DELETE request does not match the bound canary target');
      }
    } else if (queryKeys.length !== 0) {
      throw new Error('Query parameters are not allowed for this route');
    }

    if (stage === 'setup.fixture_session') {
      const bodyKeys = Object.keys(input.body || {});
      if (bodyKeys.length !== 1 || bodyKeys[0] !== 'userId' || input.body.userId !== 'bob') {
        throw new Error('Fixture session setup must select only the Bob test user');
      }
    } else if (stage === 'setup.canary_post') {
      const bodyKeys = Object.keys(input.body || {}).sort();
      if (bodyKeys.join(',') !== 'content,title'
        || typeof input.body.title !== 'string'
        || !input.body.title.startsWith('agent-canary-')
        || typeof input.body.content !== 'string') {
        throw new Error('Canary setup must contain only the generated title and content');
      }
    } else if (input.body !== undefined) {
      throw new Error(`HTTP action body is not allowed for ${stage}`);
    }

    if (this.requestCount >= this.maxRequests) throw new Error('HTTP request budget exhausted');
    this.requestCount += 1;
  }

  metrics() {
    return { requestCount: this.requestCount, maxRequests: this.maxRequests };
  }
}

module.exports = { ActionPolicy };
