'use strict';

const { parseEnvelope, replyTo } = require('../protocol');

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/session$/ },
  { method: 'POST', pattern: /^\/api\/session$/ },
  { method: 'GET', pattern: /^\/api\/posts$/ },
  { method: 'POST', pattern: /^\/api\/posts$/ },
  { method: 'DELETE', pattern: /^\/api\/posts\/\d+$/ },
];

class ScopeGuard {
  constructor({ allowedOrigin, maxRequests = 8 }) {
    this.allowed = new URL(allowedOrigin);
    this.maxRequests = maxRequests;
    this.requestCount = 0;

    const loopbackHosts = new Set(['127.0.0.1', '[::1]', '::1']);
    if (this.allowed.protocol !== 'http:' || !loopbackHosts.has(this.allowed.hostname)) {
      throw new Error('MVP target must be an explicit HTTP loopback address');
    }
    if (this.allowed.username || this.allowed.password || this.allowed.pathname !== '/') {
      throw new Error('allowedOrigin must contain only scheme, loopback host, and port');
    }
  }

  async handle(raw) {
    const request = parseEnvelope(raw, 'scope_guard');
    if (request.payload.operation !== 'authorize_http') {
      throw new Error('Unsupported scope guard operation');
    }

    const target = new URL(request.payload.url);
    const method = String(request.payload.method || '').toUpperCase();
    if (target.origin !== this.allowed.origin) throw new Error('Target origin is outside the exact allowed scope');
    if (target.username || target.password || target.hash) throw new Error('URL credentials and fragments are forbidden');
    if (!ROUTES.some(route => route.method === method && route.pattern.test(target.pathname))) {
      throw new Error(`HTTP action is not allowlisted: ${method} ${target.pathname}`);
    }

    const queryKeys = Array.from(target.searchParams.keys());
    if (method === 'DELETE') {
      if (queryKeys.length !== 1 || queryKeys[0] !== 'authorId' || !target.searchParams.get('authorId')) {
        throw new Error('DELETE requests require exactly one non-empty authorId parameter');
      }
    } else if (queryKeys.length !== 0) {
      throw new Error('Query parameters are not allowed for this route');
    }

    if (this.requestCount >= this.maxRequests) throw new Error('HTTP request budget exhausted');
    this.requestCount += 1;

    return JSON.stringify(replyTo(request, 'scope_guard', 'scope.authorized', {
      authorized: true,
      requestNumber: this.requestCount,
      maxRequests: this.maxRequests,
      method,
      url: target.toString(),
    }));
  }

  metrics() {
    return { requestCount: this.requestCount, maxRequests: this.maxRequests };
  }
}

module.exports = { ScopeGuard };
