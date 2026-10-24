/**
 * Explicit read-only university fixture gateway for CA3P agent/protocol callers.
 * Does not weaken the fixed stored-XSS / BOLA canary gateway.
 */
import protocol from '../../../agent/src/protocol.js';
import { scanUniversityFixture, UNIVERSITY_FIXTURE_ORIGINS } from '../../../xss-parser/university-fixtures.mjs';

const { parseEnvelope, replyTo } = protocol;

export function createUniversityParserGateway({ scanFixture = scanUniversityFixture } = {}) {
  let busy = false;
  return {
    async exchange(serializedRequest, { signal } = {}) {
      const request = parseEnvelope(serializedRequest, 'xss-parser');
      if (request.sender !== 'agent' || request.type !== 'module.request'
        || request.payload.operation !== 'parse_site'
        || !['before', 'after'].includes(request.payload.phase)
        || !['daehan', 'wonchang'].includes(request.payload.site)
        || Object.keys(request.payload).sort().join(',') !== 'operation,origin,phase,site') {
        throw new Error('Unsupported university parser request.');
      }
      const { site, origin } = request.payload;
      if (request.payload.origin !== UNIVERSITY_FIXTURE_ORIGINS[site]
        || request.policyContext?.targetOrigin !== origin
        || request.policyContext?.targetMode !== 'isolated_local_lab') {
        throw new Error('University parser target is not the approved loopback fixture.');
      }
      if (busy) throw new Error('University parser gateway is already processing a request.');
      busy = true;
      try {
        const result = await scanFixture(site, { signal });
        if (result.origin !== origin || result.report?.summary?.scope !== 'visited-client-pages'
          || result.report?.schemaVersion !== '3.4'
          || !Array.isArray(result.report.pages)
          || !result.report.pages.every(page => {
            try { return new URL(page.url).origin === origin; } catch { return false; }
          })) throw new Error('University scan did not return the selected origin.');
        const report = result.report;
        // The legacy protocol validates observedPosts and page origins; here we
        // deliberately avoid asserting API IDs or account ownership from DOM text.
        const observedPosts = report.pages.flatMap(page => (page.posts || []).map(post => ({
          id: post.id ?? null, idSource: post.idSource ?? null, title: post.title ?? null,
          author: post.author ?? null, pageUrl: page.url,
        })));
        return JSON.stringify(replyTo(request, 'xss-parser', 'parser.result', {
          operation: 'parse_site',
          phase: request.payload.phase,
          site,
          report,
          dependencies: result.dependencies,
          observedPosts,
          errors: report.pages.filter(page => page.error)
            .map(page => ({ url: page.url, message: page.error })),
          truncated: !!report.summary.truncated,
          evidenceId: 'university-parser-' + request.runId,
        }));
      } finally {
        busy = false;
      }
    },
  };
}
