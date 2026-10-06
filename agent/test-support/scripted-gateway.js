'use strict';

const { parseEnvelope, replyTo } = require('../src/protocol');

function createScriptedGateway({ failOn = null } = {}) {
  const requests = [];
  const events = [];
  const rawResponses = [];
  let finalReport = null;
  let evidenceSequence = 0;
  let canary = null;
  let deleted = false;

  function serializedResponse(request, sender, type, payload) {
    const response = replyTo(request, sender, type, payload);
    if (failOn === 'wrong_correlation' && sender === 'web_explorer') {
      response.correlationId = 'wrong-correlation-id';
    }
    const raw = JSON.stringify(response);
    rawResponses.push(raw);
    return raw;
  }

  function evidenceId() {
    evidenceSequence += 1;
    return `fake-evidence-${evidenceSequence}`;
  }

  function webResponse(request, status, bodyJson) {
    return serializedResponse(request, 'web_explorer', 'web.result', {
      operation: 'http_request',
      trust: 'untrusted_observation',
      request: {
        method: request.payload.method,
        path: request.payload.path,
        session: request.payload.session,
      },
      response: { status, ok: status >= 200 && status < 300, bodyJson },
      evidenceId: evidenceId(),
    });
  }

  async function exchange(rawRequest) {
    if (typeof rawRequest !== 'string') throw new TypeError('Scripted gateway accepts JSON strings only');
    const request = parseEnvelope(rawRequest);
    requests.push({ raw: rawRequest, envelope: request });

    if (request.receiver === 'web_explorer') {
      const { method, path, session, body } = request.payload;
      if (method === 'GET' && path === '/api/session' && session === 'attacker') {
        return webResponse(request, 200, { user: { id: 'alice', name: 'Alice' } });
      }
      if (method === 'POST' && path === '/api/session' && session === 'fixture') {
        return webResponse(request, 200, { user: { id: body.userId, name: 'Bob' } });
      }
      if (method === 'POST' && path === '/api/posts' && session === 'fixture') {
        canary = { id: 4, title: body.title, content: body.content, authorId: 'bob', authorName: 'Bob' };
        return webResponse(request, 201, { post: canary });
      }
      if (method === 'DELETE' && path === '/api/posts/4') {
        if (failOn === 'action_transport') throw new Error('scripted action transport failure');
        deleted = true;
        return webResponse(request, 200, { deletedId: 4 });
      }
      if (method === 'GET' && path === '/api/posts') {
        if (deleted && failOn === 'verify_transport') {
          throw new Error('scripted verification transport failure');
        }
        return webResponse(request, 200, { posts: deleted || !canary ? [] : [canary] });
      }
      throw new Error(`Unexpected scripted Web Explorer request: ${method} ${path}`);
    }

    if (request.receiver === 'vulnerability_db') {
      if (failOn === 'knowledge_module_error') {
        return serializedResponse(request, 'vulnerability_db', 'module.error', {
          error: {
            code: 'EXTERNAL_FAILURE',
            message: 'scripted external knowledge failure',
            source: 'external_module',
            retryable: false,
          },
        });
      }
      const observation = request.payload.observation;
      const resource = observation.posts.find(post => String(post.id) === String(observation.resourceId));
      return serializedResponse(request, 'vulnerability_db', 'knowledge.result', {
        candidates: [{
          knowledgeId: 'lab-cwe-639',
          cwe: 'CWE-639',
          severity: 'high',
          severityBasis: 'scripted_contract_fixture_without_cvss',
          attackerId: observation.attackerId,
          resource: { id: resource.id, ownerId: resource.authorId },
          actionTemplate: { method: 'DELETE', pathTemplate: '/api/posts/{resourceId}' },
          successCriteria: ['different users', '2xx deletion', 'resource absent after verification'],
          provenance: { source: 'external-vulnerability-db-fixture' },
        }],
      });
    }

    if (request.receiver === 'pentest_db') {
      if (request.payload.operation === 'append') {
        events.push(request.payload.event);
        return serializedResponse(request, 'pentest_db', 'storage.appended', {
          ok: true,
          eventType: request.payload.event.stage,
        });
      }
      if (request.payload.operation === 'finalize') {
        if (failOn === 'finalize_transport') throw new Error('scripted finalize transport failure');
        finalReport = request.payload.report;
        return serializedResponse(request, 'pentest_db', 'storage.finalized', {
          ok: true,
          artifactRef: `memory://reports/${request.runId}`,
        });
      }
    }

    throw new Error(`Unexpected external receiver: ${request.receiver}`);
  }

  return {
    exchange,
    requests,
    rawResponses,
    events,
    get finalReport() { return finalReport; },
  };
}

module.exports = { createScriptedGateway };
