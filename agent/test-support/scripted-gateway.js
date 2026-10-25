'use strict';

const { parseEnvelope, replyTo } = require('../src/protocol');

function createScriptedGateway({ failOn = null, beforePosts, afterPosts, historyAssessments = [] } = {}) {
  const requests = [];
  const rawResponses = [];
  const events = [];
  let finalReport = null;
  let sequence = 0;
  let canary = null;
  let deleted = false;

  function evidenceId() { sequence += 1; return `fixture-evidence-${sequence}`; }
  function respond(request, sender, type, payload) {
    const response = replyTo(request, sender, type, payload);
    if (failOn === 'wrong_correlation' && sender === 'xss-parser') response.correlationId = 'wrong';
    const raw = JSON.stringify(response);
    rawResponses.push(raw);
    return raw;
  }
  function attackResponse(request, status, bodyJson, error = null, decision = 'ALLOW') {
    const method = request.payload.curl.method;
    const ok = status !== null && status >= 200 && status < 300;
    return respond(request, 'attack-module', 'attack.result', {
      operation: 'execute_curl',
      success: ok && error === null && decision === 'ALLOW',
      request: { method, url: request.payload.curl.url, session: request.payload.session },
      response: { status, ok, bodyJson },
      error,
      guardrail: {
        decision, ruleId: decision === 'ALLOW' ? 'FIXTURE-ALLOW' : 'FIXTURE-DENY',
        stage: method === 'DELETE' ? 'loop.act' : method === 'GET'
          ? 'setup.attacker_session' : canary ? 'setup.canary_post' : 'setup.fixture_session',
        reason: 'fixture guardrail decision',
      },
      evidenceId: evidenceId(),
    });
  }
  function parserResponse(request) {
    const { origin, phase } = request.payload;
    const override = phase === 'before' ? beforePosts : afterPosts;
    const posts = typeof override === 'function'
      ? override(canary)
      : override ?? (phase === 'before'
        ? (canary ? [canary] : [])
        : (deleted ? [] : canary ? [canary] : []));
    const observedPosts = posts.map(post => ({
      id: String(post.id), idSource: 'visible-label', title: post.title,
      author: 'Bob', pageUrl: `${origin}/`,
    }));
    const truncated = failOn === 'parser_incomplete' && phase === 'after';
    const report = {
      schemaVersion: '3.4', startUrl: `${origin}/`,
      pages: [{ url: `${origin}/`, posts: observedPosts }],
      summary: { scope: 'visited-client-pages', truncated, errors: 0 },
    };
    return respond(request, 'xss-parser', 'parser.result', {
      operation: 'parse_site', phase, report, observedPosts, errors: [], truncated,
      evidenceId: evidenceId(),
    });
  }

  async function exchange(rawRequest) {
    const request = parseEnvelope(rawRequest);
    requests.push({ raw: rawRequest, envelope: request });
    if (request.receiver === 'attack-module') {
      const command = request.payload.curl;
      const target = new URL(command.url);
      if (command.method === 'GET' && target.pathname === '/api/session') {
        return attackResponse(request, 200, { user: { id: 'alice', name: 'Alice' } });
      }
      if (command.method === 'POST' && target.pathname === '/api/session') {
        return attackResponse(request, 200, { user: { id: command.body.userId, name: 'Bob' } });
      }
      if (command.method === 'POST' && target.pathname === '/api/posts') {
        canary = {
          id: 4, title: command.body.title, content: command.body.content,
          authorId: 'bob', authorName: 'Bob',
        };
        return attackResponse(request, 201, { post: canary });
      }
      if (command.method === 'DELETE' && target.pathname === '/api/posts/4') {
        if (failOn === 'action_transport') throw new Error('scripted action transport failure');
        if (failOn === 'guardrail_denied') return attackResponse(request, null, {}, 'guardrail_denied', 'DENY');
        if (failOn === 'attack_result_failure') return attackResponse(request, null, {}, 'curl_failed');
        deleted = true;
        return attackResponse(request, 200, { deletedId: 4 });
      }
      throw new Error(`Unexpected attack command: ${command.method} ${target.pathname}`);
    }
    if (request.receiver === 'xss-parser') {
      if (failOn === 'verify_transport' && request.payload.phase === 'after') {
        throw new Error('scripted verification transport failure');
      }
      return parserResponse(request);
    }
    if (request.receiver === 'casper-db') {
      if (failOn === 'history_module_error') {
        return respond(request, 'casper-db', 'module.error', {
          error: { code: 'EXTERNAL_FAILURE', message: 'scripted history failure' },
        });
      }
      return respond(request, 'casper-db', 'history.result', {
        operation: 'assess_xss_history', assessments: historyAssessments,
        readyCaseCount: historyAssessments.length, observations: historyAssessments.map(() => ({})),
        evidenceId: evidenceId(),
      });
    }
    if (request.receiver === 'pentest-db') {
      const { operation } = request.payload;
      if (operation === 'get_attack_info') {
        return respond(request, 'pentest-db', 'storage.attack_info', {
          operation, attackInfo: { vulnType: 'stored_xss', cwe: 'CWE-79' },
          evidenceId: evidenceId(),
        });
      }
      if (operation === 'append') {
        events.push(request.payload.event);
        return respond(request, 'pentest-db', 'storage.appended', {
          ok: true, eventType: request.payload.event.stage,
        });
      }
      if (operation === 'finalize') {
        if (failOn === 'finalize_transport') throw new Error('scripted finalize transport failure');
        finalReport = request.payload.report;
        return respond(request, 'pentest-db', 'storage.finalized', {
          ok: true, artifactRef: `memory://reports/${request.runId}`,
        });
      }
    }
    throw new Error(`Unexpected module receiver: ${request.receiver}`);
  }

  return {
    exchange, requests, events, rawResponses,
    get finalReport() { return finalReport; },
  };
}

module.exports = { createScriptedGateway };
