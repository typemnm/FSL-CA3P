import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test from 'node:test';
import protocol from '../../agent/src/protocol.js';
import xssCanary from '../../agent/src/xss-canary.js';
import { startLocalLab } from '../local-lab-gateway.mjs';

const { createEnvelope } = protocol;
const { createStoredXssCanary } = xssCanary;
const runId = 'run-xss-gateway-test';

function request(origin, receiver, iteration, payload, type = 'module.request') {
  return createEnvelope({
    runId, iteration, sender: 'agent', receiver, type, payload,
    policyContext: {
      targetMode: 'isolated_local_lab', targetOrigin: origin,
      testProfile: 'stored_xss_canary', maxIterations: 1,
      rawChainOfThoughtStored: false,
    },
  });
}

async function exchange(lab, receiver, iteration, payload, type) {
  return JSON.parse(await lab.gateway.exchange(JSON.stringify(
    request(lab.origin, receiver, iteration, payload, type),
  )));
}

function curl(origin, method, path, body) {
  return {
    operation: 'execute_curl', session: 'attacker',
    curl: { method, url: `${origin}${path}`, ...(body ? { body } : {}) },
  };
}

async function browserAvailable() {
  try {
    const { chromium } = await import('../../xss-parser/node_modules/playwright/index.mjs');
    return existsSync(process.env.XSS_PARSER_BROWSER_PATH || chromium.executablePath());
  } catch { return false; }
}

test('XSS gateway binds one Agent POST to the created canary and verifies browser execution',
  { timeout: 45_000 }, async t => {
    if (!await browserAvailable()) {
      t.skip('Playwright Chromium is not installed.');
      return;
    }
    const lab = await startLocalLab();
    t.after(() => lab.close());
    const session = await exchange(lab, 'attack-module', 0,
      curl(lab.origin, 'GET', '/api/session'));
    assert.equal(session.payload.success, true);
    assert.equal(session.payload.response.bodyJson.user.id, 'alice');

    await assert.rejects(exchange(lab, 'attack-module', 1,
      curl(lab.origin, 'POST', '/api/posts', { title: 'too-early', content: 'bad' })),
    /outside the fixed XSS canary sequence/);
    const before = await exchange(lab, 'xss-parser', 1,
      { operation: 'parse_site', origin: lab.origin, phase: 'before' });
    assert.equal(before.payload.operation, 'parse_site');
    await exchange(lab, 'casper-db', 1,
      { operation: 'assess_xss_history', parserReport: before.payload.report });
    await exchange(lab, 'pentest-db', 1, {
      operation: 'get_attack_info', vulnType: 'stored_xss',
      target: { endpoint: 'POST /api/posts', parameter: 'content' },
    }, 'storage.request');

    const canary = createStoredXssCanary();
    const body = {
      title: `agent-xss-canary-${runId}-${canary.marker}`,
      content: canary.content,
    };
    await assert.rejects(exchange(lab, 'attack-module', 1, {
      ...curl(lab.origin, 'POST', '/api/posts', body),
      curl: { method: 'POST', url: 'https://example.com/api/posts', body },
    }), /outside the fixed XSS canary sequence/);
    await assert.rejects(exchange(lab, 'attack-module', 1,
      curl(lab.origin, 'POST', '/api/posts', {
        ...body, content: '<img src=x onerror=alert(1)>',
      })), /outside the fixed local probe/);
    const postsBefore = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
    assert.equal(postsBefore.posts.length, 3);

    const posted = await exchange(lab, 'attack-module', 1,
      curl(lab.origin, 'POST', '/api/posts', body));
    assert.equal(posted.payload.success, true);
    assert.equal(posted.payload.guardrail.ruleId,
      'PROFILE.stored_xss_canary.xss.inject_canary');
    const postId = posted.payload.response.bodyJson.post.id;
    assert.equal(posted.payload.response.bodyJson.post.content, canary.content);
    await assert.rejects(exchange(lab, 'attack-module', 1,
      curl(lab.origin, 'POST', '/api/posts', body)), /outside the fixed XSS canary sequence/);
    await assert.rejects(exchange(lab, 'attack-module', 1,
      curl(lab.origin, 'DELETE', `/api/posts/${postId}?authorId=alice`)),
    /outside the fixed XSS canary sequence/);
    await assert.rejects(exchange(lab, 'xss-parser', 1, {
      operation: 'verify_stored_xss', origin: lab.origin,
      postId, marker: 'f'.repeat(32),
    }), /only this run's created canary/);
    await assert.rejects(exchange(lab, 'xss-parser', 1, {
      operation: 'verify_stored_xss', origin: lab.origin,
      postId: postId + 1, marker: canary.marker,
    }), /only this run's created canary/);

    const verification = await exchange(lab, 'xss-parser', 1, {
      operation: 'verify_stored_xss', origin: lab.origin,
      postId, marker: canary.marker,
    });
    assert.equal(verification.payload.execution.postId, postId);
    assert.equal(verification.payload.execution.marker, canary.marker);
    assert.equal(verification.payload.execution.executed, true);
    assert.equal(verification.payload.execution.payloadPresent, true);
    const postsAfter = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
    assert.equal(postsAfter.posts.length, 4);
    assert.equal(postsAfter.posts.filter(post => post.title === body.title).length, 1);
    await assert.rejects(exchange(lab, 'xss-parser', 1, {
      operation: 'verify_stored_xss', origin: lab.origin,
      postId, marker: canary.marker,
    }), /outside the fixed sequence/);
  });

test('XSS gateway rejects untrusted target policy before contacting the board', async t => {
  const lab = await startLocalLab();
  t.after(() => lab.close());
  const wrong = request(lab.origin, 'attack-module', 0,
    curl(lab.origin, 'GET', '/api/session'));
  wrong.policyContext.targetOrigin = 'http://127.0.0.1:1';
  await assert.rejects(lab.gateway.exchange(JSON.stringify(wrong)),
    /outside the isolated XSS local lab policy context/);
  const posts = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
  assert.equal(posts.posts.length, 3);
});

test('the existing cross-user delete profile remains selectable for its fixture setup', async t => {
  const lab = await startLocalLab({ profile: 'agent_cross_user_delete_canary' });
  t.after(() => lab.close());
  const envelope = createEnvelope({
    runId: 'run-bola-gateway-test', iteration: 0,
    sender: 'agent', receiver: 'attack-module', type: 'module.request',
    payload: curl(lab.origin, 'GET', '/api/session'),
    policyContext: {
      targetMode: 'isolated_local_lab', targetOrigin: lab.origin,
      testProfile: 'agent_cross_user_delete_canary', maxIterations: 1,
      rawChainOfThoughtStored: false,
    },
  });
  const session = JSON.parse(await lab.gateway.exchange(JSON.stringify(envelope)));
  assert.equal(session.payload.success, true);
  assert.equal(session.payload.guardrail.ruleId,
    'PROFILE.agent_cross_user_delete_canary.setup.attacker_session');
});
