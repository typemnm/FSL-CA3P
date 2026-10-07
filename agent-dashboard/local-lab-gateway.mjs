import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import protocol from '../agent/src/protocol.js';
import xssCanary from '../agent/src/xss-canary.js';
import attackModule from '../attack-module/index.js';
import { observeStoredXssExecution, parseLocalSite } from './integrations/xss-parser.mjs';
import { createLocalGuardrail, GuardrailDeniedError } from './integrations/guardrail.mjs';
import { matchCasperHistory } from './integrations/casper-db.mjs';
import { createPentestDb } from './integrations/pentest-db.mjs';

const { parseEnvelope, replyTo } = protocol;
const { storedXssCanaryContent } = xssCanary;
const { executeCurl } = attackModule;
const TEMP_PREFIX = 'ca3p-local-lab-';
const START_TIMEOUT_MS = 10_000;
const STOP_TIMEOUT_MS = 3_000;
const CANARY_CONTENT = 'Authorization-test canary requested by the agent.';
const BOLA_PROFILE = 'agent_cross_user_delete_canary';
const XSS_PROFILE = 'stored_xss_canary';
const BOARD_SERVER = fileURLToPath(new URL('../vul-web-1/server.js', import.meta.url));

function isDirectTempChild(root, target) {
  const child = relative(root, target);
  return child.length > TEMP_PREFIX.length
    && child.startsWith(TEMP_PREFIX)
    && !child.startsWith('..')
    && !isAbsolute(child)
    && !child.includes(sep)
    && basename(target).startsWith(TEMP_PREFIX);
}

async function removePrivateBoardData(directory) {
  let actual;
  try {
    actual = await realpath(directory);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  const lexicalRoot = resolve(tmpdir());
  const lexicalTarget = resolve(directory);
  const actualRoot = await realpath(tmpdir());
  if (!isDirectTempChild(lexicalRoot, lexicalTarget)
    || !isDirectTempChild(actualRoot, actual)
    || basename(lexicalTarget).toLowerCase() !== basename(actual).toLowerCase()) {
    throw new Error('Refusing to remove a directory outside the private local lab temp area.');
  }
  await rm(actual, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function closedProcess(child) {
  return new Promise(resolveClosed => child.once('close', (code, signal) => resolveClosed({ code, signal })));
}

function waitAtMost(promise, milliseconds) {
  return new Promise(resolveWait => {
    const timer = setTimeout(() => resolveWait(false), milliseconds);
    promise.then(() => { clearTimeout(timer); resolveWait(true); }, () => { clearTimeout(timer); resolveWait(true); });
  });
}

async function stopProcess(child, closed) {
  if (child.exitCode === null && child.signalCode === null) {
    try { child.kill('SIGTERM'); } catch { /* The process may already have exited. */ }
  }
  if (await waitAtMost(closed, STOP_TIMEOUT_MS)) return;
  try { child.kill('SIGKILL'); } catch { /* The process may already have exited. */ }
  if (!await waitAtMost(closed, STOP_TIMEOUT_MS)) {
    throw new Error('The local lab server did not exit after termination.');
  }
}

function awaitBoardOrigin(child) {
  return new Promise((resolveOrigin, rejectOrigin) => {
    let output = '';
    let settled = false;
    const finish = (error, origin) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout.off('data', onOutput);
      child.off('error', onError);
      child.off('exit', onExit);
      child.stdout.resume();
      if (error) rejectOrigin(error);
      else resolveOrigin(origin);
    };
    const onOutput = chunk => {
      output = `${output}${chunk}`.slice(-2048);
      const match = /게시판 실행 중: http:\/\/127\.0\.0\.1:(\d+)/u.exec(output);
      if (!match) return;
      const port = Number(match[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        finish(new Error('The local lab server reported an invalid port.'));
      } else {
        finish(null, `http://127.0.0.1:${port}`);
      }
    };
    const onError = error => finish(error);
    const onExit = (code, signal) => finish(new Error(`The local lab server exited before startup (${code ?? signal}).`));
    const timer = setTimeout(() => finish(new Error('The local lab server did not start within 10 seconds.')), START_TIMEOUT_MS);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', onOutput);
    child.once('error', onError);
    child.once('exit', onExit);
    child.stderr.resume();
  });
}

function exactKeys(value, keys) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function assertAttackRequest(request, position, canaryId, origin) {
  if (request.sender !== 'agent' || request.receiver !== 'attack-module'
    || request.type !== 'module.request') {
    throw new Error('Only agent curl JSON requests can reach attack-module.');
  }
  const expected = {
    0: { iteration: 0, stage: 'setup.attacker_session', method: 'GET', path: '/api/session', session: 'attacker' },
    1: { iteration: 0, stage: 'setup.fixture_session', method: 'POST', path: '/api/session', session: 'fixture' },
    2: { iteration: 0, stage: 'setup.canary_post', method: 'POST', path: '/api/posts', session: 'fixture' },
    4: { iteration: 1, stage: 'loop.act', method: 'DELETE', path: `/api/posts/${canaryId}`, search: '?authorId=bob', session: 'attacker' },
  }[position];
  if (!expected) throw new Error('Attack-module request is outside the fixed canary sequence.');
  const payload = request.payload;
  const command = payload.curl;
  const url = `${origin}${expected.path}${expected.search ?? ''}`;
  if (!exactKeys(payload, ['operation', 'session', 'curl'])
    || payload.operation !== 'execute_curl'
    || payload.session !== expected.session
    || request.iteration !== expected.iteration
    || !exactKeys(command, expected.method === 'POST' ? ['method', 'url', 'body'] : ['method', 'url'])
    || command.method !== expected.method || command.url !== url) {
    throw new Error('Attack-module command is outside the fixed local canary sequence.');
  }
  if (position === 1 && (!exactKeys(command.body, ['userId']) || command.body.userId !== 'bob')) {
    throw new Error('Fixture session must select Bob only.');
  }
  if (position === 2 && (!exactKeys(command.body, ['title', 'content'])
    || typeof command.body.title !== 'string'
    || !/^agent-canary-run-[0-9]+-[a-f0-9]{8}$/.test(command.body.title)
    || command.body.content !== CANARY_CONTENT)) {
    throw new Error('Canary post body is outside the fixed local lab fixture.');
  }
  if (position === 4 && (!Number.isInteger(canaryId) || canaryId < 1)) {
    throw new Error('DELETE must address only the observed Bob canary.');
  }
  return { ...expected, url, command };
}

function sessionCookie(raw) {
  const pair = raw?.split(';', 1)[0];
  if (!pair || !/^board_user=[A-Za-z0-9._=-]+$/.test(pair)) {
    throw new Error('Local lab did not provide a valid session cookie.');
  }
  return pair;
}

function createBolaGateway(origin, isClosed) {
  const pentestDb = createPentestDb();
  const cookies = { attacker: null, fixture: null };
  let step = 0;
  let canaryId = null;
  let runId = null;
  let guardrail = null;
  let beforeReport = null;
  let historyRead = false;
  let catalogRead = false;

  return {
    async exchange(serializedRequest, { signal } = {}) {
      if (isClosed()) throw new Error('The local lab gateway is closed.');
      const request = parseEnvelope(serializedRequest);
      if (request.sender !== 'agent'
        || request.policyContext.targetMode !== 'isolated_local_lab'
        || request.policyContext.targetOrigin !== origin
        || request.policyContext.maxIterations !== 1
        || (request.policyContext.testProfile !== undefined
          && request.policyContext.testProfile !== BOLA_PROFILE)) {
        throw new Error('Request is outside the isolated local lab policy context.');
      }
      if (runId === null) {
        runId = request.runId;
        guardrail = createLocalGuardrail({ origin, runId, profile: BOLA_PROFILE });
      }
      if (request.runId !== runId) throw new Error('The local lab gateway accepts one run only.');

      if (request.receiver === 'pentest-db') {
        if (request.payload.operation === 'get_attack_info') {
          if (!historyRead || catalogRead) throw new Error('Pentest catalog lookup is outside the fixed sequence.');
          catalogRead = true;
        }
        return pentestDb.exchange(serializedRequest, { signal });
      }

      if (request.receiver === 'casper-db') {
        if (step !== 4 || historyRead || request.type !== 'module.request'
          || !exactKeys(request.payload, ['operation', 'parserReport'])
          || request.payload.operation !== 'assess_xss_history'
          || JSON.stringify(request.payload.parserReport) !== JSON.stringify(beforeReport)) {
          throw new Error('casper-db accepts only the observed parser report in this run.');
        }
        const history = await matchCasperHistory({ report: beforeReport, origin, signal });
        historyRead = true;
        return JSON.stringify(replyTo(request, 'casper-db', 'history.result', {
          operation: 'assess_xss_history',
          readyCaseCount: history.readyCaseCount,
          observations: history.observations,
          assessments: history.assessments,
          evidenceId: `casper-evidence-${randomUUID()}`,
        }));
      }

      if (request.receiver === 'xss-parser') {
        const phase = step === 3 ? 'before' : step === 5 ? 'after' : null;
        if (!phase || request.type !== 'module.request'
          || !exactKeys(request.payload, ['operation', 'origin', 'phase'])
          || request.payload.operation !== 'parse_site'
          || request.payload.origin !== origin || request.payload.phase !== phase
          || request.iteration !== 1
          || (phase === 'after' && (!historyRead || !catalogRead))) {
          throw new Error('xss-parser request is outside the fixed local canary sequence.');
        }
        const parsed = await parseLocalSite(origin, { signal });
        step += 1;
        if (phase === 'before') beforeReport = parsed.report;
        return JSON.stringify(replyTo(request, 'xss-parser', 'parser.result', {
          operation: 'parse_site', phase,
          report: parsed.report,
          observedPosts: parsed.observedPosts,
          errors: parsed.errors,
          truncated: parsed.truncated,
          evidenceId: `parser-evidence-${randomUUID()}`,
        }));
      }

      if (request.receiver !== 'attack-module') {
        throw new Error('Unsupported local lab receiver.');
      }
      if (step === 4 && (!historyRead || !catalogRead)) {
        throw new Error('The prior-case and attack catalog lookups must complete before the canary action.');
      }
      const { stage, method, session, command, url } = assertAttackRequest(request, step, canaryId, origin);
      let decision;
      try {
        decision = step === 0
          ? guardrail.authorizeRead(stage, { operation: 'http_request', session, method, path: '/api/session' })
          : guardrail.authorizeCurl(stage, request.payload);
      } catch (error) {
        if (!(error instanceof GuardrailDeniedError)) throw error;
        return JSON.stringify(replyTo(request, 'attack-module', 'attack.result', {
          operation: 'execute_curl', success: false, error: 'guardrail_denied',
          guardrail: error.guardrailDecision,
          request: { method, url, session },
          response: { status: null, ok: false, bodyJson: {} },
          evidenceId: `guardrail-evidence-${randomUUID()}`,
        }));
      }
      const result = await executeCurl(command, { allowedOrigin: origin, cookie: cookies[session], signal });
      step += 1;
      if (step === 1 && result.success) {
        if (result.bodyJson.user?.id !== 'alice') throw new Error('Attacker session is not Alice.');
        cookies.attacker = sessionCookie(result.setCookie);
      }
      if (step === 2 && result.success) {
        if (result.bodyJson.user?.id !== 'bob') throw new Error('Fixture session is not Bob.');
        cookies.fixture = sessionCookie(result.setCookie);
      }
      if (step === 3 && result.success) {
        const post = result.bodyJson.post;
        if (result.status !== 201 || !Number.isInteger(post?.id) || post.id < 1
          || post.authorId !== 'bob' || post.title !== command.body.title) {
          throw new Error('Local lab did not create the requested Bob canary.');
        }
        canaryId = post.id;
        guardrail.bindCanary({ resourceId: post.id, ownerId: 'bob', createdByRunId: runId });
      }
      return JSON.stringify(replyTo(request, 'attack-module', 'attack.result', {
        operation: 'execute_curl', success: result.success, error: result.error,
        guardrail: decision,
        request: { method, url, session },
        response: {
          status: result.status,
          ok: Number.isInteger(result.status) && result.status >= 200 && result.status < 300,
          bodyJson: result.bodyJson,
        },
        evidenceId: `lab-evidence-${randomUUID()}`,
      }));
    },
  };
}

function assertXssAttackRequest(request, position, origin, runId) {
  if (request.sender !== 'agent' || request.receiver !== 'attack-module'
    || request.type !== 'module.request') {
    throw new Error('Only agent curl JSON requests can reach attack-module.');
  }
  const expected = position === 0
    ? { iteration: 0, stage: 'xss.setup_session', method: 'GET', path: '/api/session' }
    : position === 2
      ? { iteration: 1, stage: 'xss.inject_canary', method: 'POST', path: '/api/posts' }
      : null;
  if (!expected) throw new Error('Attack-module request is outside the fixed XSS canary sequence.');
  const payload = request.payload;
  const command = payload.curl;
  const url = `${origin}${expected.path}`;
  if (!exactKeys(payload, ['operation', 'session', 'curl'])
    || payload.operation !== 'execute_curl' || payload.session !== 'attacker'
    || request.iteration !== expected.iteration
    || !exactKeys(command, expected.method === 'POST' ? ['method', 'url', 'body'] : ['method', 'url'])
    || command.method !== expected.method || command.url !== url) {
    throw new Error('Attack-module command is outside the fixed XSS canary sequence.');
  }
  let marker = null;
  if (expected.method === 'POST') {
    if (!exactKeys(command.body, ['title', 'content'])
      || typeof command.body.title !== 'string'
      || typeof command.body.content !== 'string') {
      throw new Error('XSS canary POST must contain the fixed title and content fields.');
    }
    const titlePrefix = `agent-xss-canary-${runId}-`;
    if (!command.body.title.startsWith(titlePrefix)) {
      throw new Error('XSS canary title is not bound to this run.');
    }
    marker = command.body.title.slice(titlePrefix.length);
    if (!/^[0-9a-f]{32}$/.test(marker)
      || command.body.content !== storedXssCanaryContent(marker)) {
      throw new Error('XSS canary content is outside the fixed local probe.');
    }
  }
  return { ...expected, url, command, marker };
}

function createXssGateway(origin, isClosed) {
  const pentestDb = createPentestDb();
  let runId = null;
  let guardrail = null;
  let attackerCookie = null;
  let step = 0;
  let beforeReport = null;
  let historyRead = false;
  let catalogRead = false;
  let postId = null;
  let marker = null;
  let busy = false;

  async function handle(serializedRequest, { signal } = {}) {
    if (isClosed()) throw new Error('The local lab gateway is closed.');
    const request = parseEnvelope(serializedRequest);
    if (request.sender !== 'agent'
      || request.policyContext.targetMode !== 'isolated_local_lab'
      || request.policyContext.targetOrigin !== origin
      || request.policyContext.maxIterations !== 1
      || request.policyContext.testProfile !== XSS_PROFILE) {
      throw new Error('Request is outside the isolated XSS local lab policy context.');
    }
    if (runId === null) {
      runId = request.runId;
      guardrail = createLocalGuardrail({ origin, runId, profile: XSS_PROFILE });
    }
    if (request.runId !== runId) throw new Error('The local lab gateway accepts one run only.');

    if (request.receiver === 'pentest-db') {
      if (request.payload.operation === 'get_attack_info') {
        if (step !== 2 || !historyRead || catalogRead
          || request.type !== 'storage.request'
          || !exactKeys(request.payload, ['operation', 'vulnType', 'target'])
          || request.payload.vulnType !== 'stored_xss'
          || !exactKeys(request.payload.target, ['endpoint', 'parameter'])
          || request.payload.target.endpoint !== 'POST /api/posts'
          || request.payload.target.parameter !== 'content') {
          throw new Error('Pentest catalog lookup is outside the fixed XSS sequence.');
        }
        catalogRead = true;
      } else if (!['append', 'finalize'].includes(request.payload.operation)) {
        throw new Error('Unsupported XSS storage operation.');
      }
      return pentestDb.exchange(serializedRequest, { signal });
    }

    if (request.receiver === 'casper-db') {
      if (step !== 2 || historyRead || request.iteration !== 1
        || request.type !== 'module.request'
        || !exactKeys(request.payload, ['operation', 'parserReport'])
        || request.payload.operation !== 'assess_xss_history'
        || JSON.stringify(request.payload.parserReport) !== JSON.stringify(beforeReport)) {
        throw new Error('casper-db accepts only the observed XSS parser report in this run.');
      }
      const history = await matchCasperHistory({ report: beforeReport, origin, signal });
      historyRead = true;
      return JSON.stringify(replyTo(request, 'casper-db', 'history.result', {
        operation: 'assess_xss_history',
        readyCaseCount: history.readyCaseCount,
        observations: history.observations,
        assessments: history.assessments,
        evidenceId: `casper-evidence-${randomUUID()}`,
      }));
    }

    if (request.receiver === 'xss-parser') {
      if (step === 1) {
        if (request.type !== 'module.request' || request.iteration !== 1
          || !exactKeys(request.payload, ['operation', 'origin', 'phase'])
          || request.payload.operation !== 'parse_site'
          || request.payload.origin !== origin || request.payload.phase !== 'before') {
          throw new Error('XSS parser observation is outside the fixed sequence.');
        }
        guardrail.authorizeRead('xss.observe', {
          operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/posts',
        });
        const parsed = await parseLocalSite(origin, { signal });
        beforeReport = parsed.report;
        step = 2;
        return JSON.stringify(replyTo(request, 'xss-parser', 'parser.result', {
          operation: 'parse_site', phase: 'before',
          report: parsed.report,
          observedPosts: parsed.observedPosts,
          errors: parsed.errors,
          truncated: parsed.truncated,
          evidenceId: `parser-evidence-${randomUUID()}`,
        }));
      }
      if (step === 3) {
        if (request.type !== 'module.request' || request.iteration !== 1
          || !exactKeys(request.payload, ['operation', 'origin', 'postId', 'marker'])
          || request.payload.operation !== 'verify_stored_xss'
          || request.payload.origin !== origin
          || request.payload.postId !== postId || request.payload.marker !== marker) {
          throw new Error('XSS verification must address only this run\'s created canary.');
        }
        guardrail.authorizeRead('xss.observe', {
          operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/posts',
        });
        const execution = await observeStoredXssExecution(origin, { postId, marker, signal });
        if (execution.postId !== postId || execution.marker !== marker) {
          throw new Error('XSS observer returned evidence for a different canary.');
        }
        step = 4;
        return JSON.stringify(replyTo(request, 'xss-parser', 'parser.result', {
          operation: 'verify_stored_xss', phase: 'after', execution,
          evidenceId: `parser-evidence-${randomUUID()}`,
        }));
      }
      throw new Error('XSS parser request is outside the fixed sequence.');
    }

    if (request.receiver !== 'attack-module') throw new Error('Unsupported XSS local lab receiver.');
    if (step === 2 && (!historyRead || !catalogRead)) {
      throw new Error('The history and catalog lookups must complete before the XSS canary POST.');
    }
    const { stage, method, command, url, marker: requestedMarker } = assertXssAttackRequest(
      request, step, origin, runId,
    );
    let decision;
    try {
      decision = step === 0
        ? guardrail.authorizeRead(stage, {
          operation: 'http_request', session: 'attacker', method, path: '/api/session',
        })
        : guardrail.authorizeCurl(stage, request.payload);
    } catch (error) {
      if (!(error instanceof GuardrailDeniedError)) throw error;
      return JSON.stringify(replyTo(request, 'attack-module', 'attack.result', {
        operation: 'execute_curl', success: false, error: 'guardrail_denied',
        guardrail: error.guardrailDecision,
        request: { method, url, session: 'attacker' },
        response: { status: null, ok: false, bodyJson: {} },
        evidenceId: `guardrail-evidence-${randomUUID()}`,
      }));
    }
    const result = await executeCurl(command, {
      allowedOrigin: origin, cookie: attackerCookie, signal,
    });
    step += 1;
    if (step === 1 && result.success) {
      if (result.bodyJson.user?.id !== 'alice') throw new Error('XSS session is not Alice.');
      attackerCookie = sessionCookie(result.setCookie);
    }
    if (step === 3 && result.success) {
      const post = result.bodyJson.post;
      if (result.status !== 201 || !Number.isInteger(post?.id) || post.id <= 2
        || post.authorId !== 'alice' || post.title !== command.body.title
        || post.content !== command.body.content) {
        throw new Error('Local lab did not create the requested Alice XSS canary.');
      }
      postId = post.id;
      marker = requestedMarker;
      guardrail.bindCanary({ resourceId: postId, ownerId: 'alice', createdByRunId: runId });
    }
    return JSON.stringify(replyTo(request, 'attack-module', 'attack.result', {
      operation: 'execute_curl', success: result.success, error: result.error,
      guardrail: decision,
      request: { method, url, session: 'attacker' },
      response: {
        status: result.status,
        ok: Number.isInteger(result.status) && result.status >= 200 && result.status < 300,
        bodyJson: result.bodyJson,
      },
      evidenceId: `lab-evidence-${randomUUID()}`,
    }));
  }

  return {
    exchange(serializedRequest, options) {
      if (busy) throw new Error('The XSS local lab gateway accepts one request at a time.');
      busy = true;
      return handle(serializedRequest, options).finally(() => { busy = false; });
    },
  };
}

export async function startLocalLab({ profile = XSS_PROFILE } = {}) {
  if (profile !== XSS_PROFILE && profile !== BOLA_PROFILE) {
    throw new Error('Unsupported local lab profile.');
  }
  const directory = await mkdtemp(join(tmpdir(), TEMP_PREFIX));
  // The board process needs no model credentials or provider settings.
  const boardEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^DEEPSEEK_/i.test(name)));
  let child;
  let closed;
  let closeTask;
  try {
    child = spawn(process.execPath, [BOARD_SERVER], {
      env: {
        ...boardEnv,
        HOST: '127.0.0.1',
        PORT: '0',
        BOARD_DATA_FILE: join(directory, 'posts.json'),
        BOARD_COOKIE_SECRET: randomBytes(32).toString('hex'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    // Keep an error listener after startup so a later child-process error cannot
    // become an unhandled EventEmitter error.
    child.on('error', () => {});
    closed = closedProcess(child);
    const origin = await awaitBoardOrigin(child);
    let isClosed = false;
    const gateway = profile === XSS_PROFILE
      ? createXssGateway(origin, () => isClosed)
      : createBolaGateway(origin, () => isClosed);
    const close = () => {
      if (!closeTask) {
        isClosed = true;
        closeTask = (async () => {
          try { await stopProcess(child, closed); }
          finally { await removePrivateBoardData(directory); }
        })();
      }
      return closeTask;
    };
    const closeAfterUnexpectedExit = () => { void close().catch(() => {}); };
    child.once('exit', closeAfterUnexpectedExit);
    child.once('error', closeAfterUnexpectedExit);
    if (child.exitCode !== null || child.signalCode !== null) closeAfterUnexpectedExit();
    return { origin, gateway, close };
  } catch (error) {
    try {
      if (child) await stopProcess(child, closed);
    } finally {
      await removePrivateBoardData(directory);
    }
    throw error;
  }
}
