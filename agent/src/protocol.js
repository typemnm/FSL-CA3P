'use strict';

const { randomUUID } = require('node:crypto');

const SCHEMA_VERSION = '1.0';
const MAX_MESSAGE_BYTES = 1_000_000;
const DEFAULT_GATEWAY_TIMEOUT_MS = 10_000;
const MODULE_NAMES = new Set([
  'agent',
  'xss-parser',
  'attack-module',
  'casper-db',
  'pentest-db',
]);
const MESSAGE_TYPES = new Set([
  'module.request',
  'module.error',
  'parser.result',
  'attack.result',
  'history.result',
  'storage.request',
  'storage.attack_info',
  'storage.appended',
  'storage.finalized',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function urlHasOrigin(raw, origin) {
  try { return new URL(raw).origin === origin; }
  catch { return false; }
}

function createEnvelope({
  runId,
  iteration,
  sender,
  receiver,
  type,
  payload = {},
  evidence = [],
  policyContext = {},
  correlationId,
}) {
  const messageId = randomUUID();
  const message = {
    schemaVersion: SCHEMA_VERSION,
    runId,
    iteration,
    messageId,
    correlationId: correlationId || messageId,
    timestamp: new Date().toISOString(),
    sender,
    receiver,
    type,
    payload,
    evidence,
    policyContext,
  };
  validateEnvelope(message);
  return message;
}

function validateEnvelope(message, expectedReceiver) {
  if (!isObject(message)) throw new TypeError('JSON envelope must be an object');
  if (message.schemaVersion !== SCHEMA_VERSION) throw new Error('Unsupported schemaVersion');

  for (const field of ['runId', 'messageId', 'correlationId', 'timestamp', 'sender', 'receiver', 'type']) {
    if (typeof message[field] !== 'string' || message[field].length === 0) {
      throw new TypeError(`Envelope field ${field} must be a non-empty string`);
    }
  }
  if (!MODULE_NAMES.has(message.sender) || !MODULE_NAMES.has(message.receiver)) {
    throw new Error('Envelope sender and receiver must be known module names');
  }
  if (!MESSAGE_TYPES.has(message.type)) throw new Error(`Unsupported envelope type ${message.type}`);
  if (Number.isNaN(Date.parse(message.timestamp))) throw new Error('Envelope timestamp must be ISO-8601 compatible');
  if (!Number.isInteger(message.iteration) || message.iteration < 0) {
    throw new TypeError('Envelope iteration must be a non-negative integer');
  }
  if (!isObject(message.payload)) throw new TypeError('Envelope payload must be an object');
  if (!Array.isArray(message.evidence)) throw new TypeError('Envelope evidence must be an array');
  if (!isObject(message.policyContext)) throw new TypeError('Envelope policyContext must be an object');
  if (expectedReceiver && message.receiver !== expectedReceiver) {
    throw new Error(`Envelope was addressed to ${message.receiver}, not ${expectedReceiver}`);
  }

  JSON.stringify(message);
  return message;
}

function parseEnvelope(raw, expectedReceiver) {
  if (typeof raw !== 'string') throw new TypeError('Module boundary accepts serialized JSON only');
  if (Buffer.byteLength(raw, 'utf8') > MAX_MESSAGE_BYTES) throw new Error('Module message exceeds 1 MB');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid JSON module message: ${error.message}`);
  }
  return validateEnvelope(parsed, expectedReceiver);
}

function replyTo(request, sender, type, payload = {}, evidence = []) {
  return createEnvelope({
    runId: request.runId,
    iteration: request.iteration,
    sender,
    receiver: request.sender,
    type,
    payload,
    evidence,
    policyContext: request.policyContext,
    correlationId: request.messageId,
  });
}

function gatewayError(request, code, message) {
  return createEnvelope({
    runId: request.runId,
    iteration: request.iteration,
    sender: 'agent',
    receiver: 'agent',
    type: 'module.error',
    payload: {
      error: {
        code,
        message,
        source: 'agent_gateway',
        retryable: false,
        causedBy: request.messageId,
      },
    },
    evidence: [],
    policyContext: request.policyContext,
    correlationId: request.messageId,
  });
}

function validateResponseContract(request, response) {
  if (response.type === 'module.error') {
    const details = response.payload.error;
    if (!isObject(details)
      || typeof details.code !== 'string'
      || typeof details.message !== 'string') {
      throw new Error('module.error payload must contain string code and message fields');
    }
    return response;
  }

  let expectedType;
  if (request.receiver === 'xss-parser' && request.type === 'module.request') {
    expectedType = 'parser.result';
  } else if (request.receiver === 'attack-module' && request.type === 'module.request') {
    expectedType = 'attack.result';
  } else if (request.receiver === 'casper-db' && request.type === 'module.request') {
    expectedType = 'history.result';
  } else if (request.receiver === 'pentest-db' && request.type === 'storage.request') {
    if (request.payload.operation === 'get_attack_info') expectedType = 'storage.attack_info';
    if (request.payload.operation === 'append') expectedType = 'storage.appended';
    if (request.payload.operation === 'finalize') expectedType = 'storage.finalized';
  }
  if (!expectedType) throw new Error('Unsupported external request contract');
  if (response.type !== expectedType) {
    throw new Error(`Expected ${expectedType} response, received ${response.type}`);
  }

  if (expectedType === 'parser.result') {
    const payload = response.payload;
    if (request.payload.operation === 'verify_stored_xss') {
      const execution = payload.execution;
      if (payload.operation !== 'verify_stored_xss'
        || payload.phase !== 'after'
        || !isObject(execution)
        || execution.marker !== request.payload.marker
        || execution.postId !== request.payload.postId
        || !urlHasOrigin(execution.pageUrl, request.payload.origin)
        || typeof execution.executed !== 'boolean'
        || typeof execution.postVisible !== 'boolean'
        || typeof execution.payloadPresent !== 'boolean'
        || typeof execution.bindingCalled !== 'boolean'
        || !Array.isArray(execution.errors)
        || !execution.errors.every(error => typeof error === 'string')
        || !isNonEmptyString(payload.evidenceId)) {
        throw new Error('parser.result payload does not satisfy the browser execution contract');
      }
      return response;
    }
    const parserOrigin = (() => {
      try { return new URL(payload.report?.startUrl).origin; }
      catch { return null; }
    })();
    if (request.payload.operation !== 'parse_site'
      || payload.operation !== 'parse_site'
      || payload.phase !== request.payload.phase
      || !['before', 'after'].includes(payload.phase)
      || parserOrigin !== request.payload.origin
      || payload.report?.schemaVersion !== '3.4'
      || !Array.isArray(payload.report.pages)
      || !payload.report.pages.every(page => isObject(page)
        && urlHasOrigin(page.url, request.payload.origin))
      || !Array.isArray(payload.observedPosts)
      || !payload.observedPosts.every(post => isObject(post)
        && (post.id === null || typeof post.id === 'string')
        && (post.title === null || typeof post.title === 'string')
        && (post.author === null || typeof post.author === 'string')
        && urlHasOrigin(post.pageUrl, request.payload.origin))
      || !Array.isArray(payload.errors)
      || typeof payload.truncated !== 'boolean'
      || !isNonEmptyString(payload.evidenceId)) {
      throw new Error('parser.result payload does not satisfy the site observation contract');
    }
  }
  if (expectedType === 'attack.result') {
    const payload = response.payload;
    const httpResponse = payload.response;
    const matchingRequest = isObject(payload.request)
      && payload.request.method === request.payload.curl?.method
      && payload.request.url === request.payload.curl?.url
      && payload.request.session === request.payload.session;
    const validStatus = httpResponse?.status === null
      || (Number.isInteger(httpResponse?.status)
        && httpResponse.status >= 100 && httpResponse.status <= 599);
    const expectedOk = httpResponse?.status !== null
      && httpResponse?.status >= 200 && httpResponse?.status < 300;
    const validError = payload.error === null
      || (typeof payload.error === 'string' && payload.error.length > 0);
    if (request.payload.operation !== 'execute_curl'
      || payload.operation !== 'execute_curl'
      || typeof payload.success !== 'boolean'
      || !matchingRequest
      || !isObject(httpResponse)
      || !validStatus
      || typeof httpResponse.ok !== 'boolean'
      || httpResponse.ok !== expectedOk
      || !isObject(httpResponse.bodyJson)
      || !isObject(payload.guardrail)
      || !['ALLOW', 'DENY'].includes(payload.guardrail.decision)
      || !isNonEmptyString(payload.guardrail.ruleId)
      || !isNonEmptyString(payload.guardrail.stage)
      || (payload.success && payload.guardrail.decision !== 'ALLOW')
      || !validError
      || (payload.success && (!httpResponse.ok || payload.error !== null))
      || (!payload.success && !payload.error)
      || !isNonEmptyString(payload.evidenceId)) {
      throw new Error('attack.result payload does not satisfy the curl result contract');
    }
  }
  if (expectedType === 'history.result') {
    const payload = response.payload;
    if (request.payload.operation !== 'assess_xss_history'
      || payload.operation !== 'assess_xss_history'
      || !Array.isArray(payload.assessments)
      || !payload.assessments.every(assessment => isObject(assessment)
        && ['retest_candidate', 'manual_review', 'no_match'].includes(assessment.decision)
        && Array.isArray(assessment.matches))
      || !Number.isInteger(payload.readyCaseCount) || payload.readyCaseCount < 0
      || !Array.isArray(payload.observations)
      || !payload.observations.every(isObject)
      || !isNonEmptyString(payload.evidenceId)) {
      throw new Error('history.result payload does not satisfy the XSS assessment contract');
    }
  }
  if (expectedType === 'storage.attack_info') {
    const payload = response.payload;
    if (payload.operation !== 'get_attack_info'
      || (payload.attackInfo !== null && !isObject(payload.attackInfo))
      || !isNonEmptyString(payload.evidenceId)) {
      throw new Error('storage.attack_info payload does not satisfy the catalog contract');
    }
  }
  if (expectedType === 'storage.appended' && response.payload.ok !== true) {
    throw new Error('storage.appended payload must acknowledge the write');
  }
  if (expectedType === 'storage.finalized'
    && (response.payload.ok !== true
      || typeof response.payload.artifactRef !== 'string'
      || response.payload.artifactRef.length === 0)) {
    throw new Error('storage.finalized payload must contain an artifact reference');
  }
  return response;
}

async function invokeJson(gateway, request, { timeoutMs = DEFAULT_GATEWAY_TIMEOUT_MS } = {}) {
  validateEnvelope(request);
  if (!gateway || typeof gateway.exchange !== 'function') {
    throw new TypeError('Agent requires a JSON gateway with exchange(serializedRequest)');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('Gateway timeout must be a positive integer');
  }

  const rawRequest = JSON.stringify(request);
  if (Buffer.byteLength(rawRequest, 'utf8') > MAX_MESSAGE_BYTES) {
    return gatewayError(request, 'PROTOCOL_FAILURE', 'Module message exceeds 1 MB');
  }

  let rawResponse;
  const controller = new AbortController();
  let timeoutId;
  try {
    rawResponse = await Promise.race([
      Promise.resolve().then(() => gateway.exchange(rawRequest, { signal: controller.signal })),
      new Promise((resolve, reject) => {
        timeoutId = setTimeout(() => {
          controller.abort();
          reject(new Error(`Gateway response timed out after ${timeoutMs} ms`));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : String(error ?? 'Unknown gateway rejection');
    return gatewayError(request, 'TRANSPORT_FAILURE', message);
  } finally {
    clearTimeout(timeoutId);
  }

  try {
    const response = parseEnvelope(rawResponse, request.sender);
    if (response.runId !== request.runId || response.iteration !== request.iteration) {
      throw new Error('Module response run or iteration mismatch');
    }
    if (response.sender !== request.receiver || response.correlationId !== request.messageId) {
      throw new Error('Module response sender or correlation mismatch');
    }
    return validateResponseContract(request, response);
  } catch (error) {
    return gatewayError(request, 'PROTOCOL_FAILURE', error.message);
  }
}

function assertModuleSuccess(response) {
  validateEnvelope(response);
  if (response.type !== 'module.error') return response;
  const details = response.payload.error || {};
  const error = new Error(details.message || `Module ${response.sender} failed`);
  const reportedCode = details.code || 'MODULE_FAILURE';
  const isGatewayError = response.sender === 'agent';
  const reservedGatewayCodes = new Set(['TRANSPORT_FAILURE', 'PROTOCOL_FAILURE']);
  error.code = !isGatewayError && reservedGatewayCodes.has(reportedCode)
    ? 'EXTERNAL_MODULE_FAILURE'
    : reportedCode;
  error.source = isGatewayError ? 'agent_gateway' : 'external_module';
  if (error.code !== reportedCode) error.reportedCode = reportedCode;
  if (!isGatewayError) error.externalModule = response.sender;
  error.moduleResponse = response;
  throw error;
}

module.exports = {
  DEFAULT_GATEWAY_TIMEOUT_MS,
  MAX_MESSAGE_BYTES,
  MODULE_NAMES,
  SCHEMA_VERSION,
  assertModuleSuccess,
  createEnvelope,
  invokeJson,
  isObject,
  parseEnvelope,
  replyTo,
  validateEnvelope,
  validateResponseContract,
};
