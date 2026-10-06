'use strict';

const { randomUUID } = require('node:crypto');

const SCHEMA_VERSION = '1.0';
const MAX_MESSAGE_BYTES = 1_000_000;
const DEFAULT_GATEWAY_TIMEOUT_MS = 10_000;
const MODULE_NAMES = new Set([
  'agent',
  'web_explorer',
  'vulnerability_db',
  'pentest_db',
]);
const MESSAGE_TYPES = new Set([
  'module.request',
  'module.error',
  'web.result',
  'knowledge.result',
  'storage.request',
  'storage.appended',
  'storage.finalized',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isKnowledgeCandidate(candidate) {
  return isObject(candidate)
    && isNonEmptyString(candidate.knowledgeId)
    && isNonEmptyString(candidate.cwe)
    && isNonEmptyString(candidate.severity)
    && isNonEmptyString(candidate.severityBasis)
    && isNonEmptyString(candidate.attackerId)
    && isObject(candidate.resource)
    && ['string', 'number'].includes(typeof candidate.resource.id)
    && isNonEmptyString(candidate.resource.ownerId)
    && isObject(candidate.actionTemplate)
    && isNonEmptyString(candidate.actionTemplate.method)
    && isNonEmptyString(candidate.actionTemplate.pathTemplate)
    && Array.isArray(candidate.successCriteria)
    && candidate.successCriteria.every(isNonEmptyString)
    && isObject(candidate.provenance);
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
  if (request.receiver === 'web_explorer' && request.type === 'module.request') {
    expectedType = 'web.result';
  } else if (request.receiver === 'vulnerability_db' && request.type === 'module.request') {
    expectedType = 'knowledge.result';
  } else if (request.receiver === 'pentest_db' && request.type === 'storage.request') {
    if (request.payload.operation === 'append') expectedType = 'storage.appended';
    if (request.payload.operation === 'finalize') expectedType = 'storage.finalized';
  }
  if (!expectedType) throw new Error('Unsupported external request contract');
  if (response.type !== expectedType) {
    throw new Error(`Expected ${expectedType} response, received ${response.type}`);
  }

  if (expectedType === 'web.result') {
    const httpResponse = response.payload.response;
    if (response.payload.operation !== 'http_request'
      || !isObject(httpResponse)
      || !Number.isInteger(httpResponse.status)
      || httpResponse.status < 100
      || httpResponse.status > 599
      || typeof httpResponse.ok !== 'boolean'
      || httpResponse.ok !== (httpResponse.status >= 200 && httpResponse.status < 300)
      || !isObject(httpResponse.bodyJson)
      || typeof response.payload.evidenceId !== 'string'
      || response.payload.evidenceId.length === 0) {
      throw new Error('web.result payload does not satisfy the HTTP evidence contract');
    }
  }
  if (expectedType === 'knowledge.result'
    && (!Array.isArray(response.payload.candidates)
      || !response.payload.candidates.every(isKnowledgeCandidate))) {
    throw new Error('knowledge.result payload must contain valid candidate contracts');
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
