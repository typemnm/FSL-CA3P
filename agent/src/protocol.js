'use strict';

const { randomUUID } = require('node:crypto');

const SCHEMA_VERSION = '1.0';
const MAX_MESSAGE_BYTES = 1_000_000;
const MODULE_NAMES = new Set([
  'orchestrator',
  'scope_guard',
  'web_explorer',
  'vulnerability_db',
  'rule_reasoner',
  'pentest_db',
]);
const MESSAGE_TYPES = new Set([
  'module.request',
  'module.error',
  'scope.request',
  'scope.authorized',
  'web.result',
  'knowledge.result',
  'reasoner.decision',
  'reasoner.reflection',
  'storage.request',
  'storage.appended',
  'storage.finalized',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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

async function invokeJson(module, request) {
  validateEnvelope(request);
  try {
    const rawResponse = await module.handle(JSON.stringify(request));
    const response = parseEnvelope(rawResponse, request.sender);
    if (response.runId !== request.runId || response.iteration !== request.iteration) {
      throw new Error('Module response run or iteration mismatch');
    }
    if (response.sender !== request.receiver || response.correlationId !== request.messageId) {
      throw new Error('Module response sender or correlation mismatch');
    }
    return response;
  } catch (error) {
    return replyTo(request, request.receiver, 'module.error', {
      error: {
        code: error.code || 'MODULE_FAILURE',
        message: error.message,
        retryable: false,
        causedBy: request.messageId,
      },
    });
  }
}

function assertModuleSuccess(response) {
  validateEnvelope(response);
  if (response.type !== 'module.error') return response;
  const details = response.payload.error || {};
  const error = new Error(details.message || `Module ${response.sender} failed`);
  error.code = details.code || 'MODULE_FAILURE';
  error.moduleResponse = response;
  throw error;
}

module.exports = {
  MAX_MESSAGE_BYTES,
  SCHEMA_VERSION,
  assertModuleSuccess,
  createEnvelope,
  invokeJson,
  isObject,
  parseEnvelope,
  replyTo,
  validateEnvelope,
};
