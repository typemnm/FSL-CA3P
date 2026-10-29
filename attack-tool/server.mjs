import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { listTemplates, renderTemplate, verifyTemplate, projectTemplateResponse } from './templates.mjs';

const MAX_BYTES = 128 * 1024;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fault = (code, message = code) => Object.assign(new Error(message), { code });
const tools = [
  { name: 'list_attack_templates', description: 'Find packet templates by vulnerability and dependency. Templates are references, never authorization.',
    inputSchema: { type: 'object', properties: Object.fromEntries(['attackType', 'runtime', 'framework', 'library'].map(key => [key, { type: 'string' }])), additionalProperties: false } },
  { name: 'execute_attack_template', description: 'Execute the fixed baseline and attack packets through the server-bound guardrail, then compare results.',
    inputSchema: { type: 'object', required: ['templateId', 'payload'], properties: { templateId: { const: 'sqli-like-tautology' }, payload: { type: 'string', enum: listTemplates()[0].payloads } }, additionalProperties: false } },
  { name: 'execute_probe', description: 'Execute an application capability through its server-bound policy and executor.',
    inputSchema: { type: 'object', required: ['probe', 'hypothesis'], properties: { probe: { type: 'object' }, hypothesis: { type: 'object' } }, additionalProperties: false } },
];

async function readJson(request) {
  const parts = []; let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BYTES) throw fault('REQUEST_TOO_LARGE');
    parts.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); }
  catch { throw fault('INVALID_JSON'); }
}

/** Host code registers principals and capabilities; none can be supplied by an AI request. */
export async function createAttackTool({ host = '127.0.0.1', ports = [0, 0], principals = [], timeoutMs = 30_000 } = {}) {
  if (!['127.0.0.1', '::1', '0.0.0.0'].includes(host)
    || !Array.isArray(ports) || !ports.length || ports.length > 32
    || ports.some(port => !Number.isInteger(port) || port < 0 || port > 65535)
    || new Set(ports.filter(Boolean)).size !== ports.filter(Boolean).length
    || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000) throw fault('INVALID_CONFIG');
  const identities = new Map(), servers = [], controllers = new Set();
  const counters = { requests: 0, denied: 0 };
  let closed = false;
  function registerPrincipal({ agentId, runId, portIndex = 0, token = randomBytes(32).toString('hex'),
    authorize, execute, guardrail } = {}) {
    if (closed || !/^[A-Za-z0-9:_.-]{1,128}$/.test(agentId ?? '')
      || !/^[A-Za-z0-9:_.-]{1,128}$/.test(runId ?? '') || identities.has(agentId)
      || !Number.isInteger(portIndex) || portIndex < 0 || portIndex >= ports.length
      || typeof token !== 'string' || token.length < 32 || token.length > 256
      || [...identities.values()].some(item => item.token === token)) throw fault('INVALID_PRINCIPAL');
    const principal = { agentId, runId, portIndex, token, authorize, execute, guardrail, queue: Promise.resolve() };
    identities.set(agentId, principal);
    return { agentId, runId, portIndex, token };
  }
  principals.forEach(registerPrincipal);
  const reply = (response, status, value) => {
    if (response.destroyed || response.writableEnded) return;
    const body = JSON.stringify(value);
    if (Buffer.byteLength(body) > MAX_BYTES) return reply(response, 500, { error: 'RESPONSE_TOO_LARGE' });
    response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(body);
  };
  async function dispatch(principal, message, signal) {
    signal.throwIfAborted();
    if (!record(message) || message.jsonrpc !== '2.0'
      || !['string', 'number'].includes(typeof message.id)
      || (typeof message.id === 'string' && message.id.length > 128)
      || Object.keys(message).some(key => !['jsonrpc', 'id', 'method', 'params'].includes(key))) throw fault('INVALID_REQUEST');
    if (message.method === 'initialize') return { protocolVersion: 'ca3p-attack-tool-1', agentId: principal.agentId,
      runId: principal.runId, capabilities: { tools: {} } };
    if (message.method === 'tools/list') return { tools: tools.filter(tool => tool.name === 'list_attack_templates'
      || (tool.name === 'execute_probe' ? principal.authorize && principal.execute : principal.guardrail)) };
    if (message.method !== 'tools/call') throw fault('METHOD_NOT_FOUND');
    const params = message.params;
    if (!record(params) || Object.keys(params).some(key => !['name', 'arguments'].includes(key))
      || !record(params.arguments)) throw fault('INVALID_ARGUMENTS');
    const input = params.arguments;
    const context = { agentId: principal.agentId, runId: principal.runId, signal };
    if (params.name === 'list_attack_templates') {
      if (Object.keys(input).some(key => !['attackType', 'runtime', 'framework', 'library'].includes(key))
        || Object.values(input).some(value => typeof value !== 'string' || value.length > 128)) throw fault('INVALID_ARGUMENTS');
      return { templates: listTemplates(input) };
    }
    if (params.name === 'execute_attack_template') {
      if (typeof principal.guardrail?.execute !== 'function') throw fault('CAPABILITY_UNAVAILABLE');
      const rendered = renderTemplate(input);
      const baseline = await principal.guardrail.execute(rendered.baseline, context);
      signal.throwIfAborted();
      const attack = await principal.guardrail.execute(rendered.packet, context);
      const verification = verifyTemplate(baseline, attack);
      return { templateId: rendered.template.templateId,
        baseline: projectTemplateResponse(baseline), attack: projectTemplateResponse(attack), verification };
    }
    if (params.name === 'execute_probe') {
      if (typeof principal.authorize !== 'function' || typeof principal.execute !== 'function') throw fault('CAPABILITY_UNAVAILABLE');
      if (Object.keys(input).length !== 2 || !record(input.probe) || !record(input.hypothesis)) throw fault('INVALID_ARGUMENTS');
      const decision = await principal.authorize(input, context);
      signal.throwIfAborted();
      if (decision?.allowed !== true) { counters.denied += 1; throw fault('GUARDRAIL_DENIED'); }
      return principal.execute(input, context);
    }
    throw fault('TOOL_NOT_FOUND');
  }
  try {
    for (const [index, port] of ports.entries()) {
      const server = createServer(async (request, response) => {
        if (request.method === 'GET' && request.url === '/health') return reply(response, 200, { status: 'ok', service: 'attack-tool', protocolVersion: 'ca3p-attack-tool-1' });
        if (request.method !== 'POST' || request.url !== '/rpc') return reply(response, 404, { error: 'NOT_FOUND' });
        // Browser pages cannot use credentials to turn this local daemon into a cross-origin proxy.
        if (request.headers.origin || !/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] ?? '')) return reply(response, 415, { error: 'INVALID_CONTENT_TYPE' });
        const authorization = request.headers.authorization;
        const supplied = typeof authorization === 'string' && authorization.startsWith('Bearer ')
          ? authorization.slice(7) : '';
        const identity = [...identities.values()].find(item => item.portIndex === index
          && Buffer.byteLength(supplied) === Buffer.byteLength(item.token)
          && timingSafeEqual(Buffer.from(supplied), Buffer.from(item.token)));
        if (!identity) return reply(response, 401, { error: 'UNAUTHORIZED' });
        const controller = new AbortController(); controllers.add(controller);
        const timer = setTimeout(() => controller.abort(fault('REQUEST_TIMEOUT')), timeoutMs);
        const abort = () => { if (!response.writableEnded) controller.abort(fault('CLIENT_DISCONNECTED')); };
        response.once('close', abort);
        let message;
        try {
          counters.requests += 1;
          const cancelled = new Promise((_, reject) => {
            controller.signal.addEventListener('abort', () => reject(controller.signal.reason), { once: true });
          });
          message = await Promise.race([readJson(request), cancelled]);
          controller.signal.throwIfAborted();
          // Serialize one worker's capability calls to preserve stateful policy
          // reservations. Different workers and ports can run concurrently.
          const pending = identity.queue.then(() => dispatch(identity, message, controller.signal));
          identity.queue = pending.catch(() => {});
          const result = await Promise.race([pending, cancelled]);
          reply(response, 200, { jsonrpc: '2.0', id: message.id, result,
            context: { agentId: identity.agentId, runId: identity.runId } });
        } catch (error) {
          const code = typeof error?.code === 'string' && /^[A-Z_]{1,64}$/.test(error.code) ? error.code : 'EXECUTION_FAILED';
          const id = ['string', 'number'].includes(typeof message?.id) ? message.id : null;
          reply(response, 200, { jsonrpc: '2.0', id, error: { code, message: code } });
        } finally { clearTimeout(timer); controllers.delete(controller); response.off('close', abort); request.resume(); }
      });
      server.requestTimeout = timeoutMs; server.headersTimeout = Math.min(timeoutMs, 10_000);
      servers.push(server);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
    }
  } catch (error) { await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve)))); throw error; }
  return {
    endpoints: servers.map(server => `http://${host === '0.0.0.0' ? '127.0.0.1' : host === '::1' ? '[::1]' : host}:${server.address().port}`),
    registerPrincipal,
    metrics: () => ({ ...counters, agents: identities.size, ports: servers.length }),
    async close() {
      closed = true;
      for (const controller of controllers) controller.abort(fault('SERVER_CLOSED'));
      await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); })));
      identities.clear();
    },
  };
}
