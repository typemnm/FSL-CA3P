import { randomUUID } from 'node:crypto';

export function createAttackToolClient({ endpoint, token, agentId, runId, timeoutMs = 35_000 } = {}) {
  const origin = new URL(endpoint);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.origin !== endpoint
    || origin.username || origin.password || typeof token !== 'string' || token.length < 32) throw new TypeError('Invalid attack-tool client configuration.');
  async function request(method, params, { signal } = {}) {
    const id = randomUUID();
    const response = await fetch(endpoint + '/rpc', { method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }),
      signal: AbortSignal.any([AbortSignal.timeout(timeoutMs), ...(signal ? [signal] : [])]) });
    if (!response.ok) throw Object.assign(new Error('Attack-tool HTTP ' + response.status), { code: 'ATTACK_TOOL_HTTP_ERROR' });
    const chunks = []; let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > 128 * 1024) throw new Error('Attack-tool response exceeded limit.');
      chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    const envelope = JSON.parse(text);
    if (envelope.jsonrpc !== '2.0' || envelope.id !== id) throw new Error('Attack-tool response correlation mismatch.');
    if (envelope.error) throw Object.assign(new Error(envelope.error.message), { code: envelope.error.code });
    if (envelope.context?.agentId !== agentId || envelope.context?.runId !== runId) throw new Error('Attack-tool response identity mismatch.');
    return envelope.result;
  }
  return { initialize: options => request('initialize', undefined, options),
    listTools: options => request('tools/list', undefined, options),
    call: (name, args, options) => request('tools/call', { name, arguments: args }, options) };
}
