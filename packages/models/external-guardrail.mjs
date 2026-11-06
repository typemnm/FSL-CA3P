/** External probes require an explicitly configured local guardrail model. */
export function resolveExternalGuardrail({ env = process.env } = {}) {
  const endpoint = env.CA3P_GUARDRAIL_SLLM_ENDPOINT ?? env.SLLM_ENDPOINT;
  const model = env.CA3P_GUARDRAIL_SLLM_MODEL ?? env.SLLM_MODEL;
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || url.username || url.password || url.search || url.hash
      || typeof model !== 'string' || !model.trim()) throw new Error('Invalid local guardrail settings.');
    return { provider: 'local', endpoint, model: model.trim() };
  } catch { return { provider: 'unavailable', endpoint: null, model: null }; }
}
