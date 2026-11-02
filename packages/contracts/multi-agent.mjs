export const MULTI_AGENT_DEFAULTS = Object.freeze({
  enabled: true,
  maxConcurrentAgents: 2,
  maxTasks: 4,
});

const invalid = () => Object.assign(new TypeError('Choose bounded multi-agent follow-up settings.'),
  { status: 400, code: 'INVALID_MULTI_AGENT_OPTIONS' });

export function validateMultiAgentOptions(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || value.enabled !== true
    || Object.keys(value).some(key => !Object.hasOwn(MULTI_AGENT_DEFAULTS, key))) throw invalid();
  const maxConcurrentAgents = value.maxConcurrentAgents ?? MULTI_AGENT_DEFAULTS.maxConcurrentAgents;
  const maxTasks = value.maxTasks ?? MULTI_AGENT_DEFAULTS.maxTasks;
  if (!Number.isSafeInteger(maxConcurrentAgents) || maxConcurrentAgents < 1 || maxConcurrentAgents > 2
    || !Number.isSafeInteger(maxTasks) || maxTasks < 1 || maxTasks > 4
    || maxConcurrentAgents > maxTasks) throw invalid();
  return { enabled: true, maxConcurrentAgents, maxTasks };
}
