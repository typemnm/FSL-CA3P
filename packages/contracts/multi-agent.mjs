export const MULTI_AGENT_DEFAULTS = Object.freeze({
  enabled: true,
  maxConcurrentAgents: 2,
  maxTasks: 4,
});
const OPTIONAL_LIMITS = Object.freeze({
  maxTargetRequests: [1, 224],
  maxModelRequests: [1, 160],
  maxModelTokens: [1, 1_000_000],
  deadlineMs: [1_000, 1_800_000],
});

const invalid = () => Object.assign(new TypeError('Choose bounded multi-agent follow-up settings.'),
  { status: 400, code: 'INVALID_MULTI_AGENT_OPTIONS' });

export function validateMultiAgentOptions(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || value.enabled !== true
    || Object.keys(value).some(key => !Object.hasOwn(MULTI_AGENT_DEFAULTS, key)
      && !Object.hasOwn(OPTIONAL_LIMITS, key))) throw invalid();
  const maxConcurrentAgents = value.maxConcurrentAgents ?? MULTI_AGENT_DEFAULTS.maxConcurrentAgents;
  const maxTasks = value.maxTasks ?? MULTI_AGENT_DEFAULTS.maxTasks;
  if (!Number.isSafeInteger(maxConcurrentAgents) || maxConcurrentAgents < 1 || maxConcurrentAgents > 2
    || !Number.isSafeInteger(maxTasks) || maxTasks < 1 || maxTasks > 4
    || maxConcurrentAgents > maxTasks) throw invalid();
  for (const [key, [minimum, maximum]] of Object.entries(OPTIONAL_LIMITS)) {
    if (value[key] !== undefined && (!Number.isSafeInteger(value[key])
      || value[key] < minimum || value[key] > maximum)) throw invalid();
  }
  return { enabled: true, maxConcurrentAgents, maxTasks,
    ...Object.fromEntries(Object.keys(OPTIONAL_LIMITS).filter(key => value[key] !== undefined)
      .map(key => [key, value[key]])) };
}
