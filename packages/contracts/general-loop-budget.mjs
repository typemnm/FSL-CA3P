export const GENERAL_LOOP_BUDGET_DEFAULTS = Object.freeze({
  maxIterations: 6,
  maxProbes: 24,
  maxEvidenceItems: 128,
});

export const GENERAL_LOOP_BUDGET_CAPS = Object.freeze({
  maxIterations: 32,
  maxProbes: 128,
  maxEvidenceItems: 256,
});

const fields = Object.keys(GENERAL_LOOP_BUDGET_DEFAULTS);
const invalid = () => Object.assign(new TypeError('Provide all three general loop limits within their allowed ranges.'),
  { status: 400, code: 'INVALID_GENERAL_LOOP_BUDGET' });

export function validateGeneralLoopBudget(limits) {
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)
    || Object.keys(limits).length !== fields.length
    || fields.some(field => !Object.hasOwn(limits, field))) throw invalid();
  const result = {};
  for (const field of fields) {
    const value = limits[field];
    if (!Number.isSafeInteger(value) || value < 1 || value > GENERAL_LOOP_BUDGET_CAPS[field]) throw invalid();
    result[field] = value;
  }
  return result;
}

export function validateGeneralLoopBudgetPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).length !== 1 || !Object.hasOwn(body, 'limits')) throw invalid();
  return validateGeneralLoopBudget(body.limits);
}
