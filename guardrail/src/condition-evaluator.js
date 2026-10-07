'use strict';

const { containsKeyDeep, deepEqual, getField, isPlainObject } = require('./utils');

function queryKeys(query) {
  return isPlainObject(query) ? Object.keys(query).sort() : [];
}

function bodyKeys(body) {
  return isPlainObject(body) ? Object.keys(body).sort() : [];
}

class ConditionEvaluator {
  evaluate(condition, context) {
    if (!isPlainObject(condition)) throw new TypeError('Condition must be an object');
    if (condition.all) {
      if (!Array.isArray(condition.all)) throw new TypeError('all must be an array');
      return condition.all.every(item => this.evaluate(item, context));
    }
    if (condition.any) {
      if (!Array.isArray(condition.any)) throw new TypeError('any must be an array');
      return condition.any.some(item => this.evaluate(item, context));
    }

    const actual = condition.field ? getField(context, condition.field) : undefined;
    switch (condition.operator) {
      case 'equals': return deepEqual(actual, condition.value);
      case 'not_equals': return !deepEqual(actual, condition.value);
      case 'in': return Array.isArray(condition.values) && condition.values.some(value => deepEqual(actual, value));
      case 'not_in': return Array.isArray(condition.values) && !condition.values.some(value => deepEqual(actual, value));
      case 'contains': return Array.isArray(actual) ? actual.includes(condition.value) : String(actual ?? '').includes(String(condition.value));
      case 'matches': return new RegExp(condition.value, condition.flags || '').test(String(actual ?? ''));
      case 'field_present': return actual !== undefined && actual !== null && String(actual).length > 0;
      case 'equals_field': {
        const expected = getField(context, condition.value);
        return actual !== undefined
          && actual !== null
          && expected !== undefined
          && expected !== null
          && String(actual) === String(expected);
      }
      case 'less_than': return Number.isFinite(actual) && actual < condition.value;
      case 'between_inclusive': return Number.isFinite(actual) && actual >= condition.values[0] && actual <= condition.values[1];
      case 'starts_with': return typeof actual === 'string' && actual.startsWith(condition.value);
      case 'starts_with_field': {
        const expected = getField(context, condition.value);
        return typeof actual === 'string'
          && typeof expected === 'string'
          && expected.length > 0
          && actual.startsWith(expected);
      }
      case 'exact_keys': return deepEqual(Object.keys(actual || {}).sort(), [...condition.values].sort());
      case 'classified_as': return context.classifications.includes(condition.value);
      case 'not_classified_as': return !context.classifications.includes(condition.value);
      case 'unsafe_url_reference': return this.unsafeUrl(actual);
      case 'not_in_endpoint_catalog': return this.notInEndpointCatalog(context);
      case 'has_duplicate_query_parameter': return this.hasDuplicateQuery(context.action?.query);
      case 'untrusted_input_contains_trusted_fields': return this.hasTrustedFieldSpoof(context.action);
      case 'contains_forbidden_keys': return containsKeyDeep(actual, new Set(condition.values.map(value => value.toLowerCase())));
      case 'budget_exceeded': return this.budgetExceeded(context);
      case 'not_exactly_one_nonempty_value': return !this.exactlyOneNonEmpty(actual);
      default: throw new Error(`Unsupported operator: ${condition.operator}`);
    }
  }

  unsafeUrl(value) {
    if (value === undefined) return false;
    if (typeof value !== 'string') return true;
    return /^[a-z][a-z0-9+.-]*:/i.test(value)
      || value.startsWith('//')
      || value.includes('#')
      || value.includes('\\');
  }

  notInEndpointCatalog(context) {
    const action = context.action;
    if (action?.operation === 'browser_fuzz') return false;
    if (action?.operation !== 'http_request') return true;
    const endpoint = context.endpointCatalog.find(item => (
      item.method === String(action.method || '').toUpperCase()
      && new RegExp(item.pathPattern).test(action.path || '')
    ));
    if (!endpoint) return true;
    return !deepEqual(queryKeys(action.query), [...endpoint.queryKeys].sort())
      || !deepEqual(bodyKeys(action.body), [...endpoint.bodyKeys].sort());
  }

  hasDuplicateQuery(query) {
    if (!isPlainObject(query)) return query !== undefined;
    return Object.values(query).some(value => Array.isArray(value) && value.length > 1);
  }

  hasTrustedFieldSpoof(action) {
    return containsKeyDeep(action, new Set([
      'trustedcontext', 'policycontext', 'boundcanary', 'networkpolicy', 'budget',
    ]));
  }

  exactlyOneNonEmpty(value) {
    if (Array.isArray(value)) return value.length === 1 && String(value[0]).length > 0;
    return typeof value === 'string' && value.length > 0;
  }

  budgetExceeded(context) {
    const limits = context.profile?.trustedContextRequirements || {};
    const budget = context.trustedContext?.budget;
    if (!isPlainObject(budget)) return true;
    const checks = [
      ['maximumHttpRequests', 'requestCount'],
      ['maximumMutations', 'mutationCount'],
      ['maximumXssSubmissions', 'xssSubmissionCount'],
    ];
    for (const [limitKey, counterKey] of checks) {
      if (limits[limitKey] === undefined) continue;
      if (!Number.isInteger(budget[counterKey]) || budget[counterKey] < 0) return true;
      const relevant = counterKey === 'requestCount'
        || (counterKey === 'mutationCount' && ['POST', 'DELETE'].includes(context.action?.method))
        || (counterKey === 'xssSubmissionCount' && context.stage === 'xss.inject_canary');
      if (relevant && budget[counterKey] >= limits[limitKey]) return true;
    }
    return Number.isInteger(limits.maximumIterations)
      && (!Number.isInteger(context.trustedContext.iteration)
        || context.trustedContext.iteration > limits.maximumIterations);
  }
}

module.exports = { ConditionEvaluator };
