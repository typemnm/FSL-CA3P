'use strict';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function getField(root, path) {
  if (typeof path !== 'string' || path.length === 0) return undefined;
  const parts = path.split('.');
  let value = root;
  for (const part of parts) {
    if (typeof value === 'string' && part === 'resourceId') {
      const match = value.match(/^\/api\/posts\/([0-9]+)$/);
      value = match?.[1];
      continue;
    }
    if (value === null || value === undefined) return undefined;
    value = value[part];
  }
  return value;
}

function deepEqual(left, right) {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((item, index) => deepEqual(item, right[index]));
  }
  if (!isPlainObject(left) || !isPlainObject(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return deepEqual(leftKeys, rightKeys)
    && leftKeys.every(key => deepEqual(left[key], right[key]));
}

function containsKeyDeep(value, forbidden) {
  if (Array.isArray(value)) return value.some(item => containsKeyDeep(item, forbidden));
  if (!isPlainObject(value)) return false;
  return Object.entries(value).some(([key, child]) => (
    forbidden.has(key.toLowerCase()) || containsKeyDeep(child, forbidden)
  ));
}

function isSubset(expected, actual) {
  if (Array.isArray(expected)) return deepEqual(expected, actual);
  if (!isPlainObject(expected)) return Object.is(expected, actual);
  if (!isPlainObject(actual)) return false;
  return Object.entries(expected).every(([key, value]) => isSubset(value, actual[key]));
}

module.exports = { containsKeyDeep, deepEqual, getField, isPlainObject, isSubset };
