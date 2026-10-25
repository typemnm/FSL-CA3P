'use strict';

const fs = require('node:fs');
const { isPlainObject } = require('./utils');

function validateRuleset(ruleset) {
  if (!isPlainObject(ruleset)) throw new TypeError('Ruleset must be a JSON object');
  if (!/^1\./.test(ruleset.schemaVersion || '')) throw new Error('Unsupported ruleset schemaVersion');
  if (ruleset.engine?.defaultDecision !== 'DENY' || ruleset.engine?.failureMode !== 'closed') {
    throw new Error('Ruleset must be fail-closed with DENY as the default');
  }
  if (!Array.isArray(ruleset.endpointCatalog)) throw new Error('endpointCatalog must be an array');
  if (!Array.isArray(ruleset.hardDenyRules)) throw new Error('hardDenyRules must be an array');
  if (!isPlainObject(ruleset.profiles)) throw new Error('profiles must be an object');
  const ids = new Set();
  for (const rule of ruleset.hardDenyRules) {
    if (!rule?.id || ids.has(rule.id)) throw new Error('Hard-deny rule IDs must be unique and non-empty');
    ids.add(rule.id);
  }
  return ruleset;
}

function loadRuleset(filePath) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load ruleset: ${error.message}`);
  }
  return validateRuleset(parsed);
}

module.exports = { loadRuleset, validateRuleset };
