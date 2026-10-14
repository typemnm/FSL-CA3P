'use strict';

const NAMED_ENTITIES = Object.freeze({
  amp: '&', apos: "'", colon: ':', gt: '>', lt: '<', quot: '"', sol: '/', tab: '\t', newline: '\n',
});

function decodeHtmlEntities(value) {
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);?/gi, (whole, entity) => {
    const lower = entity.toLowerCase();
    if (lower.startsWith('#x')) return String.fromCodePoint(Number.parseInt(lower.slice(2), 16));
    if (lower.startsWith('#')) return String.fromCodePoint(Number.parseInt(lower.slice(1), 10));
    return Object.hasOwn(NAMED_ENTITIES, lower) ? NAMED_ENTITIES[lower] : whole;
  });
}

function normalizeString(input, options = {}) {
  const maxBytes = options.maximumInputBytes ?? 65536;
  const passes = options.maximumDecodePasses ?? 2;
  if (typeof input !== 'string') return input;
  if (Buffer.byteLength(input, 'utf8') > maxBytes) throw new Error('Input exceeds the normalization byte limit');
  if (input.includes('\0')) throw new Error('NUL bytes are forbidden');

  let value = input;
  for (let index = 0; index < passes; index += 1) {
    const before = value;
    if (/%[0-9a-f]{2}/i.test(value)) value = decodeURIComponent(value);
    value = decodeHtmlEntities(value);
    if (value === before) break;
  }
  if (/%[0-9a-f]{2}/i.test(value) || /&(?:#x[0-9a-f]+|#[0-9]+|(?:lt|gt|amp|quot|apos));?/i.test(value)) {
    throw new Error('Input remains encoded after the maximum decode passes');
  }
  return value.normalize('NFKC').toLowerCase();
}

function classify(ruleset, input) {
  const labels = new Set();
  const matchedClassifiers = [];
  for (const classifier of ruleset.classifiers || []) {
    let matched = false;
    for (const field of classifier.fields || []) {
      const raw = field.split('.').reduce((value, key) => value?.[key], input);
      if (classifier.match?.type === 'field_present') {
        matched ||= raw !== undefined && raw !== null && String(raw).length > 0;
      } else if (classifier.match?.type === 'regex_any' && typeof raw === 'string') {
        const normalized = normalizeString(raw, ruleset.normalization);
        matched ||= classifier.match.patterns.some(pattern => (
          new RegExp(pattern, classifier.match.flags || '').test(normalized)
        ));
      } else if (!['field_present', 'regex_any'].includes(classifier.match?.type)) {
        throw new Error(`Unsupported classifier type: ${classifier.match?.type}`);
      }
    }
    if (matched) {
      matchedClassifiers.push(classifier.id);
      for (const label of classifier.labels || []) labels.add(label);
    }
  }
  return { labels, matchedClassifiers };
}

module.exports = { classify, decodeHtmlEntities, normalizeString };
