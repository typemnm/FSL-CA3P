import { parse } from 'acorn';

function propertyName(property) {
  if (property?.key?.type === 'Identifier' && !property.computed) return property.key.name;
  if (property?.key?.type === 'Literal') return String(property.key.value);
  return null;
}

function objectProperty(object, name) {
  return object?.type === 'ObjectExpression' ?
    object.properties.find(property => propertyName(property) === name)?.value : null;
}

function staticText(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'TemplateLiteral') {
    return node.quasis.map((part, index) =>
      part.value.cooked + (index < node.expressions.length ? '{expression}' : '')).join('');
  }
  return null;
}

function calleeName(node) {
  if (node?.type === 'Identifier') return node.name;
  if (node?.type === 'MemberExpression') {
    const object = calleeName(node.object);
    const member = !node.computed && node.property.type === 'Identifier' ? node.property.name : null;
    return object && member ? object + '.' + member : null;
  }
  return null;
}

function bodyKeys(node) {
  const body = node?.type === 'CallExpression' && calleeName(node.callee) === 'JSON.stringify' ?
    node.arguments[0] : node;
  if (body?.type !== 'ObjectExpression') return [];
  return body.properties.map(propertyName).filter(Boolean).slice(0, 40);
}

function visit(node, callback) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) visit(child, callback);
    return;
  }
  if (typeof node.type === 'string') callback(node);
  for (const [key, value] of Object.entries(node)) {
    if (key !== 'loc' && value && typeof value === 'object') visit(value, callback);
  }
}

export function findScriptHints(source, scriptUrl) {
  if (typeof source !== 'string' || source.length > 1_000_000) {
    return { hints: [], error: 'Script was too large to analyze.' };
  }
  let program;
  try {
    program = parse(source, { ecmaVersion: 'latest', sourceType: 'module', locations: true, allowHashBang: true });
  } catch (error) {
    return { hints: [], error: error.message.slice(0, 200) };
  }
  const hints = [];
  visit(program, node => {
    if (node.type !== 'CallExpression' || hints.length >= 100) return;
    const callee = calleeName(node.callee);
    if (!callee || !/(?:^|\.)(?:fetch|api|request|get|post|put|patch|delete)$/.test(callee)) return;
    const endpointPattern = staticText(node.arguments[0]);
    if (!endpointPattern?.startsWith('/')) return;
    const options = node.arguments[1];
    const declaredMethod = staticText(objectProperty(options, 'method'))?.toUpperCase() ||
      (/\.(get|post|put|patch|delete)$/.exec(callee)?.[1].toUpperCase() ?? null);
    const keys = bodyKeys(objectProperty(options, 'body'));
    hints.push({
      scriptUrl,
      line: node.loc.start.line,
      callee,
      endpointPattern,
      declaredMethod,
      bodyKeys: keys,
      evidence: 'static JavaScript call; this request was not necessarily observed'
    });
  });
  return { hints, error: null };
}
