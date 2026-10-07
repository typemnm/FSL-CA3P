import { parse } from 'acorn';

const LIMIT = 1_000_000;
const RENDER_PROPERTIES = new Set(['innerHTML', 'outerHTML', 'textContent']);
const RENDER_METHODS = new Set(['insertAdjacentHTML', 'replaceChildren', 'append', 'prepend']);

function prop(node) {
  if (!node || node.type !== 'MemberExpression') return null;
  if (!node.computed && node.property.type === 'Identifier') return node.property.name;
  if (node.property.type === 'Literal') return String(node.property.value);
  return null;
}

function name(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const base = name(node.object);
    const key = prop(node);
    return base && key ? base + '.' + key : null;
  }
  return null;
}

function text(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'TemplateLiteral') return node.quasis.map((part, index) =>
    part.value.cooked + (index < node.expressions.length ?
      '{' + expressionName(node.expressions[index]) + '}' : '')).join('');
  return null;
}

function expressionName(node) {
  const inner = node?.type === 'CallExpression' && name(node.callee) === 'encodeURIComponent' ?
    node.arguments[0] : node;
  return name(inner) || 'expression';
}

function objectValue(node, key) {
  if (node?.type !== 'ObjectExpression') return null;
  const item = node.properties.find(entry =>
    entry.type === 'Property' && !entry.computed &&
    (entry.key.name || entry.key.value) === key);
  return item?.value || null;
}

function bodyKeys(node) {
  const body = node?.type === 'CallExpression' && name(node.callee) === 'JSON.stringify' ?
    node.arguments[0] : node;
  if (body?.type !== 'ObjectExpression') return [];
  return body.properties.filter(item => item.type === 'Property' && !item.computed)
    .map(item => item.key.name || item.key.value).filter(item => typeof item === 'string').slice(0, 20);
}

function walk(node, callback) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, callback);
    return;
  }
  if (node.type) callback(node);
  for (const [key, value] of Object.entries(node)) {
    if (key !== 'loc' && key !== 'parent' && value && typeof value === 'object') walk(value, callback);
  }
}

function walkEffects(node, callback) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) walkEffects(item, callback);
    return;
  }
  callback(node);
  if (node.type === 'CallExpression' && prop(node.callee) === 'addEventListener') return;
  for (const value of Object.values(node)) {
    if (value && typeof value === 'object') walkEffects(value, callback);
  }
}

function selectorOf(node, selectors, aliases = new Map()) {
  if (!node) return null;
  if (node.type === 'Identifier') return aliases.get(node.name) || selectors.get(node.name) || null;
  if (node.type === 'MemberExpression') return selectors.get(name(node)) || null;
  if (node.type === 'CallExpression') {
    const called = name(node.callee);
    if (called === 'Array.from') return selectorOf(node.arguments[0], selectors, aliases);
    if (['document.querySelector', 'document.querySelectorAll'].includes(called)) return text(node.arguments[0]);
    if (called === 'document.getElementById') {
      const id = text(node.arguments[0]);
      return id ? '#' + id : null;
    }
  }
  return null;
}

function selectorsFrom(program) {
  const selectors = new Map();
  const created = new Set();
  walk(program, node => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier') return;
    if (node.init?.type === 'CallExpression' && name(node.init.callee) === 'document.createElement') {
      created.add(node.id.name);
    }
    if (node.init?.type === 'ObjectExpression') {
      for (const item of node.init.properties) {
        if (item.type !== 'Property' || item.computed) continue;
        const key = item.key.name || item.key.value;
        const selector = selectorOf(item.value, selectors);
        if (selector) selectors.set(node.id.name + '.' + key, selector);
      }
    }
    const selector = selectorOf(node.init, selectors);
    if (selector) selectors.set(node.id.name, selector);
  });
  walk(program, node => {
    if (node.type !== 'AssignmentExpression' || node.left?.type !== 'MemberExpression' ||
      node.left.object.type !== 'Identifier' || !created.has(node.left.object.name)) return;
    const value = text(node.right);
    if (!value || !/^[a-zA-Z_][\w-]*$/.test(value)) return;
    if (prop(node.left) === 'className') selectors.set(node.left.object.name, '.' + value);
    if (prop(node.left) === 'id') selectors.set(node.left.object.name, '#' + value);
  });
  return { selectors, created };
}

function defaultGetWrapper(called, functions) {
  const fn = functions.get(called);
  if (!fn) return false;
  const options = fn.params?.[1];
  if (options?.type !== 'AssignmentPattern' || options.right.type !== 'ObjectExpression' ||
    options.right.properties.length) return false;
  let fetchCall = false;
  walk(fn.body, node => {
    if (node.type === 'CallExpression' && name(node.callee) === 'fetch' &&
      node.arguments[0]?.type === 'Identifier' && node.arguments[0].name === fn.params[0]?.name) {
      fetchCall = true;
    }
  });
  return fetchCall;
}

function callRequest(node, baseUrl, functions) {
  if (node.type !== 'CallExpression') return null;
  const called = name(node.callee);
  if (!called || !/(?:^|\.)(?:fetch|api|request|get|post|put|patch|delete)$/.test(called)) return null;
  const raw = text(node.arguments[0]);
  if (!raw) return null;
  let url;
  try { url = new URL(raw, baseUrl); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== new URL(baseUrl).origin) return null;
  const options = node.arguments[1];
  const method = text(objectValue(options, 'method'))?.toUpperCase() ||
    /\.(get|post|put|patch|delete)$/.exec(called)?.[1].toUpperCase() ||
    (called === 'fetch' || defaultGetWrapper(called, functions) ? 'GET' : 'UNKNOWN');
  const keys = /\.(post|put|patch)$/.test(called) ? bodyKeys(options) :
    bodyKeys(objectValue(options, 'body'));
  return { method, url: url.href, ...(keys.length ? { bodyKeys: keys } : {}) };
}

function effects(node, baseUrl, selectors, created, functions) {
  const calls = new Set(), requests = [], renders = [];
  walkEffects(node, item => {
    if (item.type === 'CallExpression') {
      const request = callRequest(item, baseUrl, functions);
      if (request) requests.push(request);
      else if (item.callee.type === 'Identifier' && functions.has(item.callee.name)) {
        calls.add(item.callee.name);
      }
      const operation = prop(item.callee);
      if (RENDER_METHODS.has(operation)) {
        if (item.callee.object?.type === 'Identifier' && created.has(item.callee.object.name)) return;
        const selector = selectorOf(item.callee.object, selectors);
        if (selector) renders.push({ selector, operation });
      }
    }
    if (item.type === 'AssignmentExpression' && RENDER_PROPERTIES.has(prop(item.left))) {
      if (item.left.object?.type === 'Identifier' && created.has(item.left.object.name) &&
        !['innerHTML', 'outerHTML'].includes(prop(item.left))) return;
      const selector = selectorOf(item.left.object, selectors);
      const value = name(item.right);
      if (selector || prop(item.left) === 'innerHTML') {
        renders.push({ selector, operation: prop(item.left), ...(value ? { value } : {}) });
      }
    }
  });
  return { calls, requests, renders };
}

export function analyzeScript(source, scriptUrl, pageUrl) {
  if (typeof source !== 'string' || source.length > LIMIT) return { behaviors: [], truncated: true };
  let program;
  try { program = parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true }); }
  catch { return { behaviors: [], truncated: true }; }
  const { selectors, created } = selectorsFrom(program);
  const functions = new Map();
  walk(program, node => {
    if (node.type === 'FunctionDeclaration' && node.id) functions.set(node.id.name, node);
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' &&
      ['FunctionExpression', 'ArrowFunctionExpression'].includes(node.init?.type)) {
      functions.set(node.id.name, node.init);
    }
  });
  const behaviors = [];
  let truncated = false;
  const addBehavior = (event, selector, handler) => {
    if (!handler) return;
    if (behaviors.length >= 60) { truncated = true; return; }
    const pending = [handler];
    const seen = new Set();
    const requests = [], renders = [];
    while (pending.length && seen.size < 30) {
      const current = pending.shift();
      const key = typeof current === 'string' ? current : current.start;
      if (seen.has(key)) continue;
      seen.add(key);
      const body = typeof current === 'string' ? functions.get(current) : current;
      if (!body) continue;
      const found = effects(body.body || body, pageUrl, selectors, created, functions);
      requests.push(...found.requests);
      renders.push(...found.renders);
      pending.push(...found.calls);
    }
    if (pending.length) truncated = true;
    const unique = items => [...new Map(items.map(item => [JSON.stringify(item), item])).values()];
    const allApi = unique(requests);
    const api = allApi.slice(0, 12);
    const priority = item => item.operation === 'innerHTML' || item.operation === 'outerHTML' ? 0 :
      item.selector?.startsWith('#') && ['replaceChildren', 'append', 'prepend', 'insertAdjacentHTML'].includes(item.operation) ? 1 :
      item.selector?.startsWith('#') ? 2 : 3;
    const allUpdates = unique(renders).sort((left, right) => priority(left) - priority(right));
    const updates = allUpdates.slice(0, 8);
    if (allApi.length > api.length || allUpdates.length > updates.length) truncated = true;
    if (api.length || updates.length) behaviors.push({
      trigger: { event, selector }, api, updates, evidence: 'static-js', script: scriptUrl
    });
  };
  const collect = (node, aliases = new Map()) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { for (const item of node) collect(item, aliases); return; }
    if (node.type === 'CallExpression') {
      const called = name(node.callee);
      if (called?.endsWith('.forEach') && node.arguments[0]?.type === 'ArrowFunctionExpression') {
        const selector = selectorOf(node.callee.object, selectors, aliases);
        const param = node.arguments[0].params[0];
        const nested = new Map(aliases);
        if (selector && param?.type === 'Identifier') nested.set(param.name, selector);
        collect(node.arguments[0].body, nested);
        return;
      }
      if (prop(node.callee) === 'addEventListener') {
        const event = text(node.arguments[0]);
        const selector = selectorOf(node.callee.object, selectors, aliases);
        const handler = node.arguments[1]?.type === 'Identifier' ? node.arguments[1].name : node.arguments[1];
        if (event) addBehavior(event, selector, handler);
      }
    }
    for (const [key, value] of Object.entries(node)) {
      if (key !== 'loc' && value && typeof value === 'object') collect(value, aliases);
    }
  };
  collect(program);
  for (const item of program.body) {
    if (item.type === 'ExpressionStatement' && item.expression.type === 'CallExpression' &&
      item.expression.callee.type === 'Identifier' && functions.has(item.expression.callee.name)) {
      addBehavior('page-load', null, item.expression.callee.name);
    }
  }
  return { behaviors, truncated };
}
