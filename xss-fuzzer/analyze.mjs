import { parse } from 'acorn';

export function analyze(js, file) {
  let ast;
  try { ast = parse(js, { ecmaVersion: 'latest', sourceType: 'module', locations: true }); }
  catch (error) { return { candidates: [], errors: [{ file, message: error.message }] }; }
  const candidates = [];
  const prop = node => node?.type === 'MemberExpression'
    ? (node.computed ? node.property.value : node.property.name) : null;
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    let sink;
    if (node.type === 'AssignmentExpression' && ['innerHTML', 'outerHTML', 'srcdoc'].includes(prop(node.left))) sink = prop(node.left);
    if (node.type === 'CallExpression') {
      const member = prop(node.callee);
      if (['insertAdjacentHTML', 'write', 'writeln'].includes(member)) sink = member;
      if (node.callee.name === 'eval' || node.callee.name === 'Function') sink = node.callee.name;
      if (['setTimeout', 'setInterval'].includes(node.callee.name) && node.arguments[0]?.type === 'Literal' && typeof node.arguments[0].value === 'string') sink = node.callee.name;
      if (member === 'setAttribute' && /^on/i.test(node.arguments[0]?.value || '')) sink = 'event-attribute';
    }
    if (node.type === 'NewExpression' && node.callee.name === 'Function') sink = 'Function';
    if (sink) candidates.push({ file, line: node.loc.start.line, column: node.loc.start.column + 1,
      sink, status: 'candidate', evidence: js.slice(node.start, node.end),
      note: 'Dangerous sink syntax only; this does not prove attacker control or execution.' });
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  }
  visit(ast);
  return { candidates, errors: [] };
}
