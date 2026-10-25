import { createHash } from 'node:crypto';
import { parse } from 'acorn';

export const MODULE_ID = 'web-parser';
export const RULESET_VERSION = 'web-indicators-1';
export const LIMITS = Object.freeze({ assets: 200, relations: 2000, libraries: 300,
  sourceBytes: 262144, totalSourceBytes: 8388608, domReferences: 200, astNodes: 30000 });
// A small, explicit indicator catalogue, not a CVE database or a complete detector.
const RULES = [
  ['jquery', 'jquery', /\bjQuery(?: JavaScript Library)?\s+v?(\d+\.\d+(?:\.\d+)?(?:-[\w.-]+)?)/i],
  ['lodash', 'lodash', /\blodash\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i],
  ['bootstrap', 'bootstrap', /\bBootstrap\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i],
  ['vue', 'vue', /\bVue(?:\.js)?\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i],
  ['react', 'react', /\bReact\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/],
  ['react-dom', 'react-dom', /\bReactDOM\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/],
  ['angular', 'angular', /\bAngularJS\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i],
  ['axios', 'axios', /\baxios\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i],
  ['moment', 'moment', /\bmoment(?:\.js)?\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)/i]
];
const VERSION = '(\\d+\\.\\d+(?:\\.\\d+)?(?:-[a-zA-Z][\\w.-]*)?)';
const digest = text => createHash('sha256').update(text).digest('hex');

/** Browser-side DOM inventory; no clicks, writes, global getters or library code evaluation. */
export function readResourceReferences() {
  const nodes = [...document.querySelectorAll('script[src], link[rel~="stylesheet"][href], link[rel~="modulepreload"][href]')];
  return {
    items: nodes.slice(0, 200).map(node => ({
      url: node.tagName === 'SCRIPT' ? node.src : node.href,
      kind: node.tagName === 'SCRIPT' || node.relList.contains('modulepreload') ? 'script' : 'stylesheet',
      relation: node.tagName === 'SCRIPT' ? 'script-src' : node.relList.contains('modulepreload') ? 'modulepreload' : 'stylesheet-link'
    })),
    truncated: nodes.length > 200
  };
}

export function createWebInventory(origin, displayUrl) {
  const assets = new Map(), libraries = new Map(), modules = new Map(), technologies = new Map();
  const relations = new Map(), reasons = new Set(), analysed = new Set();
  let inspectedBytes = 0;
  const addReason = reason => reasons.add(reason);
  const relation = (from, to, kind, evidence) => {
    if (!from || !to) return;
    const key = JSON.stringify([from, to, kind, evidence]);
    if (relations.has(key)) return;
    if (relations.size >= LIMITS.relations) { addReason('relation-limit'); return; }
    relations.set(key, { from, to, kind, evidence });
  };
  const asset = (raw, kind, inline = false) => {
    let url;
    try { url = new URL(raw); } catch { addReason('unsupported-resource-url'); return null; }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      addReason('unsupported-resource-url'); return null;
    }
    if (!inline) url.hash = '';
    const key = `${inline ? 'inline:' : ''}${url.href}`;
    if (!assets.has(key)) {
      if (assets.size >= LIMITS.assets) { addReason('asset-limit'); return null; }
      const external = url.origin !== origin;
      if (external) addReason('external-content-not-fetched');
      assets.set(key, { id: `asset-${assets.size + 1}`, kind, url: displayUrl(url.href),
        state: inline ? 'inline' : external ? 'blocked-origin' : 'referenced',
        _raw: url.href, _inline: inline, _states: new Set(), _hashes: new Set() });
    }
    return assets.get(key);
  };
  const evidence = (item, name, version, kind) => {
    const key = JSON.stringify([item.id, name]);
    if (!libraries.has(key)) {
      if (libraries.size >= LIMITS.libraries) { addReason('library-limit'); return; }
      libraries.set(key, { id: `library-${libraries.size + 1}`, name, ecosystem: 'npm',
        assetId: item.id, identification: 'indicator-only', _evidence: new Map() });
    }
    const entry = libraries.get(key);
    if (entry._evidence.size >= 12) { addReason('evidence-limit'); return; }
    entry._evidence.set(JSON.stringify([kind, version]), { kind, version: version || null });
    relation(item.id, entry.id, 'library-indicator', 'heuristic');
  };
  const filenameIndicators = item => {
    if (item._inline) return;
    let pathname;
    try { pathname = decodeURIComponent(new URL(item._raw).pathname); } catch { return; }
    for (const [name, stem] of RULES) {
      // Package directory or a complete conventional filename, never an arbitrary substring.
      const directory = new RegExp('(?:^|/)' + stem + '(?:@' + VERSION + ')?/','i').exec(pathname);
      const filename = new RegExp('(?:^|/)' + stem + '(?:[-.]' + VERSION + ')?(?:\\.min|\\.slim|\\.bundle|\\.production|\\.development|\\.global|\\.esm-browser)*\\.(?:js|mjs|css)$','i').exec(pathname);
      if (directory || filename) evidence(item, name, directory?.[1] || filename?.[1] || null, 'url-name-hint');
    }
  };
  const reference = (from, raw, kind, relationKind, source) => {
    const item = asset(raw, kind);
    if (item) { filenameIndicators(item); relation(from, item.id, relationKind, source); }
    return item;
  };
  const importReference = (item, specifier, kind) => {
    if (typeof specifier !== 'string' || specifier.length > 2048) return;
    let resolved;
    try { resolved = new URL(specifier, item._raw).href; }
    catch { addReason('unsupported-resource-url'); return; }
    if (/^(?:\.{1,2}\/|\/|https?:\/\/)/i.test(specifier)) {
      reference(item.id, resolved,
        kind === 'css-import' ? 'stylesheet' : 'script', kind, 'static-source');
    } else if (kind === 'css-import') {
      // CSS allows relative paths without ./; non-HTTP schemes are rejected by asset().
      reference(item.id, resolved, 'stylesheet', kind, 'static-source');
    } else {
      addReason('bare-or-unsupported-import-unresolved');
      if (!/^(@[\w.-]+\/)?[\w.-]+(?:\/[\w.-]+)*$/.test(specifier)) return;
      const key = item.id + ':' + specifier;
      if (!modules.has(key)) {
        if (modules.size >= LIMITS.assets) { addReason('module-reference-limit'); return; }
        modules.set(key, { id: `module-${modules.size + 1}`, specifier,
          resolution: 'unresolved', version: null });
      }
      relation(item.id, modules.get(key).id, kind, 'static-source');
    }
  };
  const source = (item, text, declaredKind = item?.kind) => {
    if (!item || typeof text !== 'string') return;
    const key = item.id + ':' + digest(text);
    if (analysed.has(key)) return;
    if (analysed.size >= LIMITS.assets * 2) { addReason('source-variant-limit'); return; }
    const bytes = Buffer.byteLength(text);
    if (bytes > LIMITS.sourceBytes || inspectedBytes + bytes > LIMITS.totalSourceBytes) {
      addReason('source-byte-limit'); return;
    }
    analysed.add(key); inspectedBytes += bytes; item._hashes.add(digest(text));
    // Comments only: no library recognition from arbitrary HTML prose or JS string literals.
    let comments = [], imports = [];
    if (declaredKind === 'script') {
      let program;
      try {
        program = parse(text, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true,
          onComment: (_block, content) => { if (comments.length < 100) comments.push(content.slice(0, 4096)); } });
      } catch {
        // Do not label an unparsed response as a verified JS library.
        addReason('script-syntax-not-interpreted'); return;
      }
      const pending = [program]; let visited = 0;
      while (pending.length && visited++ < LIMITS.astNodes) {
        const node = pending.pop();
        if (!node || typeof node !== 'object') continue;
        if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration', 'ImportExpression'].includes(node.type)) {
          if (node.source?.type === 'Literal' && typeof node.source.value === 'string') imports.push(node.source.value);
          else if (node.type === 'ImportExpression') addReason('dynamic-import-unresolved');
        }
        for (const value of Object.values(node)) {
          if (Array.isArray(value)) {
            for (const entry of value) {
              if (pending.length >= LIMITS.astNodes) { addReason('ast-node-limit'); break; }
              pending.push(entry);
            }
          }
          else if (value && typeof value === 'object') pending.push(value);
        }
      }
      if (pending.length) addReason('ast-node-limit');
      imports.slice(0, 100).forEach(value => importReference(item, value, 'js-import'));
      if (imports.length > 100) addReason('import-limit');
    } else if (declaredKind === 'stylesheet') {
      // Tokenize comments/strings first, so @import inside either is not a dependency.
      const tokens = text.matchAll(/\/\*([\s\S]*?)\*\/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|@import\s+(?:url\(\s*)?(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;)'"\\]+))/gi);
      let count = 0;
      for (const match of tokens) {
        if (++count > 10000) { addReason('css-token-limit'); break; }
        if (match[1] !== undefined && comments.length < 100) comments.push(match[1].slice(0, 4096));
        if (match[0].startsWith('@') && imports.length < 100) imports.push(match[2] || match[3] || match[4]);
      }
      imports.forEach(value => importReference(item, value, 'css-import'));
    }
    for (const comment of comments) {
      for (const [name, , pattern] of RULES) {
        const match = pattern.exec(comment);
        if (match) evidence(item, name, match[1], 'source-comment');
      }
    }
  };
  return {
    mark: addReason,
    references(pageId, data) {
      if (data.truncated) addReason('dom-reference-limit');
      for (const ref of data.items.slice(0, LIMITS.domReferences)) reference(pageId, ref.url, ref.kind, ref.relation, 'dom');
    },
    response(pageId, raw, kind, status, body) {
      if (!['script', 'stylesheet'].includes(kind)) return;
      const item = reference(pageId, raw, kind, 'resource-response', 'network');
      if (!item || new URL(item._raw).origin !== origin || item._inline) return;
      item._states.add(status);
      item.state = [...item._states].some(code => code >= 200 && code < 300) ? 'response-observed' : 'http-error';
      if (status >= 200 && status < 300) {
        if (body !== undefined) source(item, body, kind);
        else addReason('resource-body-not-inspected');
      }
    },
    inline(pageId, pageUrl, index, body, type) {
      if (type && !['module', 'text/javascript', 'application/javascript'].includes(type)) return;
      const url = new URL(pageUrl); url.hash = 'inline-' + index;
      const item = asset(url.href, 'script', true);
      if (item) { relation(pageId, item.id, 'inline-script', 'dom'); source(item, body); }
    },
    headers(pageId, headers) {
      const rules = [ ['x-powered-by', /^Express$/i, 'Express'],
        ['x-powered-by', /^PHP(?:\/(\d+(?:\.\d+){1,3}))?$/i, 'PHP'],
        ['x-powered-by', /^Next\.js$/i, 'Next.js'],
        ['server', /^nginx(?:\/(\d+(?:\.\d+){1,3}))?$/i, 'nginx'],
        ['server', /^Apache(?:\/(\d+(?:\.\d+){1,3}))?(?:\s|$)/i, 'Apache'] ];
      for (const [header, pattern, name] of rules) {
        const value = String(headers[header] || '').slice(0, 100);
        const match = pattern.exec(value);
        if (!match) continue;
        const key = `${name}:${match[1] || ''}`;
        if (!technologies.has(key)) technologies.set(key, { name, version: match[1] || null,
          evidence: 'response-header-claim', header, pageIds: new Set() });
        technologies.get(key).pageIds.add(pageId);
      }
    },
    snapshot() {
      return { status: 'observed', mode: 'url-observation', scope: 'web-exposed-resources',
        complete: false, serverDependencies: 'unknown', vulnerabilityMatching: 'not-performed',
        ruleset: RULESET_VERSION,
        coverage: { reasons: [...reasons].sort(), inspectedBytes },
        assets: [...assets.values()].map(({ _raw, _inline, _states, _hashes, ...rest }) => ({ ...rest,
          ...(_states.size ? { httpStatuses: [..._states].sort((a,b) => a-b) } : {}),
          ...(_hashes.size ? { inspectedContentSha256: [..._hashes].sort() } : {}) })),
        libraries: [...libraries.values()].map(({ _evidence, ...rest }) => {
          const evidence = [..._evidence.values()];
          const versions = [...new Set(evidence.map(item => item.version).filter(Boolean))].sort();
          return { ...rest, version: versions.length === 1 ? versions[0] : null,
            versionStatus: versions.length > 1 ? 'conflicting-indicators' : versions.length ? 'reported-not-verified' : 'unknown',
            ...(versions.length > 1 ? { versionCandidates: versions } : {}), evidence };
        }),
        moduleReferences: [...modules.values()],
        relations: [...relations.values()],
        technologies: [...technologies.values()].map(item => ({ ...item, pageIds: [...item.pageIds] })),
        limitations: ['not-a-server-package-inventory', 'no-execution-or-vulnerability-proof',
          'limited-indicator-catalogue', 'no-import-map-or-bundled-transitive-resolution'], sources: [] };
    }
  };
}
