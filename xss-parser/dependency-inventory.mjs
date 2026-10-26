import { open } from 'node:fs/promises';
import { basename, posix } from 'node:path';
import { createHash } from 'node:crypto';

const LIMIT = 2 * 1024 * 1024;
const object = value =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const string = value =>
  typeof value === 'string' && value.trim() ? value.trim() : null;

function bounded(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > LIMIT) {
    throw new Error('Dependency input exceeds 2 MiB.');
  }
}

export function parseNpmLock(text) {
  bounded(text);

  const lock = JSON.parse(text);
  const entries = lock.packages;

  if (![2, 3].includes(lock.lockfileVersion) ||
      !object(entries) || !object(entries[''])) {
    throw new Error(
      'Expected package-lock.json v2/v3 with packages[""].'
    );
  }

  const keys = Object.keys(entries).sort();
  const ids = new Map(keys.map((key, i) => [key, 'package-' + i]));

  if (keys.length > 20000) {
    throw new Error('Too many dependency entries.');
  }

  if (keys.some(key => key && (
    posix.isAbsolute(key) ||
    key.includes('\\') ||
    key.split('/').some(part =>
      !part || part === '.' || part === '..'
    )
  ))) {
    throw new Error('Invalid lockfile package location.');
  }

  const packages = keys.map(key => {
    const entry = entries[key];

    if (!object(entry)) {
      throw new Error('Invalid package descriptor.');
    }

    return {
      id: ids.get(key),
      name: string(entry.name) ?? (
        key
          ? key.split('node_modules/').at(-1)
          : string(lock.name)
      ),
      version: string(entry.version),
      locator: key || 'packages[""]',
      versionEvidence: entry.link
        ? 'unresolved-link'
        : string(entry.version) ? 'lockfile' : 'unknown',
      ...(entry.dev ? { dev: true } : {}),
      ...(entry.optional ? { optional: true } : {})
    };
  });

  const locate = (base, name) => {
    for (
      let folder = base;
      ;
      folder = posix.dirname(folder) === '.'
        ? ''
        : posix.dirname(folder)
    ) {
      if (posix.basename(folder) !== 'node_modules') {
        const key =
          (folder ? folder + '/' : '') + 'node_modules/' + name;

        if (ids.has(key)) return ids.get(key);
      }

      if (!folder) return null;
    }
  };

  const edges = [];

  for (const key of keys) {
    const entry = entries[key];
    const kinds = [
      'dependencies',
      'optionalDependencies',
      'peerDependencies',
      ...(key === '' ? ['devDependencies'] : [])
    ];

    for (const kind of kinds) {
      if (entry[kind] === undefined) continue;

      if (!object(entry[kind])) {
        throw new Error('Invalid dependency declaration.');
      }

      for (const [name, requested] of Object.entries(entry[kind]).sort()) {
        if (kind === 'dependencies' &&
            Object.hasOwn(entry.optionalDependencies ?? {}, name)) {
          continue;
        }

        if (!/^(@[^/\s]+\/)?[^/\s]+$/.test(name) ||
            ['.', '..'].includes(name) ||
            typeof requested !== 'string') {
          throw new Error('Invalid npm dependency name or specifier.');
        }

        if (edges.length >= 50000) {
          throw new Error('Too many dependency relations.');
        }

        edges.push({
          from: ids.get(key),
          to: locate(key, name),
          name,
          requested,
          kind
        });
      }
    }
  }

  return {
    ecosystem: 'npm',
    coverage: 'lockfile-package-graph',
    root: ids.get(''),
    packages,
    edges,
    unresolved: edges.filter(edge => edge.to === null).length,
    limitations: [
      'runtime-installation-not-verified',
      'workspace-links-not-resolved',
      'peer-range-compatibility-not-checked'
    ]
  };
}

// Bounded POM subset: no DTD, custom entities, CDATA or external I/O.
function xml(text) {
  bounded(text);

  if (/<!(?!\-\-)/.test(text)) {
    throw new Error('POM DTD/entities/CDATA are unsupported.');
  }

  const decode = value => {
    if (/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[\da-fA-F]+);)/.test(value)) {
      throw new Error('Unknown XML entity.');
    }

    return value.replace(/&([^;]+);/g, (_, name) => {
      const known = {
        amp: '&', lt: '<', gt: '>', quot: '"', apos: "'"
      };

      if (Object.hasOwn(known, name)) return known[name];

      const cp = name.startsWith('#x')
        ? parseInt(name.slice(2), 16)
        : Number(name.slice(1));

      if (!(cp > 0 && cp <= 0x10ffff) ||
          (cp >= 0xd800 && cp <= 0xdfff)) {
        throw new Error('Invalid XML code point.');
      }

      return String.fromCodePoint(cp);
    });
  };

  const root = { name: '', children: [], text: '' };
  const stack = [root];
  const tokens = /<!--[\s\S]*?-->|<\?xml[\s\S]*?\?>|<[^>]*>|[^<]+/gy;

  let offset = 0;
  let count = 0;
  let match;

  while ((match = tokens.exec(text)) !== null) {
    if (match.index !== offset) {
      throw new Error('Malformed POM XML.');
    }

    offset = tokens.lastIndex;
    const token = match[0];

    if (token.startsWith('<!--') || token.startsWith('<?xml')) {
      continue;
    }

    if (token.startsWith('</')) {
      const closing = /^<\/([A-Za-z_][\w.:-]*)\s*>$/.exec(token);

      if (!closing || stack.length === 1 ||
          stack.pop().qualified !== closing[1]) {
        throw new Error('Mismatched XML tag.');
      }
    } else if (token.startsWith('<')) {
      const opening =
        /^<([A-Za-z_][\w.:-]*)(?:\s+[A-Za-z_][\w.:-]*\s*=\s*(?:"[^"<>]*"|'[^'<>]*'))*\s*\/?\s*>$/
          .exec(token);

      if (!opening || ++count > 20000 || stack.length > 64) {
        throw new Error('Unsupported or excessive POM XML.');
      }

      const node = {
        qualified: opening[1],
        name: opening[1].split(':').at(-1),
        children: [],
        text: ''
      };

      stack.at(-1).children.push(node);

      if (!/\/\s*>$/.test(token)) stack.push(node);
    } else {
      stack.at(-1).text += decode(token);
    }
  }

  if (offset !== text.length || stack.length !== 1 ||
      root.children.length !== 1 || root.text.trim()) {
    throw new Error('Malformed POM XML.');
  }

  return root.children[0];
}

const child = (node, key) => {
  const matches =
    (node?.children ?? []).filter(item => item.name === key);

  if (matches.length > 1) {
    throw new Error('Duplicate POM field: ' + key);
  }

  return matches[0];
};

const value = (node, key) => string(child(node, key)?.text);

export function parsePom(text) {
  const project = xml(text);

  if (project.name !== 'project') {
    throw new Error('Expected a Maven project.');
  }

  const properties = new Map(
    (child(project, 'properties')?.children ?? [])
      .map(node => [node.name, node.text.trim()])
  );

  const resolve = input => {
    let result = input;

    for (let i = 0; result && i < 16 && /\$\{/.test(result); i++) {
      const next = result.replace(
        /\$\{([^}]+)\}/g,
        (all, key) => properties.get(key) ?? all
      );

      if (next === result) break;
      result = next;
    }

    return result && !/\$\{/.test(result) ? result : null;
  };

  const exact = input =>
    input && !/[\[\](),]/.test(input) &&
    !['LATEST', 'RELEASE'].includes(input)
      ? input
      : null;

  const parent = child(project, 'parent');
  const group = resolve(
    value(project, 'groupId') ?? value(parent, 'groupId')
  );
  const artifact = resolve(value(project, 'artifactId'));

  if (!artifact || !group) {
    throw new Error('Unresolved Maven project coordinates.');
  }

  const projectVersion = resolve(
    value(project, 'version') ?? value(parent, 'version')
  );

  properties.set('project.version', projectVersion ?? '${unresolved}');
  properties.set('project.groupId', group);
  properties.set('project.artifactId', artifact);

  const packages = [{
    id: 'package-0',
    name: group + ':' + artifact,
    version: exact(projectVersion),
    versionEvidence: 'pom-declaration',
    locator: 'project'
  }];

  const edges = [];
  const declarations =
    (child(project, 'dependencies')?.children ?? [])
      .filter(node => node.name === 'dependency');

  for (const [i, dep] of declarations.entries()) {
    const groupId = resolve(value(dep, 'groupId'));
    const artifactId = resolve(value(dep, 'artifactId'));

    if (!groupId || !artifactId) {
      throw new Error('Unresolved dependency coordinates.');
    }

    const requested = value(dep, 'version');
    const version = exact(resolve(requested));
    const id = 'package-' + (i + 1);
    const name = groupId + ':' + artifactId;

    packages.push({
      id,
      name,
      version,
      versionEvidence: version ? 'pom-declaration' : 'unresolved',
      locator: 'project/dependencies/dependency[' + (i + 1) + ']',
      ...(requested ? { requested } : {})
    });

    edges.push({
      from: 'package-0',
      to: id,
      scope: value(dep, 'scope') ?? 'compile',
      optional: value(dep, 'optional') === 'true',
      type: value(dep, 'type') ?? 'jar',
      ...(value(dep, 'classifier')
        ? { classifier: value(dep, 'classifier') }
        : {})
    });
  }

  return {
    ecosystem: 'maven',
    coverage: 'direct-declarations-only',
    root: 'package-0',
    packages,
    edges,
    unresolved: packages.slice(1).filter(pkg => !pkg.version).length,
    limitations: [
      'parent-bom-profiles-and-transitives-not-resolved',
      'runtime-installation-not-verified'
    ]
  };
}

export async function readInventory(inputs) {
  const sources = [];

  for (const { kind, file } of inputs) {
    if (!['npm', 'maven'].includes(kind)) {
      throw new Error('Unknown dependency format.');
    }

    const handle = await open(file, 'r');
    let content;

    try {
      const stat = await handle.stat();

      if (!stat.isFile() || stat.size > LIMIT) {
        throw new Error(
          'Dependency input must be a regular file <= 2 MiB.'
        );
      }

      const buffer = Buffer.alloc(LIMIT + 1);
      let length = 0;

      while (length < buffer.length) {
        const { bytesRead } = await handle.read(
          buffer, length, buffer.length - length, length
        );

        if (!bytesRead) break;
        length += bytesRead;
      }

      if (length > LIMIT) {
        throw new Error('Dependency file grew beyond size limit.');
      }

      content = buffer.subarray(0, length);
    } finally {
      await handle.close();
    }

    sources.push({
      file: basename(file),
      sha256: createHash('sha256').update(content).digest('hex'),
      ...(kind === 'npm'
        ? parseNpmLock(content.toString('utf8'))
        : parsePom(content.toString('utf8')))
    });
  }

  return {
    status: sources.length ? 'parsed' : 'not-provided',
    vulnerabilityMatching: 'not-performed',
    sources
  };
}
