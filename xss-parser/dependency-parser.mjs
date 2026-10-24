/**
 * Read-only, bounded dependency inventory for the two CA3P lab ecosystems.
 * This is NOT an exhaustive SCA engine: the local advisory catalog contains
 * only the six CVEs selected for the fictional university fixtures.
 */
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

export const CURATED_ADVISORIES = Object.freeze([
  { id: 'CVE-2020-8203', ecosystem: 'npm', name: 'lodash',
    introduced: '3.7.0', fixed: '4.17.19',
    reference: 'https://github.com/advisories/GHSA-p6mc-m468-83gw' },
  { id: 'CVE-2022-46175', ecosystem: 'npm', name: 'json5',
    introduced: '2.0.0', fixed: '2.2.2',
    reference: 'https://github.com/json5/json5/security/advisories/GHSA-9c47-m6qq-7p4h' },
  { id: 'CVE-2022-21670', ecosystem: 'npm', name: 'markdown-it',
    maxInclusive: '12.3.1',
    reference: 'https://github.com/markdown-it/markdown-it/security/advisories/GHSA-6vfc-qv3f-vr6c' },
  { id: 'CVE-2022-42889', ecosystem: 'maven', name: 'org.apache.commons:commons-text',
    fixed: '1.10.0',
    reference: 'https://commons.apache.org/proper/commons-text/security.html' },
  { id: 'CVE-2022-1471', ecosystem: 'maven', name: 'org.yaml:snakeyaml',
    maxInclusive: '1.33',
    reference: 'https://github.com/advisories/GHSA-mjmj-j48q-9wg2' },
  { id: 'CVE-2023-42503', ecosystem: 'maven', name: 'org.apache.commons:commons-compress',
    introduced: '1.22', fixed: '1.24.0',
    reference: 'https://commons.apache.org/proper/commons-compress/security.html' },
]);

function versionParts(version) {
  if (typeof version !== 'string' || !/^\d+(?:\.\d+){1,3}$/.test(version)) return null;
  const parts = version.split('.').map(Number);
  return parts.every(part => Number.isSafeInteger(part)) ? parts : null;
}

function compareVersions(left, right) {
  const a = versionParts(left);
  const b = versionParts(right);
  if (!a || !b) return null;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

function affected(version, advisory) {
  if (!versionParts(version)) return false;
  if (advisory.introduced && compareVersions(version, advisory.introduced) < 0) return false;
  if (advisory.fixed && compareVersions(version, advisory.fixed) >= 0) return false;
  if (advisory.maxInclusive && compareVersions(version, advisory.maxInclusive) > 0) return false;
  return true;
}

function readNpmLock(content) {
  const data = JSON.parse(content);
  if (!data || typeof data !== 'object' || Array.isArray(data) || !data.packages
    || typeof data.packages !== 'object' || !data.packages['']
    || !data.packages[''].dependencies || typeof data.packages[''].dependencies !== 'object') {
    throw new Error('Expected npm package-lock.json v2/v3 with root direct dependencies.');
  }
  return Object.keys(data.packages[''].dependencies).sort().map(name => {
    const pkg = data.packages['node_modules/' + name];
    const version = typeof pkg?.version === 'string' && versionParts(pkg.version)
      ? pkg.version : null;
    return { ecosystem: 'npm', name, version, direct: true };
  });
}

function xmlTag(xml, tag) {
  const match = new RegExp('<' + tag + '\\s*>([^<]*)</' + tag + '\\s*>').exec(xml);
  return match?.[1]?.trim() || null;
}

function readMavenPom(content) {
  if (/<!(?:DOCTYPE|ENTITY)\b/i.test(content)) {
    throw new Error('Maven manifests with DTD or entities are not supported.');
  }
  const xml = content.replace(/<!--[\s\S]*?-->/g, '');
  const properties = new Map();
  const propertyBlock = /<properties\s*>([\s\S]*?)<\/properties\s*>/.exec(xml)?.[1] || '';
  for (const match of propertyBlock.matchAll(/<([A-Za-z][\w.-]*)\s*>([^<]*)<\/\1\s*>/g)) {
    properties.set(match[1], match[2].trim());
  }
  const withoutManagement = xml.replace(/<dependencyManagement\b[^>]*>[\s\S]*?<\/dependencyManagement\s*>/g, '');
  const section = /<dependencies\b[^>]*>([\s\S]*?)<\/dependencies\s*>/.exec(withoutManagement)?.[1];
  if (!section) throw new Error('Maven pom.xml has no direct dependency list.');
  const dependencies = [];
  for (const match of section.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency\s*>/g)) {
    const block = match[1];
    const group = xmlTag(block, 'groupId');
    const artifact = xmlTag(block, 'artifactId');
    if (!group || !artifact || !/^[\w.-]+$/.test(group) || !/^[\w.-]+$/.test(artifact)) {
      throw new Error('Invalid Maven dependency coordinates.');
    }
    const scope = xmlTag(block, 'scope');
    if (scope === 'test' || scope === 'provided') continue;
    let version = xmlTag(block, 'version');
    const prop = /^\$\{([\w.-]+)\}$/.exec(version || '');
    if (prop) version = properties.get(prop[1]) || null;
    if (!versionParts(version)) version = null;
    dependencies.push({ ecosystem: 'maven', name: group + ':' + artifact,
      version, direct: true });
  }
  return dependencies.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * A version match is only a catalog match, never proof of exploitability.
 * Server-side Maven versions managed by a parent/BOM remain unresolved.
 */
export function parseDependencyManifest(content, { ecosystem, sourceFile } = {}) {
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > MAX_MANIFEST_BYTES) {
    throw new TypeError('Manifest must be UTF-8 text no larger than 2 MiB.');
  }
  if (ecosystem !== 'npm' && ecosystem !== 'maven') {
    throw new TypeError('ecosystem must be npm or maven.');
  }
  if (typeof sourceFile !== 'string' || !sourceFile || sourceFile.length > 250) {
    throw new TypeError('sourceFile must identify the manifest.');
  }
  const dependencies = ecosystem === 'npm' ? readNpmLock(content) : readMavenPom(content);
  const findings = [];
  for (const dep of dependencies) {
    if (!dep.version) continue;
    for (const advisory of CURATED_ADVISORIES) {
      if (dep.ecosystem !== advisory.ecosystem || dep.name !== advisory.name
        || !affected(dep.version, advisory)) continue;
      findings.push({
        id: advisory.id,
        dependency: { ...dep },
        status: 'affected_version',
        validation: 'not_executed',
        evidence: { sourceFile, kind: 'declared-direct-dependency-version' },
        reference: advisory.reference,
        ...(advisory.fixed ? { fixedVersion: advisory.fixed } : {}),
      });
    }
  }
  return {
    schemaVersion: '1.0',
    scope: 'direct-dependency-version-matches',
    ecosystem,
    sourceFile,
    catalog: 'ca3p-six-curated-fixture-advisories',
    dependencies,
    findings,
    unresolved: dependencies.filter(dep => !dep.version).map(dep => dep.name),
    summary: {
      directDependencies: dependencies.length,
      resolvedDirectDependencies: dependencies.filter(dep => dep.version !== null).length,
      matchedAdvisories: findings.length,
      isCompleteSCA: false,
      runtimeExploitabilityVerified: false,
    },
  };
}
