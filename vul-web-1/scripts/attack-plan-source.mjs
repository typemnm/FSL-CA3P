import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { readAttackCatalogSync } from '../../casper-db/client.mjs';

/** Resolve one versioned definition; an explicit JSON path remains a legacy input. */
export function loadAttackInfo({ catalogPath, vulnType, application, endpoint, databasePath } = {}) {
  let patterns;
  let catalogSha256;
  if (catalogPath !== undefined) {
    const path = resolve(catalogPath);
    const bytes = readFileSync(path);
    if (bytes.length > 1_000_000) throw new Error('Attack catalog exceeds 1 MB.');
    const catalog = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/u, ''));
    const definitions = Array.isArray(catalog.responses) ? catalog.responses
      : catalog.response ? [catalog.response] : [];
    catalogSha256 = createHash('sha256').update(bytes).digest('hex');
    patterns = definitions.map(definition => ({ definition }));
  } else {
    const catalog = readAttackCatalogSync({ databasePath });
    patterns = catalog.patterns;
    catalogSha256 = catalog.provenance.sha256;
  }
  const matching = patterns.filter(item => item.definition?.vulnType === vulnType
    && (application === undefined || item.definition.target?.application === application)
    && (endpoint === undefined || item.definition.target?.endpoint === endpoint));
  if (matching.length > 1) throw new Error('Ambiguous attack definition; specify application and endpoint.');
  if (!matching.length) return null;
  const pattern = matching[0];
  return { definition: pattern.definition, provenance: {
    catalog: catalogPath === undefined ? 'casper-db.attack_catalog' : 'explicit-json-catalog',
    catalogSha256,
    patternId: pattern.pattern_id ?? null,
    patternRevision: pattern.revision ?? null,
    definitionSha256: pattern.content_sha256 ?? null,
  } };
}
