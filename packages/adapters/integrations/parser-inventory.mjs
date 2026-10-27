import { createHash } from 'node:crypto';

const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const text = value => typeof value === 'string' && value.trim() ? value.trim() : null;

/** Translate web-parser evidence without promoting indicators or declarations to installed software. */
export function inventoryFromParser(report, { targetId, observedAt = new Date().toISOString(), limit = 20 } = {}) {
  if (!report || !Array.isArray(report.pages) || !text(targetId)) throw new TypeError('A parser report and target ID are required.');
  if (report.softwareInventory) {
    if (report.softwareInventory.target_id !== targetId) throw new TypeError('Software inventory target differs from this run.');
    const components = report.softwareInventory.components;
    if (!Array.isArray(components) || !components.length) throw new TypeError('Software inventory requires components.');
    return { inventory: { ...report.softwareInventory, components: components.slice(0, 20) },
      coverage: { source: 'explicit_inventory', truncated: components.length > 20, omitted: Math.max(0, components.length - 20) } };
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new TypeError('Inventory limit must be 1..20.');
  const dependencies = report.dependencies;
  const components = new Map();
  const skipped = [];
  const add = component => {
    if (!component.ecosystem || !component.package) { skipped.push('unresolved-package-identity'); return; }
    const key = JSON.stringify([component.ecosystem, component.package, component.version]);
    const previous = components.get(key);
    if (previous) {
      previous.source_refs = [...new Set([...previous.source_refs, ...component.source_refs])].slice(0, 30);
      previous.evidence.push(...component.evidence);
      previous.evidence = previous.evidence.slice(0, 30);
    } else components.set(key, component);
  };
  for (const library of dependencies?.libraries ?? []) {
    const evidence = (library.evidence ?? []).slice(0, 12);
    add({ ecosystem: text(library.ecosystem), package: text(library.name),
      version: library.versionStatus === 'conflicting-indicators' ? null : text(library.version),
      identification: 'indicator', version_status: text(library.versionStatus) ?? 'unknown',
      source_refs: [`web-parser:library:${library.id}:asset:${library.assetId}`],
      evidence: [{ kind: 'web-library-indicator', asset_id: library.assetId,
        identification: library.identification, version_candidates: library.versionCandidates ?? [], evidence }],
    });
  }
  for (const source of dependencies?.sources ?? []) {
    if (!['npm', 'maven'].includes(source.ecosystem) || !/^[a-f0-9]{64}$/.test(source.sha256 ?? '')) {
      skipped.push('unsupported-or-unbound-local-inventory'); continue;
    }
    for (const pkg of source.packages ?? []) {
      if (pkg.id === source.root) { skipped.push('local-root-project-not-a-public-dependency'); continue; }
      add({ ecosystem: source.ecosystem, package: text(pkg.name),
        version: ['unresolved', 'unresolved-link'].includes(pkg.versionEvidence) ? null : text(pkg.version),
        identification: 'declared', version_status: text(pkg.versionEvidence) ?? 'unknown',
        source_refs: [`web-parser:source:${source.sha256}:package:${pkg.id}`],
        evidence: [{ kind: 'local-dependency-declaration', source_sha256: source.sha256,
          locator: pkg.locator, version_evidence: pkg.versionEvidence, limitations: source.limitations ?? [] }],
      });
    }
  }
  for (const technology of dependencies?.technologies ?? []) {
    add({ ecosystem: 'cpe', package: text(technology.name), version: text(technology.version),
      identification: 'indicator', version_status: 'response-header-claim',
      source_refs: [`web-parser:header:${technology.header}:pages:${(technology.pageIds ?? []).join(',')}`],
      evidence: [{ kind: technology.evidence, header: technology.header, page_ids: technology.pageIds ?? [] }],
    });
  }
  const all = [...components.values()];
  const selected = all.slice(0, limit);
  return {
    inventory: selected.length ? { schema_version: 'casper-software-inventory-1', target_id: targetId,
      observed_at: observedAt, components: selected } : null,
    coverage: { source: 'web-parser.dependencies', observed_components: all.length,
      truncated: all.length > limit, omitted: Math.max(0, all.length - limit), skipped,
      parser_complete: dependencies?.complete === true, parser_reasons: dependencies?.coverage?.reasons ?? [],
      server_dependencies: dependencies?.serverDependencies ?? 'unknown',
      evidence_digest: hash({ libraries: dependencies?.libraries ?? [], sources: dependencies?.sources ?? [] }) },
  };
}

/** Stable comparison of the data actually returned; local ports and collection times are not inputs. */
export function knowledgeContextDigest(context, inventory, coverage, collection) {
  return hash({
    components: inventory?.components.map(({ ecosystem, package: name, version, cpe, identification, version_status }) =>
      ({ ecosystem, package: name, version, cpe: cpe ?? null, identification: identification ?? 'observed', version_status: version_status ?? null })) ?? [],
    candidates: (context?.external?.candidates ?? []).map(item => ({
      record_id: item.record.record_id, source_item_sha256: item.record.source_item_sha256,
      decision: item.assessment.decision,
    })).sort((a, b) => a.record_id.localeCompare(b.record_id)),
    external_status: context?.external?.status ?? 'not_requested',
    truncated: context?.external?.truncated ?? false,
    input_truncated: coverage?.truncated ?? false, omitted: coverage?.omitted ?? 0,
    collection_status: collection?.status ?? 'not_requested',
    collection_complete: collection?.collection_complete ?? false,
  });
}
