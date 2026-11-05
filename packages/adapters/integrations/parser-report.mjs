/** Read-only normalization of current TargetInfo and legacy parser reports for DB lookup. */
const methods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const list = value => Array.isArray(value) ? value : [];
const text = value => typeof value === 'string' && value.trim() ? value.trim() : null;

export function knowledgeParserReport(report, { origin } = {}) {
  if (report && Array.isArray(report.pages)) return report;
  if (report?.schemaVersion !== 'web-parser-1' || !report.target) {
    throw new TypeError('Expected a legacy parser report or web-parser-1 TargetInfo.');
  }
  const source = new URL(report.target.origin ?? report.target.finalUrl ?? report.target.requestedUrl);
  if (!['http:', 'https:'].includes(source.protocol) || source.username || source.password
      || origin && new URL(origin).origin !== source.origin) {
    throw new TypeError('Parser TargetInfo origin does not match the requested target.');
  }
  const api = [];
  const add = (raw, rawMethod, names = []) => {
    if (!text(raw)) return;
    let url;
    try { url = new URL(raw, report.target.finalUrl ?? source.origin); } catch { return; }
    const method = text(rawMethod)?.toUpperCase();
    if (url.origin !== source.origin || !methods.has(method) || url.username || url.password) return;
    api.push({ url: url.href, method,
      bodyKeys: method === 'POST' ? names.filter(name => text(name)) : [] });
    if (method === 'GET') {
      // A declared GET form supplies query field names, never invented values.
      for (const name of names.filter(name => text(name))) {
        if (!url.searchParams.has(name)) url.searchParams.append(name, '');
      }
      api[api.length - 1].url = url.href;
    }
  };
  for (const item of list(report.resources)) add(item.url, item.method);
  const forms = list(report.structure?.forms);
  for (const form of forms) add(form.action, form.method, list(form.fields).map(field => field.name));
  for (const action of list(report.structure?.formActions)) {
    const form = forms.find(item => item.selector === action.form);
    add(action.formaction, action.formmethod ?? form?.method, list(form?.fields).map(field => field.name));
  }
  const technologies = [];
  const seen = new Set();
  for (const item of [...list(report.technologies), ...list(report.libraries)]) {
    const name = text(item.name), version = text(item.version);
    if (!name) continue;
    const identity = JSON.stringify([name, version]);
    if (seen.has(identity)) continue;
    seen.add(identity);
    technologies.push({ name, version, header: `fingerprint:${technologies.length}`,
      pageIds: ['target-info'], evidence: 'web-parser-fingerprint-indicator' });
  }
  return {
    schemaVersion: 'structure-1.0', startUrl: report.target.requestedUrl ?? source.origin,
    site: { origin: source.origin }, pages: [{ id: 'target-info', behaviors: [{ api }] }],
    ...(report.softwareInventory ? { softwareInventory: report.softwareInventory } : {}),
    ...(report.inputLocations ? { inputLocations: report.inputLocations } : {}),
    dependencies: {
      libraries: [], sources: [], technologies,
      complete: report.truncated !== true && !list(report.errors).length,
      coverage: { reasons: [
        ...(report.truncated ? ['target-info-truncated'] : []),
        ...list(report.errors).map(() => 'target-info-collection-error'),
        // Wappalyzer names do not establish a package ecosystem or installed version.
        ...(technologies.length ? ['fingerprints-require-product-review'] : []),
      ] }, serverDependencies: 'unknown',
    },
  };
}
