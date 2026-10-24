// Compact projection of the existing parser. No requests or DOM interaction here.
const unique = values => [...new Set(values)];

function catalogue(prefix) {
  const items = [];
  const ids = new Map();

  return {
    items,
    add(value) {
      const key = JSON.stringify(value);

      if (!ids.has(key)) {
        const id = `${prefix}-${items.length + 1}`;
        ids.set(key, id);
        items.push({ id, ...value });
      }

      return ids.get(key);
    }
  };
}

export function toStructure(report, {
  targetUrls,
  pageUrls,
  loadedPages
} = {}) {
  if (report?.schemaVersion !== '3.4' || !Array.isArray(report.pages)) {
    throw new Error('Expected parser schema 3.4.');
  }

  const origin = new URL(report.startUrl).origin;

  const path = value =>
    value?.startsWith(origin + '/')
      ? value.slice(origin.length)
      : value;

  const canonical = value => {
    const url = new URL(value);
    url.hash = '';
    return url.href;
  };

  const targets = [];
  const byRaw = new Map();
  const byPage = new Map();
  let ambiguous = 0;

  const addTarget = (key, display, page = null) => {
    if (!byRaw.has(key)) {
      const item = {
        id: `target-${targets.length + 1}`,
        path: path(display),
        state: page
          ? (page.error ? 'failed' : 'visited')
          : 'not-visited',
        pageId: page?.id ?? null
      };

      targets.push(item);
      byRaw.set(key, item.id);
    }

    return byRaw.get(key);
  };

  for (const page of report.pages) {
    const raw = pageUrls?.get(page.id);

    byPage.set(
      page.id,
      addTarget(
        raw ? canonical(raw) : `page:${page.id}`,
        page.url,
        page
      )
    );
  }

  for (const [raw, pageId] of loadedPages ?? []) {
    if (byPage.has(pageId)) {
      byRaw.set(canonical(raw), byPage.get(pageId));
    }
  }

  const linkTarget = link => {
    const raw = targetUrls?.get(link);

    if (raw) {
      return addTarget(canonical(raw), link.url);
    }

    if (link.targetPageId && byPage.has(link.targetPageId)) {
      return byPage.get(link.targetPageId);
    }

    // A redacted URL is not an identity.
    // Never merge unknown numeric/query targets using their display URL.
    const masked =
      /\{(?:number|uuid|token|value|fragment)\}|%7B/i.test(link.url);

    if (masked) ambiguous++;

    return addTarget(
      masked ? Symbol('unknown-target') : canonical(link.url),
      link.url
    );
  };

  const components = catalogue('component');
  const forms = catalogue('form');
  const behaviors = catalogue('behavior');

  const pages = report.pages.map(page => {
    const areas = page.areas ?? [];
    const index = new Map(areas.map(area => [area.id, area]));
    const children = new Map();
    const active = new Set();
    const built = new Map();

    for (const area of areas) {
      const parent = index.has(area.parent) ? area.parent : null;

      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(area.id);
    }

    const build = id => {
      if (active.has(id)) {
        throw new Error('Cyclic area hierarchy.');
      }

      if (built.has(id)) return built.get(id);

      active.add(id);

      const area = index.get(id);
      const value = {
        kind: area.kind,
        name: area.name
      };

      const descendants = (children.get(id) ?? []).map(build);

      if (descendants.length) value.children = descendants;

      if (area.links?.length) {
        value.links = unique(area.links.map(linkTarget));
      }

      if (area.forms?.length) {
        value.forms = area.forms.map(form => forms.add({
          selector: form.selector,
          htmlMethod: form.htmlMethod,
          htmlAction: path(form.htmlAction),
          fields: form.fields ?? []
        }));
      }

      for (const key of ['fields', 'buttons', 'outputs']) {
        if (area[key]?.length) value[key] = area[key];
      }

      const result = components.add(value);
      built.set(id, result);
      active.delete(id);

      return result;
    };

    const roots = (children.get(null) ?? []).map(build);

    if (built.size !== areas.length) {
      throw new Error('Unreachable/cyclic area hierarchy.');
    }

    const rules = new Map(
      (page.renderRules ?? []).map(rule => [rule.id, rule])
    );

    const behaviorIds = (page.behaviors ?? []).map(behavior => {
      const updates = (behavior.renderRefs ?? []).map(ref => {
        const rule = rules.get(ref);

        if (!rule) {
          throw new Error('Missing render rule: ' + ref);
        }

        const { id, ...rest } = rule;
        return rest;
      });

      return behaviors.add({
        trigger: behavior.trigger,
        api: (behavior.api ?? []).map(api => ({
          ...api,
          url: path(api.url)
        })),
        updates,
        evidence: behavior.evidence,
        script: path(behavior.script)
      });
    });

    return {
      id: page.id,
      target: byPage.get(page.id),
      title: page.title,
      components: roots,
      behaviors: unique(behaviorIds),
      observations: {
        postCards: page.posts?.length ?? 0,
        eventCards: page.events?.length ?? 0
      },
      ...(page.observedRequests?.length ? {
        observedRequests: page.observedRequests.map(request => ({
          ...request,
          url: path(request.url)
        }))
      } : {}),
      ...(page.error ? { error: page.error } : {})
    };
  });

  return {
    schemaVersion: 'structure-1.0',
    site: {
      origin,
      startPath: path(report.startUrl)
    },
    coverage: {
      scope: 'visited-client-pages',
      partial: !!report.summary?.truncated,
      reasons: report.summary?.truncationReasons ?? [],
      failedPages: pages.filter(page => page.error).length,
      targetIdentity:
        targetUrls && pageUrls ? 'raw-url' : 'partially-redacted',
      ...(ambiguous ? {
        ambiguousTargetOccurrences: ambiguous
      } : {})
    },
    pages,
    targets,
    components: components.items,
    forms: forms.items,
    behaviors: behaviors.items,
    dependencies: {
      status: 'not-provided',
      vulnerabilityMatching: 'not-performed',
      sources: []
    }
  };
}
