import { parse } from 'parse5';

const MAX_SIGNALS = 64;

function attributes(node) {
  return Object.fromEntries((node.attrs ?? []).map(({ name, value }) => [name.toLowerCase(), value]));
}

function httpUrl(value, base) {
  try {
    const url = new URL(value, base);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

/** Extract only real HTML elements from an already received, bounded response body. */
export function htmlFingerprintInputs(body, requestUrl) {
  const nodes = [];
  const pending = [parse(body, { scriptingEnabled: true })];
  while (pending.length) {
    const node = pending.pop();
    if (node.tagName === 'template') continue; // Inert template content is not a loaded resource.
    if (node.tagName) nodes.push(node);
    const children = node.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) pending.push(children[index]);
  }

  const firstBase = nodes.find(node => node.tagName === 'base' && attributes(node).href !== undefined);
  const baseUrl = firstBase ? httpUrl(attributes(firstBase).href, requestUrl) ?? requestUrl : requestUrl;
  const meta = [];
  const scriptSrc = [];
  const stylesheetHref = [];
  for (const node of nodes) {
    if (!['meta', 'script', 'link'].includes(node.tagName)) continue;
    const attrs = attributes(node);
    if (node.tagName === 'meta' && meta.length < MAX_SIGNALS) {
      const name = attrs.name ?? attrs.property;
      if (name && attrs.content !== undefined) meta.push({ name: name.slice(0, 128), content: attrs.content.slice(0, 2048) });
    }
    if (node.tagName === 'script' && attrs.src && scriptSrc.length < MAX_SIGNALS) {
      const src = httpUrl(attrs.src, baseUrl);
      if (src) scriptSrc.push(src);
    }
    if (node.tagName === 'link' && attrs.href) {
      const rel = (attrs.rel ?? '').toLowerCase().split(/\s+/u);
      const href = httpUrl(attrs.href, baseUrl);
      if (!href) continue;
      if (rel.includes('stylesheet') && stylesheetHref.length < MAX_SIGNALS) stylesheetHref.push(href);
      else if (rel.includes('modulepreload') && scriptSrc.length < MAX_SIGNALS) scriptSrc.push(href);
    }
  }
  return { meta, scriptSrc, stylesheetHref };
}
