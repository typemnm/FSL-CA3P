// Runs inside the inspected browser page. Never returns input field values.
export function readDom(options = {}) {
  const AREA_SELECTOR = 'header, nav, main, aside, footer, section, dialog, details, [role=dialog], [role=region], [role=search], [role=tablist], [role=tabpanel]';
  const FIELD_SELECTOR = 'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), textarea, select, [contenteditable]:not([contenteditable=false]), [role=textbox], [role=searchbox], [role=combobox]';
  const BUTTON_SELECTOR = 'button, input[type=submit], input[type=button], input[type=reset], input[type=image], [role=button]';
  const OUTPUT_SELECTOR = 'article, table, output, [role=list], [role=grid], [role=status], [role=alert], [aria-live], [data-results]';
  const text = value => String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, 100);
  const escaped = value => CSS.escape(String(value));
  const selector = element => {
    if (element.id && document.querySelectorAll('#' + escaped(element.id)).length === 1) {
      return '#' + escaped(element.id);
    }
    const parts = [];
    for (let node = element; node && node !== document.documentElement; node = node.parentElement) {
      if (node.id && document.querySelectorAll('#' + escaped(node.id)).length === 1) {
        parts.unshift('#' + escaped(node.id));
        break;
      }
      const tag = node.tagName.toLowerCase();
      const siblings = [...node.parentElement.children].filter(sibling => sibling.tagName === node.tagName);
      parts.unshift(tag + (siblings.length > 1 ? ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')' : ''));
    }
    return parts.join(' > ');
  };
  const visible = element => element.getClientRects().length > 0 &&
    getComputedStyle(element).visibility !== 'hidden';
  const label = element => {
    const direct = element.labels ? [...element.labels].map(item => text(item.textContent)) : [];
    const ariaIds = (element.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
    return [...new Set([...direct, text(element.getAttribute('aria-label')),
      ...ariaIds.map(id => text(document.getElementById(id)?.textContent))].filter(Boolean))].join(' / ') || null;
  };
  const areaNodes = [...document.querySelectorAll(AREA_SELECTOR)].slice(0, 100);
  const areaIndex = new Map(areaNodes.map((element, index) => [element, index]));
  const areaFor = element => {
    const area = element.closest(AREA_SELECTOR);
    return areaIndex.has(area) ? areaIndex.get(area) : null;
  };
  const areas = areaNodes.map(element => {
    const parent = element.parentElement?.closest(AREA_SELECTOR);
    const heading = [...element.querySelectorAll('h1, h2, h3, h4, h5, h6')]
      .find(item => item.closest(AREA_SELECTOR) === element);
    return {
      name: text(element.getAttribute('aria-label')) || text(heading?.textContent) || element.tagName.toLowerCase(),
      kind: element.tagName.toLowerCase(),
      selector: selector(element),
      parentIndex: areaIndex.has(parent) ? areaIndex.get(parent) : null,
      forms: [], fields: [], buttons: [], links: [], outputs: []
    };
  });
  const other = { name: '기타 요소', kind: 'page', selector: null, parentIndex: null,
    forms: [], fields: [], buttons: [], links: [], outputs: [] };
  const target = element => areas[areaFor(element)] || other;
  const formNodes = [...document.forms].slice(0, 80);
  const forms = new Map();
  for (const form of formNodes) {
    const item = {
      selector: selector(form), htmlMethod: (form.getAttribute('method') || 'GET').toUpperCase(),
      htmlAction: new URL(form.getAttribute('action') || location.href, location.href).href,
      fields: []
    };
    target(form).forms.push(item);
    forms.set(form, item);
  }
  for (const element of [...document.querySelectorAll(FIELD_SELECTOR)].slice(0, 250)) {
    const type = element.tagName === 'INPUT' ? (element.type || 'text') :
      element.tagName === 'TEXTAREA' ? 'textarea' :
      element.tagName === 'SELECT' ? 'select' : element.getAttribute('role') || 'contenteditable';
    const item = {
      selector: selector(element), name: element.getAttribute('name') || null,
      label: label(element), type, required: !!element.required,
      editable: type !== 'hidden' && !element.disabled && !element.readOnly,
      visible: visible(element)
    };
    if (element.tagName === 'SELECT') {
      item.choices = [...element.options].slice(0, 12).map(option => text(option.text));
    }
    const form = forms.get(element.form || element.closest('form'));
    if (form) form.fields.push(item);
    else target(element).fields.push(item);
  }
  for (const element of [...document.querySelectorAll(BUTTON_SELECTOR)].slice(0, 150)) {
    const item = {
      selector: selector(element),
      label: label(element) || text(element.innerText || element.value || element.getAttribute('title')) || null,
      type: element.getAttribute('type') || (element.tagName === 'BUTTON' ? 'submit' : 'button'),
      visible: visible(element)
    };
    const form = forms.get(element.form || element.closest('form'));
    if (form) item.form = form.selector;
    target(element).buttons.push(item);
  }
  for (const element of [...document.querySelectorAll('a[href]')].filter(link => {
    try { return ['http:', 'https:'].includes(new URL(link.href).protocol); }
    catch { return false; }
  }).slice(0, 250)) {
    target(element).links.push({ text: text(element.innerText || element.getAttribute('aria-label')),
      url: element.href });
  }
  for (const element of [...document.querySelectorAll(OUTPUT_SELECTOR)].slice(0, 100)) {
    const area = target(element);
    const kind = element.tagName.toLowerCase();
    const group = kind === 'article' && !element.id && element.classList.length ?
      'article.' + [...element.classList].slice(0, 2).map(escaped).join('.') : selector(element);
    const existing = area.outputs.find(item => item.selector === group && item.kind === kind);
    if (existing) existing.count++;
    else area.outputs.push({ kind, selector: group, count: 1 });
  }
  const posts = [...document.querySelectorAll('article')].slice(0, 50).map(article => {
    const first = selectors => article.querySelector(selectors);
    const title = first('[itemprop="headline"], .post-title, .entry-title, h1, h2, h3, h4, h5, h6');
    const author = first('.post-author-name, [itemprop="author"], [rel="author"], .author-name, .byline, .author');
    const body = first('[itemprop="articleBody"], .post-content, .entry-content, .article-content, .post-body, .article-body');
    let id = article.getAttribute('data-post-id') || article.getAttribute('data-id');
    let idSource = id ? 'dom-attribute' : null;
    if (!id) {
      const label = first('.post-number, .post-id, [data-post-number]');
      const match = text(label?.innerText).match(/(?:NO\.?|ID|#)\s*[:.]?\s*(\d+)/i);
      if (match) { id = match[1]; idSource = 'visible-label'; }
    }
    if (!id && /^post[-_]?[\w-]+$/i.test(article.id)) {
      id = article.id.replace(/^post[-_]?/i, '');
      idSource = 'dom-id';
    }
    const fullBody = body ? String(body.innerText || '').replace(/\s+/g, ' ').trim() : '';
    return {
      selector: selector(article),
      id: id || null,
      idSource,
      author: text(author?.matches('.post-author-name, .author-name') ?
        (author.querySelector('span')?.innerText || author.innerText) : author?.innerText) || null,
      title: text(title?.innerText) || null,
      body: body ? {
        selector: selector(body),
        preview: options.includeBodyPreview ? fullBody.slice(0, 160) : null,
        length: fullBody.length,
        previewTruncated: options.includeBodyPreview ? fullBody.length > 160 : null,
        matchSelectors: [body.id ? '#' + escaped(body.id) : null,
          ...[...body.classList].slice(0, 5).map(item => '.' + escaped(item))].filter(Boolean)
      } : null,
      buttons: [...article.querySelectorAll(BUTTON_SELECTOR)].filter(visible).slice(0, 10)
        .map(button => ({ selector: selector(button),
          label: label(button) || text(button.innerText || button.value) || null }))
    };
  });
  if (other.forms.length || other.fields.length || other.buttons.length || other.links.length || other.outputs.length) {
    areas.push(other);
  }
  return {
    title: text(document.title),
    areas,
    posts,
    counts: {
      areas: document.querySelectorAll(AREA_SELECTOR).length,
      forms: document.forms.length,
      fields: document.querySelectorAll(FIELD_SELECTOR).length,
      buttons: document.querySelectorAll(BUTTON_SELECTOR).length,
      links: document.querySelectorAll('a[href]').length,
      outputs: document.querySelectorAll(OUTPUT_SELECTOR).length,
      posts: document.querySelectorAll('article').length
    }
  };
}
