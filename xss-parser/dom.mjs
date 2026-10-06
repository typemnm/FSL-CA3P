// This function runs inside the inspected browser page. Keep it self-contained.
export function readDom() {
  const short = value => String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, 160);
  const unique = values => [...new Set(values.filter(Boolean))];
  const escape = value => CSS.escape(String(value));
  const selector = element => {
    if (element.id && document.querySelectorAll('#' + escape(element.id)).length === 1) {
      return '#' + escape(element.id);
    }
    const parts = [];
    for (let node = element; node && node.nodeType === 1 && node !== document.documentElement; node = node.parentElement) {
      if (node.id && document.querySelectorAll('#' + escape(node.id)).length === 1) {
        parts.unshift('#' + escape(node.id));
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
    const direct = element.labels ? [...element.labels].map(item => short(item.textContent)) : [];
    const ariaIds = (element.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
    const ariaText = ariaIds.map(id => short(document.getElementById(id)?.textContent));
    return unique([...direct, short(element.getAttribute('aria-label')), ...ariaText]).join(' / ') || null;
  };
  const forms = [...document.forms].slice(0, 100);
  const formIndex = new Map(forms.map((form, index) => [form, index]));
  const fieldNodes = [...document.querySelectorAll(
    'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), textarea, select, [contenteditable]:not([contenteditable=false]), [role=textbox], [role=searchbox], [role=combobox]'
  )].slice(0, 300);
  const fields = [...new Set(fieldNodes)].map(element => {
    const type = element.tagName === 'INPUT' ? (element.type || 'text') :
      element.tagName === 'TEXTAREA' ? 'textarea' :
      element.tagName === 'SELECT' ? 'select' :
      element.getAttribute('role') || 'contenteditable';
    const form = element.form || element.closest('form');
    const constraints = {};
    for (const attribute of ['minlength', 'maxlength', 'min', 'max', 'step', 'pattern', 'accept', 'autocomplete', 'inputmode']) {
      if (element.hasAttribute(attribute)) constraints[attribute] = short(element.getAttribute(attribute));
    }
    if (element.hasAttribute('multiple')) constraints.multiple = true;
    const options = element.tagName === 'SELECT' ?
      [...element.options].slice(0, 30).map(option => ({ text: short(option.text), value: short(option.value) })) : undefined;
    return {
      selector: selector(element),
      tag: element.tagName.toLowerCase(),
      htmlId: element.id || null,
      name: element.getAttribute('name') || null,
      type,
      label: label(element),
      placeholder: element.getAttribute('placeholder') || null,
      required: !!element.required || element.getAttribute('aria-required') === 'true',
      disabled: !!element.disabled || element.getAttribute('aria-disabled') === 'true',
      readOnly: !!element.readOnly || element.getAttribute('aria-readonly') === 'true',
      visible: visible(element),
      userEditable: type !== 'hidden' && !element.disabled && !element.readOnly &&
        element.getAttribute('aria-disabled') !== 'true',
      formIndex: formIndex.has(form) ? formIndex.get(form) : null,
      constraints,
      ...(options ? { options, optionsTruncated: element.options.length > 30 } : {})
    };
  });
  const controls = [...new Set([...document.querySelectorAll(
    'button, input[type=submit], input[type=button], input[type=reset], input[type=image], [role=button]'
  )])].slice(0, 150).map(element => {
    const form = element.form || element.closest('form');
    return {
      selector: selector(element),
      tag: element.tagName.toLowerCase(),
      htmlId: element.id || null,
      name: element.getAttribute('name') || null,
      type: element.getAttribute('type') || (element.tagName === 'BUTTON' ? 'submit' : 'button'),
      label: label(element) || short(element.innerText || element.value || element.getAttribute('title')) || null,
      disabled: !!element.disabled,
      visible: visible(element),
      formIndex: formIndex.has(form) ? formIndex.get(form) : null
    };
  });
  const links = [...document.querySelectorAll('a[href]')].slice(0, 300).map(element => ({
    href: element.href,
    text: short(element.innerText || element.getAttribute('aria-label')),
    rel: element.rel || null
  }));
  return {
    title: short(document.title),
    forms: forms.map(form => ({
      selector: selector(form),
      htmlId: form.id || null,
      name: form.getAttribute('name') || null,
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      actionUrl: new URL(form.getAttribute('action') || location.href, location.href).href,
      enctype: form.enctype,
      fields: [],
      controls: []
    })),
    fields,
    controls,
    links,
    inlineScripts: [...document.querySelectorAll('script:not([src])')]
      .slice(0, 20).map(script => script.textContent.slice(0, 200_000)),
    counts: {
      forms: document.forms.length,
      fields: document.querySelectorAll(
        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), textarea, select, [contenteditable]:not([contenteditable=false]), [role=textbox], [role=searchbox], [role=combobox]'
      ).length,
      controls: document.querySelectorAll(
        'button, input[type=submit], input[type=button], input[type=reset], input[type=image], [role=button]'
      ).length,
      links: document.querySelectorAll('a[href]').length
    }
  };
}
