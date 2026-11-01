const ID_SEG = /^[1-9][0-9]{0,8}$/u;

function querySlot(packet) {
  const query = packet?.query;
  if (!query || typeof query !== 'object' || Array.isArray(query) || Object.keys(query).length !== 1) return null;
  const [name, value] = Object.entries(query)[0];
  return value === '{{payload}}' ? name : null;
}

export function idsForPattern(templatePath, paths) {
  if (!String(templatePath).includes(':id')) return [];
  const escaped = String(templatePath).split(':id').map(part => part.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'));
  const matchId = new RegExp('^' + escaped.join('([1-9][0-9]{0,8})') + '$', 'u');
  const ids = [];
  for (const path of paths) {
    const matched = String(path).match(matchId);
    if (matched) ids.push(matched[1]);
  }
  return [...new Set(ids)].sort((left, right) => Number(left) - Number(right));
}

export function idGroups(paths) {
  const groups = new Map();
  for (const path of paths) {
    const match = String(path).match(/^(.*)\/([1-9][0-9]{0,8})$/u);
    if (!match) continue;
    const pattern = `${match[1]}/:id`;
    const ids = groups.get(pattern) ?? new Set();
    ids.add(match[2]);
    groups.set(pattern, ids);
  }
  return [...groups.entries()]
    .map(([pattern, ids]) => ({ pattern, ids: [...ids].sort((left, right) => Number(left) - Number(right)) }))
    .filter(group => group.ids.length >= 2);
}

function fieldNames(form) {
  return (form.fields ?? []).map(field => typeof field === 'string' ? field : field?.name).filter(Boolean);
}

function relatedIds(path, groups) {
  const tokens = String(path).toLowerCase().split(/[^a-z0-9]+/u).filter(token => token.length > 3);
  const matched = groups.filter(group => tokens.some(token => group.pattern.toLowerCase().includes(token)));
  const ids = (matched.length ? matched : groups).flatMap(group => group.ids);
  return [...new Set(ids)].sort((left, right) => Number(left) - Number(right));
}

export function bindTemplate(template, { paths = [], forms = [] } = {}) {
  const packet = template?.request?.packet;
  const mode = template?.verify?.mode;
  if (!packet || !mode) return [];
  const allowed = new Set(paths);
  const groups = idGroups(paths);
  const bindings = [];
  const slot = querySlot(packet);

  if (mode === 'resultCount' || mode === 'inheritedFilter' || mode === 'textContains') {
    const candidates = new Set();
    if (allowed.has(packet.path)) candidates.add(packet.path);
    if (slot) {
      for (const form of forms) {
        if ((form.method ?? 'GET') === (packet.method ?? 'GET') && fieldNames(form).includes(slot) && form.path) {
          candidates.add(form.path);
        }
      }
    }
    let bound = 0;
    for (const path of candidates) {
      bindings.push({ path, payload: template.payloads[0] });
      bound += 1;
      if (bound >= 2) break;
    }
  }

  if (mode === 'ownershipComparison' && packet.path.includes(':id')) {
    const ids = idsForPattern(packet.path, paths);
    if (ids.length >= 2) {
      bindings.push({
        path: packet.path,
        payload: ids[1],
        baselinePayload: ids[0],
      });
    }
  }

  if (mode === 'ownershipComparison' && slot === 'id') {
    const candidates = new Set([packet.path, ...[...allowed].filter(path => /\/(partner|mobile)$/u.test(path))]);
    for (const path of candidates) {
      if (!allowed.has(path)) continue;
      const ids = relatedIds(path, groups);
      if (ids.length < 2) continue;
      bindings.push({ path, payload: ids[1], baselinePayload: ids[0], baselinePath: path });
    }
  }

  if (mode === 'containsFields' && allowed.has(packet.path)) {
    bindings.push({ path: packet.path, payload: template.payloads[0] });
  }

  if (mode === 'statusSequence') {
    const follow = template.verify.followUp?.path ?? '/';
    const baseline = template.verify.baseline?.path ?? '/';
    if (packet.path.includes(':id')) {
      const ids = idsForPattern(packet.path, paths);
      if (ids.length && allowed.has(baseline) && allowed.has(follow)) {
        bindings.push({
          path: packet.path, payload: ids[0], followUpPath: follow, baselinePath: baseline,
        });
      }
    } else if (allowed.has(packet.path) && allowed.has(baseline) && allowed.has(follow)) {
      bindings.push({
        path: packet.path, payload: template.payloads[0], followUpPath: follow, baselinePath: baseline,
      });
    }
  }

  if (mode === 'tagAcceptance' && allowed.has(packet.path)) {
    bindings.push({ path: packet.path, payload: template.payloads[0] });
  }

  const seen = new Set();
  return bindings.filter(item => {
    const key = [item.path, item.payload, item.baselinePayload ?? ''].join('\n');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function rankTemplate(template) {
  const path = template.request?.packet?.path ?? '';
  const method = template.request?.packet?.method;
  if (String(path).includes('/delete') || template.verify?.mode === 'statusSequence' && path.includes('delete')) return 2;
  if (method === 'POST' || template.verify?.mode === 'statusSequence') return 1;
  return 0;
}
