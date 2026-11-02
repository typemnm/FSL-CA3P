import { ARTIFACT_LABELS, FLOW_EDGES, FLOW_NODES, deriveFlow, edgeKey, nodeActivityCounts, routeHops } from './flow-model.js';

/** Module topology with moving data dots and the '활동 요약' list for the attack dashboard. */
const SVG_NS = 'http://www.w3.org/2000/svg';
const HOP_MS = 520;
const FAST_HOP_MS = 200;
const STAGGER_MS = 190;
const FAST_STAGGER_MS = 55;
const MAX_DOTS = 24;
const MAX_QUEUE = 160;
const NEW_MS = 90_000;
const LIST_LIMIT = 150;
const ACTIVE = new Set(['queued', 'preparing', 'running', 'stopping']);
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const nodeById = new Map(FLOW_NODES.map(node => [node.id, node]));

function edgePath(edge) {
  const a = nodeById.get(edge.a); const b = nodeById.get(edge.b);
  return edge.via ? `M${a.x} ${a.y} Q${edge.via.x} ${edge.via.y} ${b.x} ${b.y}` : `M${a.x} ${a.y} L${b.x} ${b.y}`;
}

function timeLabel(timestamp) {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return '--:--:--';
  return new Date(timestamp).toLocaleTimeString('ko-KR', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Asia/Seoul' });
}

function graphMarkup(iconPath) {
  const edges = FLOW_EDGES.map(edge => `<path class="flow-edge" data-edge="${edgeKey(edge.a, edge.b)}" d="${edgePath(edge)}"><title>${escape(`${nodeById.get(edge.a).name} ↔ ${nodeById.get(edge.b).name} · ${edge.channel}`)}</title></path>`).join('');
  const nodes = FLOW_NODES.map(node => `<g class="flow-node" data-flow-node="${node.id}" transform="translate(${node.x} ${node.y})" tabindex="0" role="button" aria-pressed="false" aria-label="${escape(`${node.name} · ${node.role}`)}">`
    + '<circle class="flow-node-halo" r="35"/><circle class="flow-node-core" r="27"/>'
    + `<g class="flow-node-icon" transform="translate(-11 -11) scale(.92)" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${iconPath(node.icon)}</g>`
    + `<text class="flow-node-name" y="48">${escape(node.name)}</text><text class="flow-node-role" y="66">${escape(node.role)}</text>`
    + '<g class="flow-node-badge" transform="translate(21 -24)"><rect x="-13" y="-10" width="26" height="20" rx="10"/><text y="5">0</text></g></g>').join('');
  return `<svg class="flow-graph" viewBox="0 0 1000 490" role="img" aria-labelledby="flow-graph-title"><title id="flow-graph-title">에이전트와 모듈 사이의 데이터 흐름</title><g class="flow-edges">${edges}</g><g class="flow-dots"></g><g class="flow-nodes">${nodes}</g></svg>`;
}

export function createFlowView({ root, iconPath = () => '', onSelectEvent = () => {}, onOpenArtifact = () => {},
  artifactHref = () => null, onNewArtifact = () => {}, now = () => Date.now(),
  reducedMotion = () => globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true } = {}) {
  root.innerHTML = `<div class="flow-layout"><div class="flow-stage"><div class="flow-stage-bar"><span class="flow-live mono" data-flow-live>IDLE</span><span class="flow-filter-note" data-flow-filter-note hidden></span><button type="button" class="button secondary flow-replay" data-flow-replay>${iconPath('play') ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPath('play')}</svg>` : ''}흐름 재생</button></div>${graphMarkup(iconPath)}<ul class="flow-legend" aria-label="점 색상 안내"><li><i class="tone-info"></i>데이터 전달</li><li><i class="tone-success"></i>허용 · 확인</li><li><i class="tone-warning"></i>차단 · 보류</li><li><i class="tone-error"></i>실패</li><li><i class="tone-artifact"></i>산출물</li></ul></div>`
    + '<aside class="flow-activity" aria-labelledby="flow-activity-title"><div class="flow-activity-head"><h3 id="flow-activity-title">활동 요약</h3><span class="activity-counter mono" data-flow-count>00</span></div>'
    + '<div class="flow-artifacts" data-flow-artifacts hidden></div><ol class="flow-activity-list" data-flow-list role="log" aria-live="polite" aria-relevant="additions"></ol></aside></div>';
  const svg = root.querySelector('.flow-graph');
  const dotLayer = svg.querySelector('.flow-dots');
  const edgeEls = new Map([...svg.querySelectorAll('[data-edge]')].map(el => [el.dataset.edge, el]));
  const nodeEls = new Map([...svg.querySelectorAll('[data-flow-node]')].map(el => [el.dataset.flowNode, el]));
  const list = root.querySelector('[data-flow-list]');
  const artifactBar = root.querySelector('[data-flow-artifacts]');
  let runId = null; let flow = { runId: null, activities: [] }; let flowKey = '';
  let seen = new Set(); const fresh = new Map(); let filter = null; let renderedKey = '';
  let queue = []; let dots = []; let frame = 0; let lastStart = -Infinity; let expiryTimer = 0;
  const edgeUse = new Map(); const pulseTimers = new Map(); let playing = new Map();

  function memoKey(run) {
    const documents = run.reportDocuments?.items ?? [];
    return [run.id, run.status, run.events?.length ?? 0, run.artifacts?.length ?? 0, run.modelCalls?.length ?? 0,
      run.reportDocument?.status ?? '', run.reportDocuments?.status ?? '',
      Array.isArray(documents) ? documents.map(item => item?.status).join(',') : ''].join('|');
  }

  function pulse(id) {
    const el = nodeEls.get(id);
    if (!el) return;
    el.classList.remove('is-pulse');
    void el.getBoundingClientRect?.();
    el.classList.add('is-pulse');
    clearTimeout(pulseTimers.get(id));
    pulseTimers.set(id, setTimeout(() => el.classList.remove('is-pulse'), 700));
  }
  function useEdge(key, delta) {
    const value = Math.max(0, (edgeUse.get(key) ?? 0) + delta);
    edgeUse.set(key, value);
    edgeEls.get(key)?.classList.toggle('is-active', value > 0);
  }
  function markPlaying(id, delta) {
    const value = Math.max(0, (playing.get(id) ?? 0) + delta);
    if (value) playing.set(id, value); else playing.delete(id);
    list.querySelector(`[data-activity="${CSS.escape(id)}"]`)?.classList.toggle('is-playing', value > 0);
  }
  function enqueue(activity) {
    const hops = routeHops(activity.route);
    if (reducedMotion() || !hops.length || typeof SVGPathElement === 'undefined') {
      for (const id of new Set([activity.node, ...activity.route])) pulse(id);
      return;
    }
    queue.push({ id: activity.id, tone: activity.tone, hops });
    if (queue.length > MAX_QUEUE) {
      for (const item of queue.splice(0, queue.length - MAX_QUEUE)) for (const [, to] of item.hops) pulse(to);
    }
    if (!frame) frame = requestAnimationFrame(tick);
  }
  function startHop(dot, time) {
    const [from, to] = dot.hops[dot.index];
    const key = edgeKey(from, to);
    const path = edgeEls.get(key);
    const edge = FLOW_EDGES.find(item => edgeKey(item.a, item.b) === key);
    dot.path = path; dot.forward = edge.a === from; dot.key = key; dot.start = time;
    dot.length = path.getTotalLength();
    useEdge(key, 1);
  }
  function tick(time) {
    frame = 0;
    const busy = queue.length > 12;
    const hopMs = busy ? FAST_HOP_MS : HOP_MS;
    while (queue.length && dots.length < MAX_DOTS && time - lastStart >= (busy ? FAST_STAGGER_MS : STAGGER_MS)) {
      const item = queue.shift();
      const el = document.createElementNS(SVG_NS, 'circle');
      el.setAttribute('r', item.tone === 'artifact' ? '7' : '5');
      el.setAttribute('class', `flow-dot tone-${item.tone}`);
      dotLayer.append(el);
      const dot = { ...item, el, index: 0 };
      startHop(dot, time); markPlaying(item.id, 1);
      dots.push(dot); lastStart = time;
    }
    dots = dots.filter(dot => {
      let progress = (time - dot.start) / hopMs;
      while (progress >= 1) {
        useEdge(dot.key, -1); pulse(dot.hops[dot.index][1]);
        dot.index += 1;
        if (dot.index >= dot.hops.length) { dot.el.remove(); markPlaying(dot.id, -1); return false; }
        startHop(dot, time); progress = 0;
      }
      const eased = progress < .5 ? 2 * progress * progress : 1 - (-2 * progress + 2) ** 2 / 2;
      const point = dot.path.getPointAtLength(dot.length * (dot.forward ? eased : 1 - eased));
      dot.el.setAttribute('cx', point.x.toFixed(1)); dot.el.setAttribute('cy', point.y.toFixed(1));
      return true;
    });
    if (dots.length || queue.length) frame = requestAnimationFrame(tick);
  }
  function clearMotion() {
    if (frame) cancelAnimationFrame(frame);
    frame = 0; queue = []; lastStart = -Infinity;
    for (const dot of dots) dot.el.remove();
    dots = [];
    for (const key of edgeUse.keys()) useEdge(key, -Infinity);
    playing = new Map();
  }

  function scheduleExpiry() {
    clearTimeout(expiryTimer);
    if (!fresh.size) return;
    const next = Math.min(...fresh.values()) + NEW_MS - now();
    expiryTimer = setTimeout(() => {
      for (const [id, at] of fresh) if (now() - at >= NEW_MS) fresh.delete(id);
      renderList(true); scheduleExpiry();
    }, Math.max(250, next));
  }

  function artifactLink(activity) {
    const href = artifactHref(activity.artifact, runId);
    return href ? `<a class="flow-artifact-download" href="${escape(href)}" download="${escape(activity.artifact.filename || '')}" aria-label="${escape(activity.artifact.label)} 내려받기">내려받기</a>` : '';
  }
  function itemMarkup(activity) {
    const node = nodeById.get(activity.node);
    const isNew = fresh.has(activity.id);
    const classes = ['flow-activity-item', `tone-${activity.tone}`, activity.artifact ? 'is-artifact' : '', isNew ? 'is-new' : '', playing.has(activity.id) ? 'is-playing' : ''].filter(Boolean).join(' ');
    const clickable = activity.artifact || activity.eventId;
    const hint = activity.artifact ? '눌러서 산출물 위치로 이동' : activity.eventId ? '눌러서 추적 데이터 보기' : '';
    const body = `<span class="flow-activity-meta"><span class="mono">${timeLabel(activity.timestamp)}</span><span class="flow-activity-node">${escape(node?.name ?? activity.node)}</span>${activity.artifact ? '<span class="flow-artifact-chip">산출물</span>' : ''}${isNew ? '<span class="flow-new-chip">NEW</span>' : ''}</span><strong>${escape(activity.title)}</strong>${activity.detail ? `<small>${escape(activity.detail)}</small>` : ''}`;
    return `<li class="${classes}" data-activity="${escape(activity.id)}">${clickable
      ? `<button type="button" class="flow-activity-main" data-activity-open="${escape(activity.id)}" title="${hint}">${body}</button>`
      : `<div class="flow-activity-main">${body}</div>`}${activity.artifact ? artifactLink(activity) : ''}</li>`;
  }
  function renderList(force = false) {
    const visible = filter ? flow.activities.filter(item => item.node === filter || item.route.includes(filter)) : flow.activities;
    const key = `${flowKey}|${filter}|${[...fresh.keys()].join(',')}`;
    if (!force && key === renderedKey) return;
    renderedKey = key;
    const recent = visible.slice(-LIST_LIMIT).reverse();
    list.innerHTML = recent.length ? recent.map(itemMarkup).join('')
      : `<li class="flow-activity-empty">${runId ? filter ? '이 모듈을 거친 활동이 없습니다.' : '수신한 활동이 없습니다.' : '점검을 시작하면 모듈 사이의 활동이 여기에 요약됩니다.'}</li>`;
    root.querySelector('[data-flow-count]').textContent = String(visible.length).padStart(2, '0');
    const artifacts = flow.activities.filter(item => item.artifact).slice(-6).reverse();
    artifactBar.hidden = !artifacts.length;
    artifactBar.innerHTML = artifacts.length ? `<span class="flow-artifacts-label">산출물 ${flow.activities.filter(item => item.artifact).length}건</span>${artifacts.map(item => `<button type="button" class="flow-artifact-pill${fresh.has(item.id) ? ' is-new' : ''}" data-activity-open="${escape(item.id)}">${escape(ARTIFACT_LABELS[item.artifact.kind] || item.artifact.label)}${item.artifact.findingId ? ` · ${escape(item.artifact.findingId)}` : ''}</button>`).join('')}` : '';
    const counts = nodeActivityCounts(flow.activities);
    for (const [id, el] of nodeEls) {
      el.querySelector('.flow-node-badge text').textContent = counts[id] > 99 ? '99+' : String(counts[id]);
      el.classList.toggle('is-idle', !counts[id]);
      el.classList.toggle('is-filtered', filter === id);
      el.setAttribute('aria-pressed', String(filter === id));
      el.setAttribute('aria-label', `${nodeById.get(id).name} · ${nodeById.get(id).role} · 활동 ${counts[id]}건${filter === id ? ' · 필터 적용 중' : ''}`);
    }
    const note = root.querySelector('[data-flow-filter-note]');
    note.hidden = !filter;
    note.innerHTML = filter ? `${escape(nodeById.get(filter)?.name)} 활동만 표시 <button type="button" class="text-button" data-flow-clear-filter>전체 보기</button>` : '';
  }

  function update(run, { visible = true, live = true } = {}) {
    const nextId = typeof run?.id === 'string' && run.id ? run.id : null;
    const key = nextId ? memoKey(run) : '';
    const changedRun = nextId !== runId;
    if (changedRun) { clearMotion(); fresh.clear(); filter = null; }
    if (changedRun || key !== flowKey) flow = nextId ? deriveFlow(run) : { runId: null, activities: [] };
    flowKey = key;
    const liveRun = live && ACTIVE.has(run?.status);
    root.querySelector('[data-flow-live]').textContent = !nextId ? 'IDLE' : liveRun ? 'LIVE' : live ? 'LATEST RUN' : 'SAVED RUN';
    root.querySelector('[data-flow-live]').classList.toggle('is-live', liveRun);
    const onScreen = visible && root.getClientRects().length > 0;
    if (changedRun) {
      runId = nextId;
      // A freshly started live run animates from its first step; a loaded history does not replay by itself.
      const animateAll = liveRun && flow.activities.length <= 6;
      seen = new Set(animateAll ? [] : flow.activities.map(item => item.id));
    }
    const arrivals = flow.activities.filter(item => !seen.has(item.id));
    for (const activity of arrivals) {
      seen.add(activity.id);
      if (activity.artifact && live) { fresh.set(activity.id, now()); onNewArtifact(activity); }
      if (onScreen) enqueue(activity);
    }
    renderList(changedRun);
    if (arrivals.some(item => item.artifact)) scheduleExpiry();
  }

  function replay() {
    clearMotion();
    renderList(true);
    for (const activity of flow.activities) enqueue(activity);
  }

  function open(id) {
    const activity = flow.activities.find(item => item.id === id);
    if (!activity) return;
    if (fresh.delete(id)) { renderList(true); scheduleExpiry(); }
    if (activity.artifact) onOpenArtifact(activity.artifact, activity);
    else if (activity.eventId) onSelectEvent(activity.eventId, activity);
  }
  function toggleFilter(id) { filter = filter === id ? null : id; renderList(true); }

  root.addEventListener('click', event => {
    const opener = event.target.closest('[data-activity-open]');
    if (opener) { open(opener.dataset.activityOpen); return; }
    const node = event.target.closest('[data-flow-node]');
    if (node) { toggleFilter(node.dataset.flowNode); return; }
    if (event.target.closest('[data-flow-clear-filter]')) { filter = null; renderList(true); return; }
    if (event.target.closest('[data-flow-replay]')) replay();
  });
  root.addEventListener('keydown', event => {
    const node = event.target.closest?.('[data-flow-node]');
    if (node && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); toggleFilter(node.dataset.flowNode); }
  });
  renderList(true);
  return { update, replay, destroy() { clearMotion(); clearTimeout(expiryTimer); for (const timer of pulseTimers.values()) clearTimeout(timer); },
    get activities() { return flow.activities; } };
}
