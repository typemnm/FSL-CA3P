import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const TEMPLATES = resolve(new URL('../templates', import.meta.url).pathname);
const ORIGINS = { 'vul-web2-daehan': process.env.DAEHAN_ORIGIN, 'vul-web-1': process.env.VULWEB1_ORIGIN };

function allTemplates(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...allTemplates(p));
    else if (name.endsWith('.json') && name !== 'schema.json') out.push(p);
  }
  return out;
}

async function req(origin, method, path, { body, headers } = {}) {
  const r = await fetch(origin + path, { method, body, headers, redirect: 'manual' });
  let json = null;
  try { json = await r.json(); } catch {}
  return { status: r.status, json };
}

function count(json, field) { const v = json?.[field]; return Array.isArray(v) ? v.length : null; }

async function resultCount(origin, t) {
  const param = (t.request.curl.match(/[?&](\w+)=\{\{payload\}\}/) || [])[1];
  if (!param) return 'inconclusive';
  const base = await req(origin, 'GET', `${t.target.endpoint}?${param}=${encodeURIComponent(t.verify.baseline.value)}`);
  if (count(base.json, t.verify.field) !== t.verify.baseline.expect) return 'inconclusive';
  for (const p of t.payloads) {
    const atk = await req(origin, 'GET', `${t.target.endpoint}?${param}=${encodeURIComponent(p)}`);
    if ((count(atk.json, t.verify.field) ?? 0) >= t.verify.attack.expectMin) return 'confirmed';
  }
  return 'not_confirmed';
}

async function fieldsPresent(origin, t) {
  const r = await req(origin, 'GET', t.target.endpoint);
  if (!r.json || typeof r.json !== 'object') return 'inconclusive';
  return t.verify.fields.every(f => r.json[f] !== undefined) ? 'confirmed' : 'not_confirmed';
}

async function statusChain(origin, t) {
  for (const s of t.verify.steps) {
    const r = await req(origin, s.method, s.path);
    if (r.status !== s.expectStatus) return r.status === 200 && s.expectStatus === 500 ? 'not_confirmed' : 'inconclusive';
  }
  return 'confirmed';
}

async function idorDelete(origin, t) {
  const c = await req(origin, 'DELETE', `${t.verify.control.path}?authorId=${t.verify.control.authorId}`);
  if (c.status !== t.verify.control.expectStatus) return 'inconclusive';
  const a = await req(origin, 'DELETE', `${t.verify.attack.path}?authorId=${t.verify.attack.authorId}`);
  if (a.status !== t.verify.attack.expectStatus) return [403,404].includes(a.status) ? 'not_confirmed' : 'inconclusive';
  const list = await req(origin, 'GET', t.verify.removedCheck.path);
  const posts = Array.isArray(list.json?.posts) ? list.json.posts : null;
  const removed = posts ? !posts.some(p => p && p.id === t.verify.removedCheck.postId) : null;
  return removed === true ? 'confirmed' : 'inconclusive';
}

const RUN = { resultCount, fieldsPresent, statusChain, idorDelete };

for (const file of allTemplates(TEMPLATES).sort((a,b)=>a.localeCompare(b))) {
  const t = JSON.parse(readFileSync(file, 'utf8'));
  const app = t.target.application;
  const origin = ORIGINS[app];
  const mode = t.verify.mode;
  if (!RUN[mode]) { console.log(`SKIP    ${t.attackType.name}/${t.templateId}  (${mode} — 자동검증 아님)`); continue; }
  if (!origin) { console.log(`SKIP    ${t.attackType.name}/${t.templateId}  (${app} 미기동)`); continue; }
  try {
    const verdict = await RUN[mode](origin, t);
    const mark = verdict === 'confirmed' ? 'PASS ✓' : verdict === 'not_confirmed' ? 'FAIL ✗' : 'INCONC';
    console.log(`${mark}  ${t.attackType.name}/${t.templateId}  [${mode}] => ${verdict}`);
  } catch (e) { console.log(`ERROR   ${t.attackType.name}/${t.templateId}  ${e.message}`); }
}
