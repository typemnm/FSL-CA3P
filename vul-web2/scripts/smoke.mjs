import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

process.env.LAB_MEMORY_DB = '1';
const { createApp: createDaehanApp } = await import('../src/server.mjs');
const { createApp: createWonchangApp } = await import('../wonchang/src/server.mjs');
const daehanPackage = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
const wonchangPackage = JSON.parse(readFileSync(fileURLToPath(new URL('../wonchang/package.json', import.meta.url)), 'utf8'));
const daehanDeps = Object.keys(daehanPackage.dependencies);
const wonchangDeps = Object.keys(wonchangPackage.dependencies);
assert.ok(daehanDeps.length >= 4 && wonchangDeps.length >= 4, 'each site has at least four external dependencies');
assert.deepEqual(daehanDeps.filter(name => wonchangDeps.includes(name)), [], 'the sites have distinct direct dependency sets');
assert.ok(daehanDeps.includes('express') && wonchangDeps.includes('koa'), 'the server frameworks differ');

async function start(siteKey) {
  const { app, db } = siteKey === 'daehan' ? createDaehanApp('daehan') : createWonchangApp();
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  return { db, server, base: `http://127.0.0.1:${server.address().port}` };
}

async function request(base, path, options = {}) {
  return fetch(base + path, { redirect: 'manual', ...options });
}

async function login(base, username, password, nextPath) {
  const response = await request(base, '/login', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password, ...(nextPath ? { next: nextPath } : {}) })
  });
  assert.equal(response.status, 302);
  if (nextPath) assert.equal(response.headers.get('location'), nextPath, 'login returns to requested service');
  return response.headers.get('set-cookie').split(';')[0];
}

function boardLinks(html) {
  return [...html.matchAll(/class="board-row" href="([^"]+)"/g)].map(match => match[1]);
}

async function expectStatus(base, path, status, options = {}) {
  const response = await request(base, path, options);
  assert.equal(response.status, status, `${options.method || 'GET'} ${path}`);
  return response;
}

const instances = [];
try {
  for (const siteKey of ['daehan', 'wonchang']) {
    const instance = await start(siteKey);
    instances.push(instance);
    const { base } = instance;
    const name = siteKey === 'daehan' ? '대한대학교' : '원창대학교';
    for (const path of ['/', '/about', '/admissions', '/colleges', '/academics', '/research', '/campus', '/facilities', '/notices', '/news', '/schedule', '/faq', '/login']) {
      const response = await request(base, path);
      if (response.status !== 200) console.error(`${siteKey} ${path}: ${response.status}\n${(await response.clone().text()).slice(-3500)}`);
      assert.equal(response.status, 200, `${siteKey} ${path}`);
      if (path === '/') assert.match(await response.text(), new RegExp(name));
    }
    const post = await request(base, '/notices/1');
    assert.equal(post.status, 200);
    for (const board of ['/notices', '/news']) {
      const html = await (await request(base, board)).text();
      const firstLink = boardLinks(html)[0];
      assert.ok(firstLink, `${board} has a clickable post link`);
      assert.equal((await request(base, firstLink)).status, 200, `${board} post link works`);
    }
    const firstNoticePage = await (await request(base, '/notices?page=1')).text();
    const secondNoticePage = await (await request(base, '/notices?page=2')).text();
    assert.equal(boardLinks(firstNoticePage).length, 10, 'first notice page contains ten posts');
    assert.equal(boardLinks(secondNoticePage).length, 2, 'second notice page contains remaining posts');
    assert.ok(!boardLinks(firstNoticePage).includes(boardLinks(secondNoticePage)[0]), 'pagination changes the posts');
    assert.match(firstNoticePage, /page=2/, 'notice pagination links to the next page');
    const filteredNotices = await (await request(base, '/notices?q=' + encodeURIComponent('학년도'))).text();
    assert.match(filteredNotices, /학년도/, 'board title search finds seeded notices');
    assert.ok(boardLinks(filteredNotices).length > 0, 'board search displays matching posts');
    for (const asset of ['/css/site.css', '/js/site.js', `/images/${siteKey}-campus.png`]) {
      const response = await expectStatus(base, asset, 200);
      assert.ok((await response.arrayBuffer()).byteLength > 0, `${asset} has content`);
    }
    await expectStatus(base, '/a-page-that-does-not-exist', 404);
    const noMatch = await request(base, '/api/search?q=zzzz-no-match');
    assert.equal((await noMatch.json()).results.length, 0);
    const matching = await request(base, '/api/search?q=' + encodeURIComponent('학년도'));
    assert.ok((await matching.json()).results.length > 0, 'global search returns seeded posts');
    const injected = await request(base, '/api/search?q=' + encodeURIComponent("' OR 1=1 --"));
    assert.ok((await injected.json()).results.length > 0, 'A05 SQL injection probe');
    const diagnostic = await request(base, '/_diag/config');
    assert.equal(diagnostic.status, 200, 'A02 public diagnostics');
    assert.match((await diagnostic.json()).database, /\.sqlite$/);
    const studentHashes = instance.db.prepare("SELECT password_hash FROM users WHERE username IN ('student1', 'student2') ORDER BY username").all();
    assert.equal(studentHashes[0].password_hash, studentHashes[1].password_hash, 'A04 identical passwords share unsalted SHA-1 hash');
    assert.match(studentHashes[0].password_hash, /^[0-9a-f]{40}$/);
    for (let attempt = 0; attempt < 8; attempt++) {
      const denied = await request(base, '/login', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: 'admin', password: 'wrong-password' })
      });
      assert.equal(denied.status, 401, 'A07 no failed-login throttle');
    }

    const studentCookie = await login(base, 'student1', 'Welcome2026');
    assert.equal((await request(base, '/mypage', { headers: { cookie: studentCookie } })).status, 200);
    assert.equal((await request(base, '/api/mypage/requests/2', { headers: { cookie: studentCookie } })).status, 200, 'A01 IDOR probe');
    const requestForm = await request(base, '/mypage/requests', {
      method: 'POST', headers: { cookie: studentCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title: '학사 문의', body: '신청 절차 확인 요청' })
    });
    assert.equal(requestForm.status, 302);
    assert.match(await (await request(base, '/mypage', { headers: { cookie: studentCookie } })).text(), /학사 문의/, 'created request appears in mypage');
    await expectStatus(base, '/mypage/requests', 400, {
      method: 'POST', headers: { cookie: studentCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title: '', body: '내용만 있음' })
    });
    for (const guarded of [
      { path: '/admin' }, { path: '/admin/posts/new' }, { path: '/admin/posts/1/edit' },
      { path: '/admin/posts', method: 'POST' }, { path: '/admin/posts/1', method: 'POST' },
      { path: '/admin/import', method: 'POST' }, { path: '/admin/settings', method: 'POST' }
    ]) {
      await expectStatus(base, guarded.path, 403, { method: guarded.method || 'GET' });
      await expectStatus(base, guarded.path, 403, {
        method: guarded.method || 'GET', headers: { cookie: studentCookie }
      });
    }

    const sideService = siteKey === 'daehan'
      ? { page: '/admissions/partner', api: '/api/admissions/partner/applications', table: 'partner_applications', owner: 'partner_user_id', first: 'partner1', second: 'partner2', password: 'Partner2026', person: 'applicant_name', unrelated: '/staff/mobile', section: '/admissions' }
      : { page: '/staff/mobile', api: '/api/staff/mobile/cases', table: 'staff_cases', owner: 'staff_user_id', first: 'staff1', second: 'staff2', password: 'Staff2026', person: 'student_name', unrelated: '/admissions/partner', section: '/campus' };
    const sectionHtml = await (await request(base, sideService.section)).text();
    assert.ok(sectionHtml.includes(sideService.page), 'auxiliary service is reachable from the university site');
    const sideLoginRedirect = await expectStatus(base, sideService.page, 302);
    const loginUrl = new URL(sideLoginRedirect.headers.get('location'), base);
    assert.equal(loginUrl.pathname, '/login');
    assert.equal(loginUrl.searchParams.get('next'), sideService.page);
    assert.match(await (await request(base, loginUrl.pathname + loginUrl.search)).text(), /name="next"/, 'return destination appears in login form');
    assert.equal((await request(base, sideService.page, { headers: { cookie: studentCookie } })).status, 403, 'student role cannot open the auxiliary service');
    await expectStatus(base, `${sideService.api}/1`, 302);
    await expectStatus(base, `${sideService.api}/1`, 403, { headers: { cookie: studentCookie } });
    assert.equal((await request(base, sideService.unrelated)).status, 404, 'each university has its own auxiliary service');
    const sideCookie = await login(base, sideService.first, sideService.password, sideService.page);
    const firstOwnerId = instance.db.prepare('SELECT id FROM users WHERE username = ?').get(sideService.first).id;
    const secondOwnerId = instance.db.prepare('SELECT id FROM users WHERE username = ?').get(sideService.second).id;
    const ownRecord = instance.db.prepare(`SELECT * FROM ${sideService.table} WHERE ${sideService.owner} = ? ORDER BY id LIMIT 1`).get(firstOwnerId);
    const otherRecord = instance.db.prepare(`SELECT * FROM ${sideService.table} WHERE ${sideService.owner} = ? ORDER BY id LIMIT 1`).get(secondOwnerId);
    assert.ok(ownRecord && otherRecord, 'fictional auxiliary records are seeded for two owners');
    const ownPage = await (await request(base, sideService.page, { headers: { cookie: sideCookie } })).text();
    assert.ok(ownPage.includes(ownRecord[sideService.person]), 'own records render in the service page');
    assert.ok(!ownPage.includes(otherRecord[sideService.person]), 'the default list is scoped to the signed-in owner');
    const foreignPage = await request(base, `${sideService.page}?id=${otherRecord.id}`, { headers: { cookie: sideCookie } });
    assert.equal(foreignPage.status, 200, 'cross-owner detail is exposed through the lookup page');
    assert.ok((await foreignPage.text()).includes(otherRecord[sideService.person]));
    const foreignApi = await request(base, `${sideService.api}/${otherRecord.id}`, { headers: { cookie: sideCookie } });
    assert.equal(foreignApi.status, 200, 'cross-owner detail is exposed through the auxiliary API');
    assert.equal((await foreignApi.json())[sideService.person], otherRecord[sideService.person]);
    for (const id of [ownRecord.id, otherRecord.id]) {
      assert.equal((await request(base, `${sideService.api}/${id}`, { headers: { cookie: sideCookie } })).status, 200, 'sequential auxiliary lookups are not throttled');
    }
    await expectStatus(base, `${sideService.page}?id=abc`, 400, { headers: { cookie: sideCookie } });
    await expectStatus(base, `${sideService.page}?id=999999`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, `${sideService.api}/abc`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, `${sideService.api}/999999`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, '/logout', 302, { headers: { cookie: sideCookie } });
    await expectStatus(base, sideService.page, 302, { headers: { cookie: sideCookie } });
    await expectStatus(base, '/logout', 302, { headers: { cookie: studentCookie } });
    await expectStatus(base, '/mypage', 302, { headers: { cookie: studentCookie } });

    const adminCookie = await login(base, 'admin', 'admin1234');
    assert.equal((await request(base, '/admin', { headers: { cookie: adminCookie } })).status, 200);
    await expectStatus(base, sideService.page, 403, { headers: { cookie: adminCookie } });
    await expectStatus(base, `${sideService.api}/1`, 403, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/new', 200, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/1/edit', 200, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/999999/edit', 404, { headers: { cookie: adminCookie } });
    const created = await request(base, '/admin/posts', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'notice', title: '검증용 공지', body: '기능 검증 본문' })
    });
    assert.equal(created.status, 302);
    const createdNotice = instance.db.prepare('SELECT id FROM posts WHERE title = ?').get('검증용 공지');
    assert.ok(createdNotice, 'created notice is stored');
    assert.match(await (await request(base, `/notices/${createdNotice.id}`)).text(), /검증용 공지/);
    const edited = await request(base, `/admin/posts/${createdNotice.id}`, {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'notice', title: '수정된 검증 공지', body: '수정된 검증 본문' })
    });
    assert.equal(edited.status, 302);
    assert.match(await (await request(base, `/notices/${createdNotice.id}`)).text(), /수정된 검증 본문/);
    const createdNews = await request(base, '/admin/posts', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'news', title: '검증용 대학 소식', body: '검증용 대학 소식 본문' })
    });
    assert.equal(createdNews.status, 302);
    const newsRecord = instance.db.prepare('SELECT id FROM posts WHERE title = ?').get('검증용 대학 소식');
    assert.ok(newsRecord, 'created news is stored');
    assert.match(await (await request(base, `/news/${newsRecord.id}`)).text(), /검증용 대학 소식/);
    await expectStatus(base, `/notices/${newsRecord.id}`, 404);
    await expectStatus(base, '/admin/posts', 400, {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'news', title: '', body: '내용만 있음' })
    });
    const imported = await request(base, '/admin/import', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ payload: JSON.stringify({ events: [{ title: '검증 일정', date: '2026-11-01', location: '본관' }] }) })
    });
    assert.equal(imported.status, 302);
    assert.match(await (await request(base, '/schedule')).text(), /검증 일정/);
    const settingChanged = await request(base, '/admin/settings', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ payload: JSON.stringify({ path: '__proto__.labProbe', value: true }) })
    });
    assert.equal(settingChanged.status, 302);
    assert.equal({}.labProbe, true, 'A03 vulnerable path setter prototype pollution');
    delete Object.prototype.labProbe;

    const removed = await request(base, '/admin/posts/1/delete', { method: 'POST' });
    assert.equal(removed.status, 302, 'A01 unauthenticated admin action');
    const brokenHome = await request(base, '/');
    assert.equal(brokenHome.status, 500, 'A06/A10 featured post deletion');
    assert.match(await brokenHome.text(), /TypeError|Cannot read properties/);
    console.log(`${siteKey}: pages, assets, search, pagination, login/logout, roles, requests, auxiliary lookup, admin CRUD/import, A01-A08 and A10 probes passed; A09 static review only`);
  }
} finally {
  await Promise.all(instances.map(({ server }) => new Promise(resolve => server.close(resolve))));
  for (const { db } of instances) db.close();
}
console.log(`distinct direct dependencies verified: 대한대학교 ${daehanDeps.join(', ')} / 원창대학교 ${wonchangDeps.join(', ')}`);
