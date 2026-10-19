import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

process.env.LAB_MEMORY_DB = '1';
const { createApp: createDaehanApp } = await import('../src/server.mjs');
const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const runFile = promisify(execFile);
const smokeImage = 'ca3p-wonchang:smoke';
const springDbPath = '/app/data/smoke.sqlite';
const daehanPackage = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
const pom = readFileSync(join(projectRoot, 'wonchang', 'pom.xml'), 'utf8');
const daehanDeps = Object.keys(daehanPackage.dependencies);
const wonchangDeps = [...pom.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>/g)]
  .map(([, group, artifact]) => `${group}:${artifact}`);
assert.ok(daehanDeps.length >= 4 && wonchangDeps.length >= 4, 'each site has at least four external dependencies');
assert.deepEqual(daehanDeps.filter(name => wonchangDeps.includes(name)), [], 'the sites have distinct direct dependency sets');
assert.ok(daehanDeps.includes('express') && wonchangDeps.some(name => name.startsWith('org.springframework.boot:spring-boot-starter-web')), 'the server frameworks differ');

async function docker(...args) {
  const { stdout } = await runFile('docker', args, { cwd: projectRoot, timeout: 600_000, maxBuffer: 4 * 1024 * 1024 });
  return stdout.trim();
}

async function startDaehan() {
  const { app, db } = createDaehanApp('daehan');
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  return {
    db, base: `http://127.0.0.1:${server.address().port}`,
    async close() {
      await new Promise(resolve => server.close(resolve));
      db.close();
    }
  };
}

async function startWonchang() {
  console.log('Building isolated Spring smoke image...');
  await docker('build', '--quiet', '-f', 'wonchang/Dockerfile', '-t', smokeImage, '.');
  const id = await docker(
    'run', '--detach', '--publish', '127.0.0.1::4102',
    '--env', 'SERVER_PORT=4102', '--env', 'SERVER_ADDRESS=0.0.0.0',
    '--env', `WONCHANG_DB_PATH=${springDbPath}`, smokeImage
  );
  try {
    const binding = await docker('port', id, '4102/tcp');
    const port = Number(binding.match(/127\.0\.0\.1:(\d+)/)?.[1]);
    assert.ok(Number.isInteger(port) && port > 0, `Docker published port: ${binding}`);
    const base = `http://127.0.0.1:${port}`;
    let ready = false;
    for (let attempt = 0; attempt < 90; attempt++) {
      try {
        if ((await fetch(base + '/login', { signal: AbortSignal.timeout(1000) })).status === 200) {
          ready = true;
          break;
        }
      } catch { /* Spring is still starting. */ }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    if (!ready) {
      const logs = await docker('logs', '--tail', '80', id).catch(error => error.message);
      throw new Error(`Spring smoke container did not become ready.\n${logs}`);
    }
    return {
      base,
      async readDb(callback) {
        const temporaryRoot = realpathSync(tmpdir());
        const dir = mkdtempSync(join(temporaryRoot, 'wonchang-smoke-'));
        try {
          await docker('cp', `${id}:${springDbPath}`, join(dir, 'smoke.sqlite'));
          const db = new DatabaseSync(join(dir, 'smoke.sqlite'), { readOnly: true });
          try { return callback(db); } finally { db.close(); }
        } finally {
          const resolvedDir = realpathSync(dir);
          assert.equal(dirname(resolvedDir), temporaryRoot, 'temporary snapshot stays under the system temporary directory');
          assert.ok(resolvedDir.split(/[\\/]/).at(-1).startsWith('wonchang-smoke-'));
          rmSync(resolvedDir, { recursive: true, force: true });
        }
      },
      async close() {
        await docker('rm', '--force', id);
      }
    };
  } catch (error) {
    await docker('rm', '--force', id).catch(() => {});
    throw error;
  }
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

function serviceRecordIds(html) {
  return [...html.matchAll(/href="\/(?:admissions\/partner|staff\/mobile)\?id=(\d+)"/g)]
    .map(match => Number(match[1]));
}

function makeSmallTar(name, content) {
  const data = Buffer.from(content);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  header.write('0000644\0', 100, 8);
  header.write('0000000\0', 108, 8);
  header.write('0000000\0', 116, 8);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12);
  header.write('00000000000\0', 136, 12);
  header.fill(32, 148, 156);
  header.write('0', 156, 1);
  header.write('ustar\0', 257, 6);
  header.write('00', 263, 2);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8);
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512), Buffer.alloc(1024)]);
}

async function expectStatus(base, path, status, options = {}) {
  const response = await request(base, path, options);
  assert.equal(response.status, status, `${options.method || 'GET'} ${path}`);
  return response;
}

const instances = [];
try {
  for (const siteKey of ['daehan', 'wonchang']) {
    const instance = siteKey === 'daehan' ? await startDaehan() : await startWonchang();
    instances.push(instance);
    const { base } = instance;
    const name = siteKey === 'daehan' ? '대한대학교' : '원창대학교';
    if (siteKey === 'wonchang') {
      const response = await request(base, '/');
      assert.match(response.headers.get('x-powered-by') || '', /Spring Boot/i, 'Wonchang runs on Spring Boot');
    }
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
    const missingPage = await expectStatus(base, '/a-page-that-does-not-exist', 404,
      siteKey === 'wonchang' ? { headers: { accept: 'text/html' } } : {});
    if (siteKey === 'wonchang') assert.match(await missingPage.text(), /error-section/, 'Spring 404 HTML is rendered');
    const noMatch = await request(base, '/api/search?q=zzzz-no-match');
    assert.equal((await noMatch.json()).results.length, 0);
    const matching = await request(base, '/api/search?q=' + encodeURIComponent('학년도'));
    assert.ok((await matching.json()).results.length > 0, 'global search returns seeded posts');
    if (siteKey === 'daehan') {
      const filtered = await request(base, '/api/search?filters=' + encodeURIComponent('{type:"news",limit:2,}'));
      const filteredResults = (await filtered.json()).results;
      assert.equal(filteredResults.length, 2, 'JSON5 advanced search limits the result count');
      assert.ok(filteredResults.every(post => post.type === 'news'), 'JSON5 advanced search filters post type');
      const inherited = await request(base, '/api/search?filters=' + encodeURIComponent('{__proto__:{type:"notice",limit:1}}'));
      const inheritedResults = (await inherited.json()).results;
      assert.equal(inheritedResults.length, 1, 'JSON5 parsed object inherits a limit');
      assert.equal(inheritedResults[0].type, 'notice', 'JSON5 parsed object inherits a post type');
    }
    const injected = await request(base, '/api/search?q=' + encodeURIComponent("' OR 1=1 --"));
    assert.ok((await injected.json()).results.length > 0, 'A05 SQL injection probe');
    const diagnostic = await request(base, '/_diag/config');
    assert.equal(diagnostic.status, 200, 'A02 public diagnostics');
    assert.match((await diagnostic.json()).database, /\.sqlite$/);
    const studentHashes = siteKey === 'daehan'
      ? instance.db.prepare("SELECT password_hash FROM users WHERE username IN ('student1', 'student2') ORDER BY username").all()
      : await instance.readDb(db => db.prepare("SELECT password_hash FROM users WHERE username IN ('student1', 'student2') ORDER BY username").all());
    assert.equal(studentHashes[0].password_hash, studentHashes[1].password_hash, 'A04 identical passwords share unsalted SHA-1 hash');
    assert.match(studentHashes[0].password_hash, /^[0-9a-f]{40}$/);
    for (let attempt = 0; attempt < 8; attempt++) {
      const denied = await request(base, '/login', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: 'admin', password: 'wrong-password' })
      });
      assert.equal(denied.status, 401, 'A07 no failed-login throttle');
    }
    const unsafeNext = await request(base, '/login', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'student1', password: 'Welcome2026', next: '/\\evil.example/path' })
    });
    assert.equal(unsafeNext.status, 302);
    assert.equal(unsafeNext.headers.get('location'), '/mypage', 'backslash return path cannot redirect to another host');

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
      { path: '/admin/import', method: 'POST' }, { path: '/admin/settings', method: 'POST' },
      ...(siteKey === 'wonchang' ? [{ path: '/admin/schedule/preview', method: 'POST' },
        { path: '/admin/archive/preview', method: 'POST' }] : [])
    ]) {
      const denied = await expectStatus(base, guarded.path, 403, { method: guarded.method || 'GET' });
      if (siteKey === 'wonchang' && guarded.path === '/admin') {
        assert.match(await denied.text(), /error-section/, 'Spring 403 HTML is rendered');
      }
      await expectStatus(base, guarded.path, 403, {
        method: guarded.method || 'GET', headers: { cookie: studentCookie }
      });
    }

    const sideService = siteKey === 'daehan'
      ? { page: '/admissions/partner', api: '/api/admissions/partner/applications', first: 'partner1', second: 'partner2', password: 'Partner2026', person: 'applicant_name', unrelated: '/staff/mobile', section: '/admissions' }
      : { page: '/staff/mobile', api: '/api/staff/mobile/cases', first: 'staff1', second: 'staff2', password: 'Staff2026', person: 'student_name', unrelated: '/admissions/partner', section: '/campus' };
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
    const ownPage = await (await request(base, sideService.page, { headers: { cookie: sideCookie } })).text();
    const otherCookie = await login(base, sideService.second, sideService.password, sideService.page);
    const otherPage = await (await request(base, sideService.page, { headers: { cookie: otherCookie } })).text();
    const ownId = serviceRecordIds(ownPage)[0];
    const otherId = serviceRecordIds(otherPage)[0];
    assert.ok(ownId && otherId && ownId !== otherId, 'fictional auxiliary records are seeded for two owners');
    const ownRecord = await (await request(base, `${sideService.api}/${ownId}`, { headers: { cookie: sideCookie } })).json();
    const otherRecord = await (await request(base, `${sideService.api}/${otherId}`, { headers: { cookie: otherCookie } })).json();
    assert.ok(ownPage.includes(ownRecord[sideService.person]), 'own records render in the service page');
    assert.ok(!ownPage.includes(otherRecord[sideService.person]), 'the default list is scoped to the signed-in owner');
    const foreignPage = await request(base, `${sideService.page}?id=${otherId}`, { headers: { cookie: sideCookie } });
    assert.equal(foreignPage.status, 200, 'cross-owner detail is exposed through the lookup page');
    assert.ok((await foreignPage.text()).includes(otherRecord[sideService.person]));
    const foreignApi = await request(base, `${sideService.api}/${otherId}`, { headers: { cookie: sideCookie } });
    assert.equal(foreignApi.status, 200, 'cross-owner detail is exposed through the auxiliary API');
    assert.equal((await foreignApi.json())[sideService.person], otherRecord[sideService.person]);
    for (const id of [ownId, otherId]) {
      assert.equal((await request(base, `${sideService.api}/${id}`, { headers: { cookie: sideCookie } })).status, 200, 'sequential auxiliary lookups are not throttled');
    }
    const invalidSideId = await expectStatus(base, `${sideService.page}?id=abc`, 400, { headers: { cookie: sideCookie } });
    if (siteKey === 'wonchang') assert.match(await invalidSideId.text(), /error-section/, 'Spring 400 HTML is rendered');
    await expectStatus(base, `${sideService.page}?id=999999`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, `${sideService.api}/abc`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, `${sideService.api}/999999`, 404, { headers: { cookie: sideCookie } });
    await expectStatus(base, '/logout', 302, { headers: { cookie: sideCookie } });
    await expectStatus(base, sideService.page, 302, { headers: { cookie: sideCookie } });
    await expectStatus(base, '/logout', 302, { headers: { cookie: studentCookie } });
    await expectStatus(base, '/mypage', 302, { headers: { cookie: studentCookie } });

    const adminCookie = await login(base, 'admin', 'admin1234');
    assert.equal((await request(base, '/admin', { headers: { cookie: adminCookie } })).status, 200);
    if (siteKey === 'wonchang') {
      const preview = await request(base, '/admin/schedule/preview', {
        method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ payload: 'events:\n  - title: 학사 일정 미리보기\n    date: 2026-11-02' })
      });
      assert.equal(preview.status, 200, 'YAML schedule preview renders');
      assert.match(await preview.text(), /학사 일정 미리보기/, 'YAML schedule preview uses parsed content');
      const bundle = new FormData();
      bundle.append('bundle', new Blob([makeSmallTar('course-guide.txt', 'fictional course guide')],
        { type: 'application/x-tar' }), 'course-guide.tar');
      const archive = await request(base, '/admin/archive/preview', {
        method: 'POST', headers: { cookie: adminCookie }, body: bundle
      });
      assert.equal(archive.status, 200, 'TAR archive preview renders');
      assert.match(await archive.text(), /course-guide\.txt/, 'TAR archive preview lists file names');
    }
    await expectStatus(base, sideService.page, 403, { headers: { cookie: adminCookie } });
    await expectStatus(base, `${sideService.api}/1`, 403, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/new', 200, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/1/edit', 200, { headers: { cookie: adminCookie } });
    await expectStatus(base, '/admin/posts/999999/edit', 404, { headers: { cookie: adminCookie } });
    const created = await request(base, '/admin/posts', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'notice', title: '검증용 공지',
        body: siteKey === 'daehan' ? '기능 **검증** 본문' : '기능 검증 본문' })
    });
    assert.equal(created.status, 302);
    const createdNoticeHtml = await (await request(base, '/notices?q=' + encodeURIComponent('검증용 공지'))).text();
    const createdNoticePath = boardLinks(createdNoticeHtml)[0];
    assert.ok(createdNoticePath, 'created notice is stored');
    assert.match(await (await request(base, createdNoticePath)).text(), /검증용 공지/);
    if (siteKey === 'daehan') {
      assert.match(await (await request(base, createdNoticePath)).text(), /<strong>검증<\/strong>/, 'Markdown renders in post detail');
    }
    const createdNoticeId = Number(createdNoticePath.match(/\/(\d+)$/)?.[1]);
    assert.ok(createdNoticeId);
    const edited = await request(base, `/admin/posts/${createdNoticeId}`, {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'notice', title: '수정된 검증 공지', body: '수정된 검증 본문' })
    });
    assert.equal(edited.status, 302);
    assert.match(await (await request(base, `/notices/${createdNoticeId}`)).text(), /수정된 검증 본문/);
    const createdNews = await request(base, '/admin/posts', {
      method: 'POST', headers: { cookie: adminCookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ type: 'news', title: '검증용 대학 소식', body: '검증용 대학 소식 본문' })
    });
    assert.equal(createdNews.status, 302);
    const createdNewsHtml = await (await request(base, '/news?q=' + encodeURIComponent('검증용 대학 소식'))).text();
    const createdNewsPath = boardLinks(createdNewsHtml)[0];
    assert.ok(createdNewsPath, 'created news is stored');
    assert.match(await (await request(base, createdNewsPath)).text(), /검증용 대학 소식/);
    const newsId = Number(createdNewsPath.match(/\/(\d+)$/)?.[1]);
    assert.ok(newsId);
    await expectStatus(base, `/notices/${newsId}`, 404);
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
      body: new URLSearchParams({ payload: JSON.stringify(siteKey === 'daehan'
        ? { path: '__proto__.labProbe', value: true }
        : { path: 'theme.labProbe', value: '${env:WONCHANG_DB_PATH}' }) })
    });
    assert.equal(settingChanged.status, 302);
    if (siteKey === 'daehan') {
      try { assert.equal({}.labProbe, true, 'A03 vulnerable lodash path setter prototype pollution'); }
      finally { delete Object.prototype.labProbe; }
    } else {
      const settings = await instance.readDb(db => JSON.parse(db.prepare("SELECT value FROM settings WHERE key = 'site_preferences'").get().value));
      assert.equal(settings.theme.labProbe, springDbPath, 'A03 vulnerable Commons Text interpolation expands an environment value');
    }

    const removed = await request(base, '/admin/posts/1/delete', { method: 'POST' });
    assert.equal(removed.status, 302, 'A01 unauthenticated admin action');
    const brokenHome = await request(base, '/');
    assert.equal(brokenHome.status, 500, 'A06/A10 featured post deletion');
    assert.match(await brokenHome.text(), /TypeError|Cannot read properties|NullPointerException|Cannot invoke/);
    console.log(`${siteKey}: pages, assets, search, pagination, login/logout, roles, requests, auxiliary lookup, admin CRUD/import, A01-A08 and A10 probes passed; A09 static review only`);
  }

  // Browser cookies are scoped by host and path, not port; both local sites share a cookie jar.
  const browserCookies = new Map();
  for (const { base } of instances) {
    const cookie = await login(base, 'student1', 'Welcome2026');
    const separator = cookie.indexOf('=');
    browserCookies.set(cookie.slice(0, separator), cookie.slice(separator + 1));
  }
  assert.equal(browserCookies.size, 2, 'each site uses its own session cookie name');
  const cookieHeader = () => [...browserCookies].map(([name, value]) => `${name}=${value}`).join('; ');
  for (const { base } of instances) {
    await expectStatus(base, '/mypage', 200, { headers: { cookie: cookieHeader() } });
  }
  const logout = await expectStatus(instances[0].base, '/logout', 302, { headers: { cookie: cookieHeader() } });
  const clearedCookie = logout.headers.get('set-cookie').split('=')[0];
  assert.ok(browserCookies.delete(clearedCookie), 'logout clears its own session cookie');
  await expectStatus(instances[0].base, '/mypage', 302, { headers: { cookie: cookieHeader() } });
  await expectStatus(instances[1].base, '/mypage', 200, { headers: { cookie: cookieHeader() } });
} finally {
  await Promise.all(instances.map(instance => instance.close()));
}
console.log(`distinct direct dependencies verified: 대한대학교 ${daehanDeps.join(', ')} / 원창대학교 ${wonchangDeps.join(', ')}`);
