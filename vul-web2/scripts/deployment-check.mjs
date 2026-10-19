import assert from 'node:assert/strict';

const sites = [
  {
    key: 'daehan', name: '대한대학교', base: 'http://127.0.0.1:4101',
    service: '/admissions/partner', api: '/api/admissions/partner/applications',
    account1: 'partner1', account2: 'partner2', password: 'Partner2026'
  },
  {
    key: 'wonchang', name: '원창대학교', base: 'http://127.0.0.1:4102',
    service: '/staff/mobile', api: '/api/staff/mobile/cases',
    account1: 'staff1', account2: 'staff2', password: 'Staff2026'
  }
];

async function request(site, path, options = {}) {
  return fetch(site.base + path, { redirect: 'manual', signal: AbortSignal.timeout(5000), ...options });
}

async function expect(site, path, status, options = {}) {
  const response = await request(site, path, options);
  assert.equal(response.status, status, `${site.key} ${options.method || 'GET'} ${path}`);
  return response;
}

async function login(site, username, password) {
  const response = await expect(site, '/login', 302, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password })
  });
  const cookie = response.headers.get('set-cookie');
  assert.ok(cookie, `${site.key} ${username} session cookie`);
  return cookie.split(';')[0];
}

function recordIds(html) {
  return [...html.matchAll(/href="\/(?:admissions\/partner|staff\/mobile)\?id=(\d+)"/g)]
    .map(match => Number(match[1]));
}

for (const site of sites) {
  const publicPages = [
    '/', '/about', '/admissions', '/colleges', '/academics', '/research',
    '/campus', '/facilities', '/notices', '/news', '/schedule', '/faq', '/login'
  ];
  for (const path of publicPages) {
    const response = await expect(site, path, 200);
    if (path === '/') {
      assert.ok((await response.text()).includes(site.name));
      if (site.key === 'wonchang') {
        assert.match(response.headers.get('x-powered-by') || '', /Spring Boot/i, 'Wonchang Spring Boot response header');
      }
    }
  }
  for (const path of ['/css/site.css', '/js/site.js', `/images/${site.key}-campus.png`]) {
    const response = await expect(site, path, 200);
    assert.ok((await response.arrayBuffer()).byteLength > 0, `${site.key} ${path} has content`);
  }
  for (const board of ['/notices', '/news']) {
    const html = await (await expect(site, board, 200)).text();
    const link = html.match(/class="board-row" href="([^"]+)"/);
    assert.ok(link, `${site.key} ${board} has a post`);
    // A post detail GET increments the persisted view counter; smoke checks it on an isolated DB.
    assert.match(link[1], new RegExp(`^${board}/[0-9]+$`), `${site.key} ${board} links to a post`);
  }
  const search = await expect(site, '/api/search?q=' + encodeURIComponent('학년도'), 200);
  assert.ok((await search.json()).results.length > 0, `${site.key} search returns results`);
  await expect(site, '/missing-page', 404);
  await expect(site, site.service, 302);
  await expect(site, `${site.api}/1`, 302);

  const studentCookie = await login(site, 'student1', 'Welcome2026');
  await expect(site, '/mypage', 200, { headers: { cookie: studentCookie } });
  await expect(site, '/admin', 403, { headers: { cookie: studentCookie } });
  await expect(site, site.service, 403, { headers: { cookie: studentCookie } });
  await expect(site, `${site.api}/1`, 403, { headers: { cookie: studentCookie } });

  const ownCookie = await login(site, site.account1, site.password);
  const otherCookie = await login(site, site.account2, site.password);
  const ownPage = await (await expect(site, site.service, 200, { headers: { cookie: ownCookie } })).text();
  const otherPage = await (await expect(site, site.service, 200, { headers: { cookie: otherCookie } })).text();
  const ownId = recordIds(ownPage)[0];
  const otherId = recordIds(otherPage)[0];
  assert.ok(ownId && otherId && ownId !== otherId, `${site.key} distinct owner records`);
  assert.ok(!recordIds(ownPage).includes(otherId), `${site.key} list is owner scoped`);
  await expect(site, `${site.service}?id=${ownId}`, 200, { headers: { cookie: ownCookie } });
  await expect(site, `${site.api}/${ownId}`, 200, { headers: { cookie: ownCookie } });
  await expect(site, `${site.service}?id=${otherId}`, 200, { headers: { cookie: ownCookie } });
  const foreignRecord = await expect(site, `${site.api}/${otherId}`, 200, { headers: { cookie: ownCookie } });
  assert.equal((await foreignRecord.json()).id, otherId, `${site.key} cross-owner record is returned`);
  await expect(site, `${site.api}/999999`, 404, { headers: { cookie: ownCookie } });

  const adminCookie = await login(site, 'admin', 'admin1234');
  await expect(site, '/admin', 200, { headers: { cookie: adminCookie } });
  await expect(site, '/admin/posts/new', 200, { headers: { cookie: adminCookie } });
  await expect(site, '/admin/posts/1/edit', 200, { headers: { cookie: adminCookie } });
  await expect(site, site.service, 403, { headers: { cookie: adminCookie } });
  await expect(site, '/logout', 302, { headers: { cookie: studentCookie } });
  await expect(site, '/mypage', 302, { headers: { cookie: studentCookie } });

  console.log(`${site.name}: ${publicPages.length} public pages, assets, boards, search, roles, auxiliary lookup, admin read paths passed`);
}
