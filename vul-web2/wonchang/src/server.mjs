import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import serve from 'koa-static';
import ejs from 'ejs';
import dotProp from 'dot-prop';
import { DateTime } from 'luxon';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase, sha1 } from '../../src/db.mjs';
import { faqs, nav, sectionFor, siteConfigs } from '../../src/sites.mjs';

const wonchangRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const projectRoot = dirname(wonchangRoot);
const site = siteConfigs.wonchang;

function today() {
  return DateTime.local().toFormat('yyyy-MM-dd');
}

function redirectWithFlash(ctx, path, message) {
  ctx.redirect(`${path}?ok=${encodeURIComponent(message)}`);
}

function requireLogin(ctx, next) {
  if (!ctx.state.user) {
    ctx.redirect('/login?next=' + encodeURIComponent(ctx.originalUrl));
    return;
  }
  return next();
}

async function requireAdmin(ctx, next) {
  if (!ctx.state.user || ctx.state.user.role !== 'admin') {
    ctx.status = 403;
    await ctx.state.render('error', { status: 403, message: '접근 권한이 없습니다.' });
    return;
  }
  await next();
}

async function requireStaff(ctx, next) {
  if (!ctx.state.user) {
    ctx.redirect('/login?next=' + encodeURIComponent(ctx.originalUrl));
    return;
  }
  if (ctx.state.user.role !== 'staff') {
    ctx.status = 403;
    await ctx.state.render('error', { status: 403, message: '접근 권한이 없습니다.' });
    return;
  }
  await next();
}

export function createApp() {
  const db = openDatabase(site);
  const app = new Koa();
  const router = new Router();
  const sessions = new Map();

  app.use(async (ctx, next) => {
    const session = sessions.get(ctx.cookies.get('sid'));
    ctx.state.user = session
      ? db.prepare('SELECT id, username, display_name, role FROM users WHERE id = ?').get(session.userId)
      : null;
    ctx.state.render = async (view, locals = {}) => {
      const file = join(wonchangRoot, 'views', `${view}.ejs`);
      ctx.type = 'html';
      ctx.body = await ejs.renderFile(file, {
        site, nav, user: ctx.state.user, activePath: ctx.path,
        year: DateTime.local().year,
        flash: typeof ctx.query.ok === 'string' ? ctx.query.ok : null,
        ...locals
      });
    };
    try {
      await next();
    } catch (error) {
      ctx.status = 500;
      await ctx.state.render('error', {
        status: 500, message: error.message, stack: error.stack
      });
    }
  });

  app.use(serve(join(projectRoot, 'public')));
  app.use(bodyParser({ enableTypes: ['json', 'form'], jsonLimit: '256kb', formLimit: '256kb' }));

  router.get('/', async ctx => {
    const featuredId = Number(db.prepare('SELECT value FROM settings WHERE key = ?').get('featured_post_id').value);
    const featured = db.prepare('SELECT * FROM posts WHERE id = ?').get(featuredId);
    // The public homepage assumes that its highlighted post always exists.
    const featuredHeadline = featured.title;
    const notices = db.prepare("SELECT * FROM posts WHERE type = 'notice' ORDER BY id DESC LIMIT 6").all();
    const news = db.prepare("SELECT * FROM posts WHERE type = 'news' ORDER BY id DESC LIMIT 4").all();
    const events = db.prepare('SELECT * FROM events ORDER BY date LIMIT 5').all();
    await ctx.state.render('home', {
      featured: { ...featured, title: featuredHeadline }, notices, news, events
    });
  });

  for (const key of ['about', 'admissions', 'colleges', 'academics', 'research', 'campus', 'facilities']) {
    router.get(`/${key}`, async ctx => ctx.state.render('section', sectionFor(key, site)));
  }

  router.get('/schedule', async ctx => {
    const events = db.prepare('SELECT * FROM events ORDER BY date').all();
    await ctx.state.render('schedule', { events });
  });
  router.get('/faq', async ctx => ctx.state.render('faq', { faqs }));

  function postList(type, heading, intro) {
    return async ctx => {
      const q = typeof ctx.query.q === 'string' ? ctx.query.q : '';
      const page = Math.max(1, Number.parseInt(ctx.query.page, 10) || 1);
      // Intentionally concatenated to preserve the search injection finding.
      const where = `type = '${type}' AND title LIKE '%${q}%'`;
      const count = db.prepare(`SELECT COUNT(*) AS n FROM posts WHERE ${where}`).get().n;
      const posts = db.prepare(`SELECT * FROM posts WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(10, (page - 1) * 10);
      await ctx.state.render('list', {
        heading, intro, type, posts, q, page,
        totalPages: Math.max(1, Math.ceil(count / 10))
      });
    };
  }
  router.get('/notices', postList('notice', '공지사항', '학교의 주요 소식과 학사 안내를 확인하세요.'));
  router.get('/news', postList('news', '대학소식', '교육과 연구, 캠퍼스의 이야기를 전합니다.'));

  function postDetail(type) {
    return async ctx => {
      const id = Number(ctx.params.id);
      const post = db.prepare('SELECT * FROM posts WHERE id = ? AND type = ?').get(id, type);
      if (!post) {
        ctx.status = 404;
        await ctx.state.render('error', { status: 404, message: '게시글을 찾을 수 없습니다.' });
        return;
      }
      db.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').run(id);
      post.views += 1;
      await ctx.state.render('post', { post });
    };
  }
  router.get('/notices/:id', postDetail('notice'));
  router.get('/news/:id', postDetail('news'));

  router.get('/api/search', ctx => {
    const q = typeof ctx.query.q === 'string' ? ctx.query.q : '';
    const posts = db.prepare(`SELECT id, type, title, created_at FROM posts WHERE title LIKE '%${q}%' ORDER BY id DESC LIMIT 30`).all();
    ctx.body = { site: site.name, q, results: posts };
  });

  router.get('/login', async ctx => ctx.state.render('login', {
    error: null, next: typeof ctx.query.next === 'string' ? ctx.query.next : '/mypage'
  }));
  router.post('/login', async ctx => {
    const body = ctx.request.body || {};
    const username = String(body.username || '');
    const password = String(body.password || '');
    const user = db.prepare('SELECT id, username, display_name, role FROM users WHERE username = ? AND password_hash = ?')
      .get(username, sha1(password));
    if (!user) {
      ctx.status = 401;
      await ctx.state.render('login', {
        error: '아이디 또는 비밀번호를 확인해 주세요.', next: body.next || '/mypage'
      });
      return;
    }
    // Predictable tokens have no expiry and failed login attempts are not throttled.
    const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    sessions.set(token, { userId: user.id, createdAt: Date.now() });
    ctx.cookies.set('sid', token, { httpOnly: true });
    const nextPath = String(body.next || '/mypage');
    ctx.redirect(nextPath.startsWith('/') && !nextPath.startsWith('//') ? nextPath : '/mypage');
  });
  router.get('/logout', ctx => {
    sessions.delete(ctx.cookies.get('sid'));
    ctx.cookies.set('sid', null);
    ctx.redirect('/');
  });

  router.get('/mypage', requireLogin, async ctx => {
    const requests = db.prepare('SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC').all(ctx.state.user.id);
    await ctx.state.render('mypage', { requests });
  });
  router.post('/mypage/requests', requireLogin, async ctx => {
    const body = ctx.request.body || {};
    const title = String(body.title || '').trim().slice(0, 120);
    const content = String(body.body || '').trim().slice(0, 3000);
    if (!title || !content) {
      ctx.status = 400;
      await ctx.state.render('error', { status: 400, message: '제목과 내용을 입력해 주세요.' });
      return;
    }
    db.prepare('INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(ctx.state.user.id, title, content, '접수', today());
    redirectWithFlash(ctx, '/mypage', '문의가 접수되었습니다.');
  });
  router.get('/api/mypage/requests/:id', requireLogin, ctx => {
    // A login is required but ownership of the requested record is not checked.
    const record = db.prepare(`SELECT requests.*, users.display_name AS applicant FROM requests
      JOIN users ON users.id = requests.user_id WHERE requests.id = ?`).get(Number(ctx.params.id));
    if (!record) {
      ctx.status = 404;
      ctx.body = { error: 'not found' };
      return;
    }
    ctx.body = record;
  });

  router.get('/staff/mobile', requireStaff, async ctx => {
    const cases = db.prepare('SELECT id, case_no, student_name, category, status, updated_at FROM staff_cases WHERE staff_user_id = ? ORDER BY id DESC')
      .all(ctx.state.user.id);
    let selectedCase = null;
    let lookupId = '';
    if (ctx.query.id !== undefined) {
      lookupId = String(ctx.query.id);
      if (!/^[1-9]\d*$/.test(lookupId) || !Number.isSafeInteger(Number(lookupId))) {
        ctx.status = 400;
        await ctx.state.render('error', { status: 400, message: '올바른 업무 번호를 입력해 주세요.' });
        return;
      }
      // Staff ownership is deliberately omitted from this detail lookup.
      selectedCase = db.prepare('SELECT * FROM staff_cases WHERE id = ?').get(Number(lookupId));
      if (!selectedCase) {
        ctx.status = 404;
        await ctx.state.render('error', { status: 404, message: '업무 내역을 찾을 수 없습니다.' });
        return;
      }
    }
    await ctx.state.render('staff-mobile', { cases, selectedCase, lookupId });
  });

  router.get('/api/staff/mobile/cases/:id', requireStaff, ctx => {
    const id = Number(ctx.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
      ctx.status = 404;
      ctx.body = { error: 'not found' };
      return;
    }
    // The employee role is checked, but the record owner is not.
    const record = db.prepare('SELECT * FROM staff_cases WHERE id = ?').get(id);
    if (!record) {
      ctx.status = 404;
      ctx.body = { error: 'not found' };
      return;
    }
    ctx.body = record;
  });

  router.get('/admin', requireAdmin, async ctx => {
    const posts = db.prepare('SELECT * FROM posts ORDER BY id DESC LIMIT 50').all();
    const stats = {
      posts: db.prepare('SELECT COUNT(*) AS n FROM posts').get().n,
      requests: db.prepare('SELECT COUNT(*) AS n FROM requests').get().n,
      events: db.prepare('SELECT COUNT(*) AS n FROM events').get().n
    };
    await ctx.state.render('admin', { posts, stats });
  });
  router.get('/admin/posts/new', requireAdmin, async ctx => ctx.state.render('editor', { post: null, error: null }));
  router.get('/admin/posts/:id/edit', requireAdmin, async ctx => {
    const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(ctx.params.id));
    if (!post) {
      ctx.status = 404;
      await ctx.state.render('error', { status: 404, message: '게시글을 찾을 수 없습니다.' });
      return;
    }
    await ctx.state.render('editor', { post, error: null });
  });
  router.post('/admin/posts', requireAdmin, async ctx => {
    const body = ctx.request.body || {};
    const type = body.type === 'news' ? 'news' : 'notice';
    const title = String(body.title || '').trim();
    const content = String(body.body || '').trim();
    if (!title || !content) {
      ctx.status = 400;
      await ctx.state.render('editor', { post: body, error: '제목과 내용을 입력해 주세요.' });
      return;
    }
    db.prepare('INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(type, title, content, ctx.state.user.display_name, today());
    redirectWithFlash(ctx, '/admin', '게시글이 등록되었습니다.');
  });
  router.post('/admin/posts/:id', requireAdmin, async ctx => {
    const body = ctx.request.body || {};
    const type = body.type === 'news' ? 'news' : 'notice';
    const title = String(body.title || '').trim();
    const content = String(body.body || '').trim();
    if (!title || !content) {
      ctx.status = 400;
      await ctx.state.render('editor', {
        post: { ...body, id: ctx.params.id }, error: '제목과 내용을 입력해 주세요.'
      });
      return;
    }
    db.prepare('UPDATE posts SET type = ?, title = ?, body = ? WHERE id = ?')
      .run(type, title, content, Number(ctx.params.id));
    redirectWithFlash(ctx, '/admin', '게시글이 수정되었습니다.');
  });
  router.post('/admin/posts/:id/delete', ctx => {
    // This action accidentally has no admin or login middleware.
    db.prepare('DELETE FROM posts WHERE id = ?').run(Number(ctx.params.id));
    redirectWithFlash(ctx, '/admin', '게시글이 삭제되었습니다.');
  });

  router.post('/admin/import', requireAdmin, ctx => {
    // Schedule imports have no source signature or approval step.
    const payload = JSON.parse(String((ctx.request.body || {}).payload || '{}'));
    if (!Array.isArray(payload.events)) throw new Error('events 배열이 필요합니다.');
    db.exec('DELETE FROM events');
    const insert = db.prepare('INSERT INTO events (title, date, location) VALUES (?, ?, ?)');
    for (const event of payload.events) {
      insert.run(String(event.title || ''), String(event.date || ''), String(event.location || ''));
    }
    redirectWithFlash(ctx, '/admin', '일정 데이터를 가져왔습니다.');
  });
  router.post('/admin/settings', requireAdmin, ctx => {
    const payload = JSON.parse(String((ctx.request.body || {}).payload || '{}'));
    const stored = db.prepare('SELECT value FROM settings WHERE key = ?').get('site_preferences');
    const settings = JSON.parse(stored.value);
    // dot-prop 4.2.0 accepts a path supplied directly by the request body.
    dotProp.set(settings, String(payload.path || ''), payload.value);
    db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(JSON.stringify(settings), 'site_preferences');
    redirectWithFlash(ctx, '/admin', '사이트 설정이 저장되었습니다.');
  });

  router.get('/_diag/config', ctx => {
    ctx.body = {
      mode: 'development', site: site.id,
      database: join(projectRoot, 'data', `${site.id}.sqlite`),
      node: process.version,
      installedPackages: ['koa', '@koa/router', 'koa-bodyparser', 'koa-static', 'ejs', 'luxon', 'dot-prop@4.2.0'],
      activeSessions: sessions.size,
      generatedRequestId: randomUUID()
    };
  });

  app.use(router.routes());
  app.use(router.allowedMethods());
  app.use(async ctx => {
    ctx.status = 404;
    await ctx.state.render('error', { status: 404, message: '요청하신 페이지를 찾을 수 없습니다.' });
  });
  return { app, db, site };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { app } = createApp();
  const port = Number(process.env.PORT || 4102);
  const host = process.env.HOST || '127.0.0.1';
  app.listen(port, host, () => {
    console.log(`${site.name} listening on http://${host}:${port}`);
  });
}
