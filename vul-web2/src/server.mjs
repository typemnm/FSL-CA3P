import express from 'express';
import nunjucks from 'nunjucks';
import cookieParser from 'cookie-parser';
import lodash from 'lodash';
import dayjs from 'dayjs';
import JSON5 from 'json5';
import MarkdownIt from 'markdown-it';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { daehanDatabasePath, openDatabase, sha1 } from './db.mjs';
import { faqs, nav, sectionFor, siteConfigs } from './sites.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sessions = new Map();
const sessionCookie = 'daehan_sid';
const configuredPorts = { daehan: 4101 };
const markdown = new MarkdownIt({ html: false, breaks: true, linkify: true });

function safeNextPath(value) {
  const path = String(value || '/mypage');
  return path.startsWith('/') && !path.startsWith('//') && !/[\\\x00-\x1f\x7f]/.test(path) ? path : '/mypage';
}

function redirectWithFlash(res, path, message) {
  res.redirect(`${path}?ok=${encodeURIComponent(message)}`);
}

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).render('error', {
    status: 403, message: '접근 권한이 없습니다.'
  });
  next();
}

function requirePartner(req, res, next) {
  if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  if (req.user.role !== 'partner') return res.status(403).render('error', {
    status: 403, message: '협력기관 계정으로 로그인해 주세요.'
  });
  next();
}

export function createApp(siteKey) {
  const site = siteKey === 'daehan' ? siteConfigs.daehan : null;
  if (!site) throw new Error(`Unknown site: ${siteKey}`);
  const db = openDatabase(site);
  const app = express();
  app.set('view engine', 'njk');
  nunjucks.configure(join(root, 'views'), { autoescape: true, express: app, noCache: true });
  app.use(express.static(join(root, 'public')));
  app.use(express.urlencoded({ extended: false, limit: '256kb' }));
  app.use(express.json({ limit: '256kb' }));
  app.use(cookieParser());

  app.use((req, res, next) => {
    const session = sessions.get(req.cookies[sessionCookie]);
    req.user = session?.siteKey === siteKey ? db.prepare('SELECT id, username, display_name, role FROM users WHERE id = ?').get(session.userId) : null;
    res.locals.site = site;
    res.locals.nav = nav;
    res.locals.user = req.user;
    res.locals.activePath = req.path;
    res.locals.year = dayjs().year();
    res.locals.flash = typeof req.query.ok === 'string' ? req.query.ok : null;
    next();
  });

  app.get('/', (req, res, next) => {
    try {
      const featuredId = Number(db.prepare('SELECT value FROM settings WHERE key = ?').get('featured_post_id').value);
      const featured = db.prepare('SELECT * FROM posts WHERE id = ?').get(featuredId);
      // The home module assumes that the administrator's highlighted post always exists.
      // Deleting that ordinary post causes the public homepage to fail.
      const featuredHeadline = featured.title;
      const notices = db.prepare("SELECT * FROM posts WHERE type = 'notice' ORDER BY id DESC LIMIT 6").all();
      const news = db.prepare("SELECT * FROM posts WHERE type = 'news' ORDER BY id DESC LIMIT 4").all();
      const events = db.prepare('SELECT * FROM events ORDER BY date LIMIT 5').all();
      res.render('home', { featured: { ...featured, title: featuredHeadline }, notices, news, events });
    } catch (error) { next(error); }
  });

  for (const key of ['about', 'admissions', 'colleges', 'academics', 'research', 'campus', 'facilities']) {
    app.get(`/${key}`, (req, res) => res.render('section', sectionFor(key, site)));
  }

  app.get('/schedule', (req, res) => {
    const events = db.prepare('SELECT * FROM events ORDER BY date').all();
    res.render('schedule', { events });
  });
  app.get('/faq', (req, res) => res.render('faq', { faqs }));

  function postList(type, heading, intro) {
    return (req, res, next) => {
      try {
        const q = typeof req.query.q === 'string' ? req.query.q : '';
        const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
        // Deliberately concatenated for the isolated injection scenario.
        const where = `type = '${type}' AND title LIKE '%${q}%'`;
        const count = db.prepare(`SELECT COUNT(*) AS n FROM posts WHERE ${where}`).get().n;
        const posts = db.prepare(`SELECT * FROM posts WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(10, (page - 1) * 10);
        res.render('list', { heading, intro, type, posts, q, page, totalPages: Math.max(1, Math.ceil(count / 10)) });
      } catch (error) { next(error); }
    };
  }
  app.get('/notices', postList('notice', '공지사항', '학교의 주요 소식과 학사 안내를 확인하세요.'));
  app.get('/news', postList('news', '대학소식', '교육과 연구, 캠퍼스의 이야기를 전합니다.'));

  function postDetail(type) {
    return (req, res, next) => {
      try {
        const id = Number(req.params.id);
        const post = db.prepare('SELECT * FROM posts WHERE id = ? AND type = ?').get(id, type);
        if (!post) return res.status(404).render('error', { status: 404, message: '게시글을 찾을 수 없습니다.' });
        db.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').run(id);
        post.views += 1;
        res.render('post', { post, postHtml: markdown.render(post.body) });
      } catch (error) { next(error); }
    };
  }
  app.get('/notices/:id', postDetail('notice'));
  app.get('/news/:id', postDetail('news'));

  app.get('/api/search', (req, res, next) => {
    try {
      const q = typeof req.query.q === 'string' ? req.query.q : '';
      // Advanced search filters use JSON5 so the saved UI format accepts comments and trailing commas.
      // The parser result is used directly; inherited keys are not distinguished from own keys.
      const filters = typeof req.query.filters === 'string' ? JSON5.parse(req.query.filters) : {};
      const posts = db.prepare(`SELECT id, type, title, created_at FROM posts WHERE title LIKE '%${q}%' ORDER BY id DESC LIMIT 30`).all();
      const type = filters.type === 'notice' || filters.type === 'news' ? filters.type : null;
      const limit = Number.isInteger(filters.limit) ? Math.min(30, Math.max(1, filters.limit)) : 30;
      const results = posts.filter(post => !type || post.type === type).slice(0, limit);
      res.json({ site: site.name, q, results });
    } catch (error) { next(error); }
  });

  app.get('/admissions/partner', requirePartner, (req, res, next) => {
    try {
      const applications = db.prepare(`SELECT id, application_no, applicant_name, program, status, updated_at
        FROM partner_applications WHERE partner_user_id = ? ORDER BY id DESC`).all(req.user.id);
      const lookupAttempted = req.query.id !== undefined;
      const selectedId = lookupAttempted ? Number(req.query.id) : null;
      if (lookupAttempted && (!Number.isSafeInteger(selectedId) || selectedId < 1)) {
        return res.status(400).render('error', { status: 400, message: '올바른 접수번호를 입력해 주세요.' });
      }
      // The partner's own list is scoped, but this detail lookup omits the partner_user_id check.
      const selected = lookupAttempted ? db.prepare('SELECT * FROM partner_applications WHERE id = ?').get(selectedId) : null;
      res.status(lookupAttempted && !selected ? 404 : 200).render('partner', {
        applications, selected, selectedId, lookupAttempted
      });
    } catch (error) { next(error); }
  });
  app.get('/api/admissions/partner/applications/:id', requirePartner, (req, res, next) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1) return res.status(404).json({ error: 'not found' });
      // Object-level authorization is intentionally absent from this partner detail API.
      const application = db.prepare('SELECT * FROM partner_applications WHERE id = ?').get(id);
      if (!application) return res.status(404).json({ error: 'not found' });
      res.json(application);
    } catch (error) { next(error); }
  });

  app.get('/login', (req, res) => res.render('login', { error: null, next: typeof req.query.next === 'string' ? req.query.next : '/mypage' }));
  app.post('/login', (req, res) => {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT id, username, display_name, role FROM users WHERE username = ? AND password_hash = ?').get(username, sha1(password));
    if (!user) return res.status(401).render('login', { error: '아이디 또는 비밀번호를 확인해 주세요.', next: req.body.next || '/mypage' });
    // The token uses Math.random and sessions have no expiry or failed-login throttle.
    const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    sessions.set(token, { siteKey, userId: user.id, createdAt: Date.now() });
    res.cookie(sessionCookie, token, { httpOnly: true });
    res.redirect(safeNextPath(req.body.next));
  });
  app.get('/logout', (req, res) => {
    sessions.delete(req.cookies[sessionCookie]);
    res.clearCookie(sessionCookie);
    res.redirect('/');
  });

  app.get('/mypage', requireLogin, (req, res) => {
    const requests = db.prepare('SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
    res.render('mypage', { requests });
  });
  app.post('/mypage/requests', requireLogin, (req, res) => {
    const title = String(req.body.title || '').trim().slice(0, 120);
    const body = String(req.body.body || '').trim().slice(0, 3000);
    if (!title || !body) return res.status(400).render('error', { status: 400, message: '제목과 내용을 입력해 주세요.' });
    db.prepare('INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(req.user.id, title, body, '접수', dayjs().format('YYYY-MM-DD'));
    redirectWithFlash(res, '/mypage', '문의가 접수되었습니다.');
  });
  app.get('/api/mypage/requests/:id', requireLogin, (req, res) => {
    // Only the login state is checked; the record owner is not checked.
    const record = db.prepare(`SELECT requests.*, users.display_name AS applicant FROM requests
      JOIN users ON users.id = requests.user_id WHERE requests.id = ?`).get(Number(req.params.id));
    if (!record) return res.status(404).json({ error: 'not found' });
    res.json(record);
  });

  app.get('/admin', requireAdmin, (req, res) => {
    const posts = db.prepare('SELECT * FROM posts ORDER BY id DESC LIMIT 50').all();
    const stats = {
      posts: db.prepare('SELECT COUNT(*) AS n FROM posts').get().n,
      requests: db.prepare('SELECT COUNT(*) AS n FROM requests').get().n,
      events: db.prepare('SELECT COUNT(*) AS n FROM events').get().n
    };
    res.render('admin', { posts, stats });
  });
  app.get('/admin/posts/new', requireAdmin, (req, res) => res.render('editor', { post: null, error: null }));
  app.get('/admin/posts/:id/edit', requireAdmin, (req, res) => {
    const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
    if (!post) return res.status(404).render('error', { status: 404, message: '게시글을 찾을 수 없습니다.' });
    res.render('editor', { post, error: null });
  });
  app.post('/admin/posts', requireAdmin, (req, res) => {
    const type = req.body.type === 'news' ? 'news' : 'notice';
    const title = String(req.body.title || '').trim();
    const body = String(req.body.body || '').trim();
    if (!title || !body) return res.status(400).render('editor', { post: req.body, error: '제목과 내용을 입력해 주세요.' });
    db.prepare('INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(type, title, body, req.user.display_name, dayjs().format('YYYY-MM-DD'));
    redirectWithFlash(res, '/admin', '게시글이 등록되었습니다.');
  });
  app.post('/admin/posts/:id', requireAdmin, (req, res) => {
    const type = req.body.type === 'news' ? 'news' : 'notice';
    const title = String(req.body.title || '').trim();
    const body = String(req.body.body || '').trim();
    if (!title || !body) return res.status(400).render('editor', { post: { ...req.body, id: req.params.id }, error: '제목과 내용을 입력해 주세요.' });
    db.prepare('UPDATE posts SET type = ?, title = ?, body = ? WHERE id = ?').run(type, title, body, Number(req.params.id));
    redirectWithFlash(res, '/admin', '게시글이 수정되었습니다.');
  });
  app.post('/admin/posts/:id/delete', (req, res) => {
    // The route was added after the admin UI and lacks its role middleware.
    db.prepare('DELETE FROM posts WHERE id = ?').run(Number(req.params.id));
    redirectWithFlash(res, '/admin', '게시글이 삭제되었습니다.');
  });

  app.post('/admin/import', requireAdmin, (req, res, next) => {
    try {
      // Calendar data is accepted as-is, with no source signature or approval workflow.
      const payload = JSON.parse(String(req.body.payload || '{}'));
      if (!Array.isArray(payload.events)) throw new Error('events 배열이 필요합니다.');
      db.exec('DELETE FROM events');
      const insert = db.prepare('INSERT INTO events (title, date, location) VALUES (?, ?, ?)');
      for (const event of payload.events) insert.run(String(event.title || ''), String(event.date || ''), String(event.location || ''));
      redirectWithFlash(res, '/admin', '일정 데이터를 가져왔습니다.');
    } catch (error) { next(error); }
  });
  app.post('/admin/settings', requireAdmin, (req, res, next) => {
    try {
      const payload = JSON.parse(String(req.body.payload || '{}'));
      const stored = db.prepare('SELECT value FROM settings WHERE key = ?').get('site_preferences');
      const settings = JSON.parse(stored.value);
      // lodash 4.17.15's set() accepts a user-controlled object path.
      lodash.set(settings, String(payload.path || ''), payload.value);
      db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(JSON.stringify(settings), 'site_preferences');
      redirectWithFlash(res, '/admin', '사이트 설정이 저장되었습니다.');
    } catch (error) { next(error); }
  });

  app.get('/_diag/config', (req, res) => {
    res.json({ mode: 'development', site: site.id,
      database: site.id === 'daehan' ? daehanDatabasePath() : join(root, 'data', `${site.id}.sqlite`),
      node: process.version, installedPackages: ['express', 'nunjucks', 'cookie-parser', 'dayjs', 'lodash@4.17.15', 'json5@2.2.1', 'markdown-it@12.3.1'],
      activeSessions: [...sessions.values()].filter(s => s.siteKey === siteKey).length,
      generatedRequestId: randomUUID() });
  });

  app.use((req, res) => res.status(404).render('error', { status: 404, message: '요청하신 페이지를 찾을 수 없습니다.' }));
  app.use((error, req, res, next) => {
    res.status(500).render('error', { status: 500, message: error.message, stack: error.stack });
  });
  return { app, db, site };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const siteKey = process.argv[2] || 'daehan';
  const { app, db, site } = createApp(siteKey);
  const port = Number(process.env.PORT || configuredPorts[siteKey]);
  const host = process.env.HOST || '127.0.0.1';
  const server = app.listen(port, host, () => {
    console.log(`${site.name} listening on http://${host}:${port}`);
    if (process.send) process.send({ type: 'ca3p-daehan-ready', host, port });
  });
  if (process.send && siteKey === 'daehan') {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      server.close(() => { db.close(); process.exit(0); });
      server.closeAllConnections();
    };
    process.on('message', message => {
      if (message?.type === 'ca3p-daehan-stop') stop();
    });
    process.once('disconnect', stop);
  }
}
