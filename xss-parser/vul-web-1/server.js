'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT ?? 3000);
const DATA_FILE = process.env.BOARD_DATA_FILE || path.join(__dirname, 'data', 'posts.json');
const COOKIE_SECRET = process.env.BOARD_COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'board_user';

const USERS = Object.freeze({
  alice: Object.freeze({ id: 'alice', name: '앨리스', role: 'member' }),
  bob: Object.freeze({ id: 'bob', name: '밥', role: 'member' }),
  admin: Object.freeze({ id: 'admin', name: '관리자', role: 'admin' })
});

const STATIC_FILES = Object.freeze({
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' }
});

function initialPosts() {
  const now = Date.now();
  return [
    {
      id: 1,
      title: '게시판에 오신 것을 환영합니다',
      content: '안녕하세요! 이곳은 자유롭게 글을 쓰고 이야기를 나누는 게시판입니다. 첫 글을 남겨 보세요.',
      authorId: 'admin',
      authorName: '관리자',
      createdAt: new Date(now - 1000 * 60 * 60 * 9).toISOString()
    },
    {
      id: 2,
      title: '이용 안내',
      content: '새 글 쓰기 패널에서 글을 작성할 수 있습니다. 작성한 글은 본인 계정에서 삭제할 수 있습니다.',
      authorId: 'admin',
      authorName: '관리자',
      createdAt: new Date(now - 1000 * 60 * 60 * 5).toISOString()
    },
    {
      id: 3,
      title: '오늘의 첫 인사 👋',
      content: '반갑습니다! 여러분의 이야기가 궁금해요.',
      authorId: 'bob',
      authorName: '밥',
      createdAt: new Date(now - 1000 * 60 * 45).toISOString()
    }
  ];
}

function ensureDataFile() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ posts: initialPosts() }, null, 2), 'utf8');
  }
}

function readPosts() {
  const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!data || !Array.isArray(data.posts)) {
    throw new Error('게시글 저장 파일 형식이 올바르지 않습니다.');
  }
  return data.posts;
}

function writePosts(posts) {
  fs.writeFileSync(DATA_FILE, JSON.stringify({ posts }, null, 2), 'utf8');
}

function signedUserCookie(user) {
  const payload = Buffer.from(JSON.stringify(user), 'utf8').toString('base64url');
  const signature = crypto.createHmac('sha256', COOKIE_SECRET).update(payload).digest('base64url');
  return `${COOKIE_NAME}=${payload}.${signature}; Path=/; SameSite=Lax; Max-Age=604800`;
}

function parseUserCookie(req) {
  const cookie = (req.headers.cookie || '')
    .split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(`${COOKIE_NAME}=`));
  if (!cookie) return null;

  const value = cookie.slice(COOKIE_NAME.length + 1);
  const [payload, signature] = value.split('.');
  if (!payload || !signature) return null;

  const expected = crypto.createHmac('sha256', COOKIE_SECRET).update(payload).digest();
  let received;
  try {
    received = Buffer.from(signature, 'base64url');
  } catch {
    return null;
  }
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) return null;

  try {
    const user = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const knownUser = USERS[user.id];
    return knownUser && user.name === knownUser.name && user.role === knownUser.role
      ? knownUser
      : null;
  } catch {
    return null;
  }
}

function currentUser(req, res) {
  const user = parseUserCookie(req);
  if (user) return user;
  res.setHeader('Set-Cookie', signedUserCookie(USERS.alice));
  return USERS.alice;
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 65536) {
      const error = new Error('요청 본문이 너무 큽니다.');
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('올바른 JSON이 필요합니다.');
    error.status = 400;
    throw error;
  }
}

async function handleApi(req, res, url) {
  if (url.pathname === '/api/session') {
    if (req.method === 'GET') {
      sendJson(res, 200, { user: currentUser(req, res) });
      return;
    }
    if (req.method === 'POST') {
      const body = await readJson(req);
      const user = body && (body.userId === 'alice' || body.userId === 'bob') ? USERS[body.userId] : null;
      if (!user) {
        sendJson(res, 400, { error: 'alice 또는 bob 계정을 선택해 주세요.' });
        return;
      }
      res.setHeader('Set-Cookie', signedUserCookie(user));
      sendJson(res, 200, { user });
      return;
    }
  }

  if (url.pathname === '/api/posts') {
    const user = currentUser(req, res);
    if (req.method === 'GET') {
      const posts = readPosts().slice().sort((a, b) => b.id - a.id);
      sendJson(res, 200, { posts });
      return;
    }
    if (req.method === 'POST') {
      const body = await readJson(req);
      const title = typeof body?.title === 'string' ? body.title.trim() : '';
      const content = typeof body?.content === 'string' ? body.content.trim() : '';
      if (!title || !content || title.length > 120 || content.length > 10000) {
        sendJson(res, 400, { error: '제목(1~120자)과 내용(1~10000자)을 입력해 주세요.' });
        return;
      }
      const posts = readPosts();
      const post = {
        id: Math.max(0, ...posts.map(item => item.id)) + 1,
        title,
        // 실습용 저장형 XSS: 본문 HTML을 그대로 저장하고 클라이언트가 HTML로 렌더링합니다.
        content,
        authorId: user.id,
        authorName: user.name,
        createdAt: new Date().toISOString()
      };
      posts.push(post);
      writePosts(posts);
      sendJson(res, 201, { post });
      return;
    }
  }

  const postRoute = url.pathname.match(/^\/api\/posts\/(\d+)$/);
  if (postRoute && req.method === 'DELETE') {
    currentUser(req, res);
    const id = Number(postRoute[1]);
    const posts = readPosts();
    const index = posts.findIndex(post => post.id === id);
    if (index < 0) {
      sendJson(res, 404, { error: '게시글을 찾을 수 없습니다.' });
      return;
    }
    const suppliedAuthorId = url.searchParams.get('authorId');
    // 실습용 파라미터 변조 취약점: 쿠키 사용자와 대조하지 않고 요청 파라미터만 신뢰합니다.
    if (!suppliedAuthorId || suppliedAuthorId !== posts[index].authorId) {
      sendJson(res, 403, { error: '삭제 권한이 없습니다.' });
      return;
    }
    posts.splice(index, 1);
    writePosts(posts);
    sendJson(res, 200, { ok: true, deletedId: id });
    return;
  }

  sendJson(res, 404, { error: 'API 경로를 찾을 수 없습니다.' });
}

async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }
    const asset = STATIC_FILES[url.pathname];
    if (!asset || req.method !== 'GET') {
      sendJson(res, 404, { error: '페이지를 찾을 수 없습니다.' });
      return;
    }
    const filePath = path.join(__dirname, 'public', asset.file);
    const content = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': asset.type, 'X-Content-Type-Options': 'nosniff' });
    res.end(content);
  } catch (error) {
    sendJson(res, error.status || 500, { error: error.status ? error.message : '서버 오류가 발생했습니다.' });
    if (!error.status) console.error(error);
  }
}

ensureDataFile();
const server = http.createServer(handler);
server.listen(PORT, HOST, () => {
  const address = server.address();
  console.log(`게시판 실행 중: http://${HOST}:${address.port}`);
});
