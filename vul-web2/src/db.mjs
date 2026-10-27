import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export function sha1(value) {
  return createHash('sha1').update(String(value)).digest('hex');
}

function daysBefore(date, count) {
  const value = new Date(`${date}T12:00:00Z`);
  value.setUTCDate(value.getUTCDate() - count);
  return value.toISOString().slice(0, 10);
}

export function openDatabase(site) {
  const dataDir = join(root, 'data');
  mkdirSync(dataDir, { recursive: true });
  const filename = process.env.LAB_MEMORY_DB === '1' ? ':memory:' : join(dataDir, `${site.id}.sqlite`);
  const db = new DatabaseSync(filename);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL,
      body TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL,
      views INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY, title TEXT NOT NULL, date TEXT NOT NULL, location TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL,
      body TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS partner_applications (
      id INTEGER PRIMARY KEY, partner_user_id INTEGER NOT NULL,
      application_no TEXT UNIQUE NOT NULL, applicant_name TEXT,
      program TEXT, contact TEXT, status TEXT, updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS staff_cases (
      id INTEGER PRIMARY KEY, staff_user_id INTEGER NOT NULL,
      case_no TEXT UNIQUE NOT NULL, student_name TEXT,
      student_no TEXT, category TEXT, contact TEXT, status TEXT,
      note TEXT, updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);

  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
    const insertUser = db.prepare('INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)');
    // Demonstration accounts contain only invented identities and throwaway passwords.
    insertUser.run('admin', '대학 관리자', 'admin', sha1('admin1234'));
    insertUser.run('student1', '김가람', 'student', sha1('Welcome2026'));
    insertUser.run('student2', '이누리', 'student', sha1('Welcome2026'));
  }

  // These fixtures are inserted independently of the original first-run seed so
  // existing Docker volumes receive them without replacing modified local data.
  if (site.id === 'daehan') {
    const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)');
    insertUser.run('partner1', '협력기관 담당자 김해온', 'partner', sha1('Partner2026'));
    insertUser.run('partner2', '협력기관 담당자 이다온', 'partner', sha1('Partner2026'));

    const partner1 = db.prepare('SELECT id FROM users WHERE username = ?').get('partner1');
    const partner2 = db.prepare('SELECT id FROM users WHERE username = ?').get('partner2');
    const insertApplication = db.prepare(`INSERT OR IGNORE INTO partner_applications
      (partner_user_id, application_no, applicant_name, program, contact, status, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`);
    [
      [partner1.id, 'DH-2026-PT-001', '윤하람', '산학협력 추천 전형', 'applicant01@example.invalid', '서류 검토', '2026-10-16'],
      [partner1.id, 'DH-2026-PT-002', '조도윤', '산학협력 추천 전형', 'applicant02@example.invalid', '보완 요청', '2026-10-17'],
      [partner2.id, 'DH-2026-PT-003', '이수빈', '지역협력 추천 전형', 'applicant03@example.invalid', '접수', '2026-10-15'],
      [partner2.id, 'DH-2026-PT-004', '박하린', '지역협력 추천 전형', 'applicant04@example.invalid', '서류 검토', '2026-10-18']
    ].forEach(row => insertApplication.run(...row));
  }

  if (site.id === 'wonchang') {
    const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)');
    insertUser.run('staff1', '학생지원팀 직원 최나래', 'staff', sha1('Staff2026'));
    insertUser.run('staff2', '학생지원팀 직원 정하늘', 'staff', sha1('Staff2026'));

    const staff1 = db.prepare('SELECT id FROM users WHERE username = ?').get('staff1');
    const staff2 = db.prepare('SELECT id FROM users WHERE username = ?').get('staff2');
    const insertCase = db.prepare(`INSERT OR IGNORE INTO staff_cases
      (staff_user_id, case_no, student_name, student_no, category, contact, status, note, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    [
      [staff1.id, 'WC-MOB-2026-001', '한서우', '20260001', '장학 지급 확인', 'case01@example.invalid', '검토 중', '장학 지급 서류의 확인 절차가 진행 중입니다.', '2026-10-16'],
      [staff1.id, 'WC-MOB-2026-002', '강민재', '20260002', '등록금 납부 확인', 'case02@example.invalid', '보완 요청', '제출된 납부 자료의 추가 확인이 필요합니다.', '2026-10-17'],
      [staff2.id, 'WC-MOB-2026-003', '오다인', '20260003', '현장실습 지원', 'case03@example.invalid', '접수', '현장실습 신청 자료를 접수했습니다.', '2026-10-15'],
      [staff2.id, 'WC-MOB-2026-004', '백유진', '20260004', '생활지원 상담', 'case04@example.invalid', '검토 중', '학생지원팀에서 상담 요청을 검토하고 있습니다.', '2026-10-18']
    ].forEach(row => insertCase.run(...row));
  }

  if (db.prepare('SELECT COUNT(*) AS n FROM posts').get().n === 0) {
    const insertPost = db.prepare('INSERT INTO posts (type, title, body, author, created_at) VALUES (?, ?, ?, ?, ?)');
    site.noticeTitles.forEach((title, index) => {
      const content = `${title}\n\n${site.name} 학생과 교직원 여러분께 안내드립니다. 관련 일정과 세부 내용을 확인해 주시기 바랍니다.\n\n대상: ${index % 2 ? '재학생 및 대학원생' : '전체 구성원'}\n문의: 학사지원과 (${site.phone})\n\n원활한 학사 운영을 위해 많은 관심과 협조 부탁드립니다.`;
      insertPost.run('notice', title, content, index % 3 === 0 ? '입학처' : '학사지원과', daysBefore('2026-10-17', index));
    });
    site.newsTitles.forEach((title, index) => {
      const content = `${title}\n\n${site.name}는 교육과 연구의 성과를 지역사회와 함께 나누고 있습니다. 이번 행사는 구성원과 지역 기관이 참여해 새로운 협력 기회를 모색했습니다.\n\n자세한 소식은 대학홍보실로 문의해 주시기 바랍니다.`;
      insertPost.run('news', title, content, '대학홍보실', daysBefore('2026-10-15', index * 3));
    });
  }

  if (db.prepare('SELECT COUNT(*) AS n FROM events').get().n === 0) {
    const insertEvent = db.prepare('INSERT INTO events (title, date, location) VALUES (?, ?, ?)');
    site.events.forEach(([title, date, location]) => insertEvent.run(title, date, location));
  }

  if (db.prepare('SELECT COUNT(*) AS n FROM requests').get().n === 0) {
    const insertRequest = db.prepare('INSERT INTO requests (user_id, title, body, status, created_at) VALUES (?, ?, ?, ?, ?)');
    insertRequest.run(2, '재학증명서 발급 문의', '온라인 증명서 발급 절차를 알고 싶습니다.', '답변 완료', '2026-10-12');
    insertRequest.run(3, '학생생활관 신청 문의', '겨울학기 입사 일정을 확인하고 싶습니다.', '접수', '2026-10-14');
  }

  if (!db.prepare('SELECT key FROM settings WHERE key = ?').get('featured_post_id')) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('featured_post_id', '1');
  }
  if (!db.prepare('SELECT key FROM settings WHERE key = ?').get('site_preferences')) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('site_preferences', JSON.stringify({ theme: { label: site.tagline } }));
  }
  return db;
}
