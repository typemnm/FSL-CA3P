import { DatabaseSync } from 'node:sqlite';
import { chmodSync, closeSync, constants, existsSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { redact } from '../contracts/index.mjs';

export const CHAT_STORE_SCHEMA_VERSION = 1;
export const CHAT_STORE_TABLES = Object.freeze(['chat_sessions', 'chat_messages']);
export const DEFAULT_CHAT_STORE_PATH = resolve(process.env.CA3P_CHAT_DB_PATH
  ?? fileURLToPath(new URL('../../.runtime/chat.sqlite', import.meta.url)));
export const CHAT_STORE_LIMITS = Object.freeze({ title: 160, content: 128_000, metadataBytes: 32_768, summary: 32_000, messages: 1000 });

const fault = (code, message, status = 400) => Object.assign(new Error(message), { code, status });
const unsupported = () => fault('UNSUPPORTED_CHAT_STORE_SCHEMA', '지원하지 않는 채팅 저장소입니다. 기존 데이터베이스는 변경하지 않았습니다.', 503);
const roles = new Set(['user', 'assistant', 'system', 'tool']);
const statuses = new Set(['completed', 'pending', 'failed', 'cancelled']);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function ownerValue(owner) {
  if (typeof owner !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/u.test(owner)) {
    throw fault('INVALID_CHAT_OWNER', '채팅 사용자 정보가 올바르지 않습니다.');
  }
  return owner;
}
function identifier(value) {
  if (typeof value !== 'string' || !uuid.test(value)) throw fault('INVALID_CHAT_ID', '채팅 식별자가 올바르지 않습니다.');
  return value;
}
function textValue(value, label, maximum, { empty = true } = {}) {
  if (typeof value !== 'string' || value.length > maximum || Buffer.byteLength(value, 'utf8') > maximum * 4
    || value.includes('\0') || (!empty && !value.trim())) {
    throw fault('INVALID_CHAT_INPUT', `${label} 형식 또는 길이가 올바르지 않습니다.`);
  }
  return value;
}
function titleValue(value) { return textValue(value, '대화 제목', CHAT_STORE_LIMITS.title, { empty: false }).trim(); }
function modelValue(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,159}$/u.test(value)) {
    throw fault('INVALID_CHAT_MODEL', '모델 식별자가 올바르지 않습니다.');
  }
  return value;
}
function metadataValue(value) {
  let nodes = 0;
  const seen = new Set();
  function visit(entry, depth) {
    if (++nodes > 3000 || depth > 12) throw fault('INVALID_CHAT_METADATA', '메시지 메타데이터가 너무 복잡합니다.');
    if (entry === null || typeof entry === 'boolean' || typeof entry === 'string') return;
    if (typeof entry === 'number' && Number.isFinite(entry)) return;
    if (!entry || typeof entry !== 'object' || seen.has(entry)
      || (!Array.isArray(entry) && Object.getPrototypeOf(entry) !== Object.prototype && Object.getPrototypeOf(entry) !== null)) {
      throw fault('INVALID_CHAT_METADATA', '메시지 메타데이터는 JSON 객체여야 합니다.');
    }
    seen.add(entry);
    for (const [key, child] of Object.entries(entry)) {
      if (key.length > 160 || ['__proto__', 'constructor', 'prototype'].includes(key)) throw fault('INVALID_CHAT_METADATA', '메타데이터 키가 올바르지 않습니다.');
      visit(child, depth + 1);
    }
    seen.delete(entry);
  }
  if (!value || Array.isArray(value) || typeof value !== 'object') throw fault('INVALID_CHAT_METADATA', '메시지 메타데이터는 JSON 객체여야 합니다.');
  visit(value, 0);
  const serialized = JSON.stringify(redact(value));
  if (Buffer.byteLength(serialized, 'utf8') > CHAT_STORE_LIMITS.metadataBytes) throw fault('INVALID_CHAT_METADATA', '메시지 메타데이터가 너무 큽니다.');
  return serialized;
}
function statusValue(value) {
  if (!statuses.has(value)) throw fault('INVALID_CHAT_STATUS', '메시지 상태가 올바르지 않습니다.');
  return value;
}

const schema = `
  CREATE TABLE chat_sessions (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, model_id TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '', compacted_through_sequence INTEGER NOT NULL DEFAULT 0,
    compaction_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE INDEX chat_sessions_owner_idx ON chat_sessions(owner, updated_at);
  CREATE TABLE chat_messages (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, status TEXT NOT NULL,
    metadata_json TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(session_id, sequence));
  PRAGMA user_version=1;`;
const columns = {
  chat_sessions: ['id:TEXT:0:1', 'owner:TEXT:1:0', 'title:TEXT:1:0', 'model_id:TEXT:1:0', 'summary:TEXT:1:0',
    'compacted_through_sequence:INTEGER:1:0', 'compaction_count:INTEGER:1:0', 'created_at:TEXT:1:0', 'updated_at:TEXT:1:0'],
  chat_messages: ['id:TEXT:0:1', 'session_id:TEXT:1:0', 'sequence:INTEGER:1:0', 'role:TEXT:1:0', 'content:TEXT:1:0',
    'status:TEXT:1:0', 'metadata_json:TEXT:1:0', 'created_at:TEXT:1:0'],
};
function assertSchema(db) {
  const version = db.prepare('PRAGMA user_version').get().user_version;
  const objects = db.prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").all();
  if (version === 0 && !objects.length) { db.exec(schema); return; }
  if (version !== CHAT_STORE_SCHEMA_VERSION
    || objects.filter(item => item.type === 'table').map(item => item.name).sort().join(',') !== [...CHAT_STORE_TABLES].sort().join(',')
    || objects.some(item => !['table', 'index'].includes(item.type) || (item.type === 'index' && item.name !== 'chat_sessions_owner_idx'))) throw unsupported();
  for (const table of CHAT_STORE_TABLES) {
    const actual = db.prepare(`PRAGMA table_info(${table})`).all().map(item => `${item.name}:${item.type}:${item.notnull}:${item.pk}`);
    if (JSON.stringify(actual) !== JSON.stringify(columns[table])) throw unsupported();
  }
  const foreignKeys = db.prepare('PRAGMA foreign_key_list(chat_messages)').all();
  const uniqueSequences = db.prepare('PRAGMA index_list(chat_messages)').all().filter(item => item.unique)
    .some(item => db.prepare(`PRAGMA index_info('${item.name.replaceAll("'", "''")}')`).all().map(column => column.name).join(',') === 'session_id,sequence');
  if (foreignKeys.length !== 1 || foreignKeys[0].table !== 'chat_sessions' || foreignKeys[0].from !== 'session_id'
    || foreignKeys[0].to !== 'id' || foreignKeys[0].on_delete !== 'CASCADE' || !uniqueSequences) throw unsupported();
}

/** Separate private store: deployment backups must include both CHAT_STORE_TABLES and SQLite sidecars. */
export function createChatRepository({ path = DEFAULT_CHAT_STORE_PATH, clock = Date.now } = {}) {
  const storePath = path === ':memory:' ? path : resolve(path);
  if (storePath !== ':memory:') {
    const parent = dirname(storePath);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    if (lstatSync(parent).isSymbolicLink()) throw fault('UNSAFE_CHAT_STORE_PATH', '채팅 저장소 경로에 링크를 사용할 수 없습니다.', 503);
    for (const suffix of ['', '-wal', '-shm', '-journal']) {
      const candidate = `${storePath}${suffix}`;
      let entry;
      try { entry = lstatSync(candidate); } catch (failure) { if (failure.code !== 'ENOENT') throw failure; }
      if (entry && (!entry.isFile() || entry.isSymbolicLink() || entry.nlink > 1)) {
        throw fault('UNSAFE_CHAT_STORE_PATH', '채팅 저장소 경로에 링크 또는 일반 파일이 아닌 항목이 있습니다.', 503);
      }
    }
    // SQLite has no creation-mode option. Create its empty file privately before it opens.
    if (!existsSync(storePath)) closeSync(openSync(storePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600));
  }
  const db = new DatabaseSync(storePath);
  let closed = false;
  function transaction(fn, { read = false } = {}) {
    if (closed) throw fault('CHAT_STORE_CLOSED', '채팅 저장소가 닫혀 있습니다.', 503);
    db.exec(read ? 'BEGIN' : 'BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (failure) { db.exec('ROLLBACK'); throw failure; }
  }
  const timestamp = () => new Date(clock()).toISOString();
  try {
    db.exec('PRAGMA busy_timeout=5000');
    // Inspect identity and columns in the same transaction. Never repair a foreign store.
    transaction(() => assertSchema(db));
    db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON;');
    if (storePath !== ':memory:') {
      chmodSync(dirname(storePath), 0o700);
      for (const suffix of ['', '-wal', '-shm']) if (existsSync(`${storePath}${suffix}`)) chmodSync(`${storePath}${suffix}`, 0o600);
    }
    // An interrupted generation is visible as cancelled and is never replayed.
    transaction(() => {
      const interrupted = db.prepare("SELECT DISTINCT session_id FROM chat_messages WHERE status='pending'").all();
      const pending = db.prepare("SELECT id,metadata_json FROM chat_messages WHERE status='pending'").all();
      for (const message of pending) {
        const metadata = { ...JSON.parse(message.metadata_json), interruption: 'server_restarted' };
        // Recovery itself must succeed even when the original metadata filled its allowance.
        const recovered = Buffer.byteLength(JSON.stringify(metadata), 'utf8') > CHAT_STORE_LIMITS.metadataBytes
          ? { interruption: 'server_restarted', previousMetadataOmitted: true } : metadata;
        db.prepare("UPDATE chat_messages SET status='cancelled',metadata_json=? WHERE id=?").run(metadataValue(recovered), message.id);
      }
      for (const session of interrupted) db.prepare('UPDATE chat_sessions SET updated_at=? WHERE id=?').run(timestamp(), session.session_id);
    });
  } catch (failure) { db.close(); throw failure; }

  function sessionRow(owner, id) {
    ownerValue(owner); identifier(id);
    const row = db.prepare('SELECT * FROM chat_sessions WHERE owner=? AND id=?').get(owner, id);
    if (!row) throw fault('CHAT_SESSION_NOT_FOUND', '대화를 찾을 수 없습니다.', 404);
    return row;
  }
  const messageView = row => ({ id: row.id, sequence: row.sequence, role: row.role, content: row.content,
    status: row.status, metadata: JSON.parse(row.metadata_json), createdAt: row.created_at });
  const sessionView = row => ({ id: row.id, title: row.title, modelId: row.model_id, summary: row.summary,
    compactedThroughSequence: row.compacted_through_sequence, compactionCount: row.compaction_count,
    createdAt: row.created_at, updatedAt: row.updated_at });
  function fullSession(row) {
    return { ...sessionView(row), messages: db.prepare('SELECT * FROM chat_messages WHERE session_id=? ORDER BY sequence').all(row.id).map(messageView) };
  }
  return {
    path: storePath,
    listSessions(owner, { limit = 50 } = {}) {
      ownerValue(owner);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw fault('INVALID_CHAT_LIMIT', '대화 목록 개수는 1~200이어야 합니다.');
      return transaction(() => db.prepare(`SELECT s.*,
        (SELECT count(*) FROM chat_messages WHERE session_id=s.id) AS message_count,
        (SELECT substr(content,1,120) FROM chat_messages WHERE session_id=s.id ORDER BY sequence DESC LIMIT 1) AS preview
        FROM chat_sessions s WHERE owner=? ORDER BY updated_at DESC,id DESC LIMIT ?`).all(owner, limit)
        .map(row => ({ ...sessionView(row), messageCount: row.message_count, lastMessagePreview: row.preview ?? '' })), { read: true });
    },
    createSession({ owner, title = '새 대화', modelId }) {
      ownerValue(owner); title = titleValue(title); modelId = modelValue(modelId);
      return transaction(() => {
        const id = randomUUID(); const at = timestamp();
        db.prepare('INSERT INTO chat_sessions(id,owner,title,model_id,created_at,updated_at) VALUES(?,?,?,?,?,?)').run(id, owner, title, modelId, at, at);
        return fullSession(sessionRow(owner, id));
      });
    },
    getSession(owner, id) { return transaction(() => fullSession(sessionRow(owner, id)), { read: true }); },
    updateSession(owner, id, changes = {}) {
      if (!changes || typeof changes !== 'object' || Array.isArray(changes)
        || Object.keys(changes).some(key => !['title', 'modelId'].includes(key))) throw fault('INVALID_CHAT_INPUT', '대화 수정 필드가 올바르지 않습니다.');
      const title = changes.title === undefined ? undefined : titleValue(changes.title);
      const modelId = changes.modelId === undefined ? undefined : modelValue(changes.modelId);
      return transaction(() => {
        const row = sessionRow(owner, id);
        db.prepare('UPDATE chat_sessions SET title=?,model_id=?,updated_at=? WHERE id=?').run(title ?? row.title, modelId ?? row.model_id, timestamp(), id);
        return fullSession(sessionRow(owner, id));
      });
    },
    appendMessage(owner, id, { role, content, status = 'completed', metadata = {} }) {
      if (!roles.has(role)) throw fault('INVALID_CHAT_ROLE', '메시지 역할이 올바르지 않습니다.');
      content = textValue(content, '메시지', CHAT_STORE_LIMITS.content); statusValue(status); const serialized = metadataValue(metadata);
      return transaction(() => {
        sessionRow(owner, id);
        const count = db.prepare('SELECT count(*) AS count,coalesce(max(sequence),0) AS sequence FROM chat_messages WHERE session_id=?').get(id);
        if (count.count >= CHAT_STORE_LIMITS.messages) throw fault('CHAT_SESSION_FULL', '대화 메시지 한도에 도달했습니다. 새 대화를 만들어 주세요.', 409);
        const messageId = randomUUID(); const at = timestamp();
        db.prepare('INSERT INTO chat_messages VALUES(?,?,?,?,?,?,?,?)').run(messageId, id, count.sequence + 1, role, content, status, serialized, at);
        db.prepare('UPDATE chat_sessions SET updated_at=? WHERE id=?').run(at, id);
        return messageView(db.prepare('SELECT * FROM chat_messages WHERE id=?').get(messageId));
      });
    },
    updateMessage(owner, id, messageId, changes = {}) {
      identifier(messageId);
      if (!changes || typeof changes !== 'object' || Array.isArray(changes)
        || Object.keys(changes).some(key => !['content', 'status', 'metadata'].includes(key))) throw fault('INVALID_CHAT_INPUT', '메시지 수정 필드가 올바르지 않습니다.');
      const content = changes.content === undefined ? undefined : textValue(changes.content, '메시지', CHAT_STORE_LIMITS.content);
      const status = changes.status === undefined ? undefined : statusValue(changes.status);
      const metadata = changes.metadata === undefined ? undefined : metadataValue(changes.metadata);
      return transaction(() => {
        const session = sessionRow(owner, id);
        const row = db.prepare('SELECT * FROM chat_messages WHERE session_id=? AND id=?').get(id, messageId);
        if (!row) throw fault('CHAT_MESSAGE_NOT_FOUND', '메시지를 찾을 수 없습니다.', 404);
        if (row.sequence <= session.compacted_through_sequence) throw fault('CHAT_MESSAGE_COMPACTED', '이미 요약된 메시지는 수정할 수 없습니다.', 409);
        db.prepare('UPDATE chat_messages SET content=?,status=?,metadata_json=? WHERE id=?').run(content ?? row.content, status ?? row.status, metadata ?? row.metadata_json, messageId);
        db.prepare('UPDATE chat_sessions SET updated_at=? WHERE id=?').run(timestamp(), id);
        return messageView(db.prepare('SELECT * FROM chat_messages WHERE id=?').get(messageId));
      });
    },
    compactSession(owner, id, { summary, throughSequence }) {
      summary = textValue(summary, '대화 요약', CHAT_STORE_LIMITS.summary, { empty: false });
      if (!Number.isInteger(throughSequence) || throughSequence < 1) throw fault('INVALID_CHAT_COMPACTION', '요약할 메시지 범위가 올바르지 않습니다.');
      return transaction(() => {
        const row = sessionRow(owner, id);
        const latest = db.prepare('SELECT max(sequence) AS sequence FROM chat_messages WHERE session_id=?').get(id).sequence ?? 0;
        if (throughSequence <= row.compacted_through_sequence || throughSequence > latest) throw fault('INVALID_CHAT_COMPACTION', '요약 범위가 이미 처리되었거나 메시지 범위를 벗어났습니다.', 409);
        if (db.prepare("SELECT 1 FROM chat_messages WHERE session_id=? AND sequence<=? AND status='pending'").get(id, throughSequence)) {
          throw fault('CHAT_MESSAGE_PENDING', '응답 생성 중인 메시지는 요약할 수 없습니다.', 409);
        }
        db.prepare('UPDATE chat_sessions SET summary=?,compacted_through_sequence=?,compaction_count=compaction_count+1,updated_at=? WHERE id=?')
          .run(summary, throughSequence, timestamp(), id);
        return fullSession(sessionRow(owner, id));
      });
    },
    deleteSession(owner, id) {
      return transaction(() => { sessionRow(owner, id); db.prepare('DELETE FROM chat_sessions WHERE id=?').run(id); return { deleted: true }; });
    },
    close() { if (!closed) { db.close(); closed = true; } },
  };
}
