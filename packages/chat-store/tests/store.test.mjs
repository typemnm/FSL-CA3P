import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm, stat, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { CHAT_STORE_LIMITS, createChatRepository } from '../index.mjs';

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-chat-store-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, path: join(directory, 'private', 'chat.sqlite') };
}
function error(code, status) { return failure => failure.code === code && failure.status === status; }

test('owner isolation applies to reads and every mutation; deletes cascade and persist across restart', async t => {
  const { path } = await temporary(t); let repository = createChatRepository({ path, clock: () => 1_800_000_000_000 });
  const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' });
  const message = repository.appendMessage('alice', session.id, { role: 'user', content: '첫 대화' });
  assert.equal(message.sequence, 1);
  assert.deepEqual(repository.listSessions('bob'), []);
  for (const attempt of [
    () => repository.getSession('bob', session.id),
    () => repository.updateSession('bob', session.id, { title: '도용' }),
    () => repository.appendMessage('bob', session.id, { role: 'assistant', content: '도용' }),
    () => repository.updateMessage('bob', session.id, message.id, { content: '도용' }),
    () => repository.compactSession('bob', session.id, { summary: '도용', throughSequence: 1 }),
    () => repository.deleteSession('bob', session.id),
  ]) assert.throws(attempt, error('CHAT_SESSION_NOT_FOUND', 404));
  repository.updateSession('alice', session.id, { title: '테스트', modelId: 'deepseek-reasoner' });
  repository.close(); repository.close();
  repository = createChatRepository({ path }); t.after(() => repository.close());
  const restored = repository.getSession('alice', session.id);
  assert.equal(restored.title, '테스트'); assert.equal(restored.modelId, 'deepseek-reasoner');
  assert.equal(restored.messages[0].content, '첫 대화');
  assert.equal(repository.listSessions('alice')[0].messageCount, 1);
  assert.equal(repository.listSessions('alice')[0].lastMessagePreview, '첫 대화');
  repository.deleteSession('alice', session.id);
  assert.throws(() => repository.getSession('alice', session.id), error('CHAT_SESSION_NOT_FOUND', 404));
  repository.close();
  const db = new DatabaseSync(path);
  assert.equal(db.prepare('SELECT count(*) AS count FROM chat_messages').get().count, 0); db.close();
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(path, '..'))).mode & 0o777, 0o700);
});

test('restart cancels an interrupted pending reply without replay and preserves safe usage metadata', async t => {
  const { path } = await temporary(t); let repository = createChatRepository({ path });
  const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' });
  repository.appendMessage('alice', session.id, { role: 'user', content: '질문' });
  const reply = repository.appendMessage('alice', session.id, { role: 'assistant', content: '부분 답변', status: 'pending',
    metadata: { authorization: 'Bearer sensitive', apiKey: 'sensitive', usage: { inputTokens: 42 }, note: 'Bearer sensitive' } });
  repository.close(); repository = createChatRepository({ path }); t.after(() => repository.close());
  const restored = repository.getSession('alice', session.id);
  assert.equal(restored.messages.length, 2);
  assert.equal(restored.messages[1].id, reply.id); assert.equal(restored.messages[1].content, '부분 답변');
  assert.equal(restored.messages[1].status, 'cancelled');
  assert.equal(restored.messages[1].metadata.interruption, 'server_restarted');
  assert.equal(restored.messages[1].metadata.authorization, '[REDACTED]');
  assert.equal(restored.messages[1].metadata.apiKey, '[REDACTED]');
  assert.equal(restored.messages[1].metadata.usage.inputTokens, 42);
  assert.equal(restored.messages[1].metadata.note, 'Bearer [REDACTED]');
});

test('compaction has monotonic boundaries, keeps the full transcript, and cannot include pending replies', () => {
  const repository = createChatRepository({ path: ':memory:' });
  try {
    const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' });
    const first = repository.appendMessage('alice', session.id, { role: 'user', content: '질문' });
    const second = repository.appendMessage('alice', session.id, { role: 'assistant', content: '', status: 'pending' });
    assert.throws(() => repository.compactSession('alice', session.id, { summary: '중간 요약', throughSequence: 2 }), error('CHAT_MESSAGE_PENDING', 409));
    repository.updateMessage('alice', session.id, second.id, { content: '답변', status: 'completed' });
    const compacted = repository.compactSession('alice', session.id, { summary: '질문과 답변 요약', throughSequence: 2 });
    assert.equal(compacted.compactionCount, 1); assert.equal(compacted.compactedThroughSequence, 2);
    assert.equal(compacted.messages.length, 2); assert.equal(compacted.messages[0].id, first.id);
    assert.throws(() => repository.updateMessage('alice', session.id, first.id, { content: '변조' }), error('CHAT_MESSAGE_COMPACTED', 409));
    for (const throughSequence of [1, 2, 3]) assert.throws(() => repository.compactSession('alice', session.id, { summary: '요약', throughSequence }), error('INVALID_CHAT_COMPACTION', 409));
    assert.equal(repository.appendMessage('alice', session.id, { role: 'user', content: '추가 질문' }).sequence, 3);
  } finally { repository.close(); }
});

test('interrupted generation with maximum-size metadata can still recover on restart', async t => {
  const { path } = await temporary(t); let repository = createChatRepository({ path });
  const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' });
  const overhead = Buffer.byteLength(JSON.stringify({ payload: '' }));
  repository.appendMessage('alice', session.id, { role: 'assistant', content: '', status: 'pending',
    metadata: { payload: 'x'.repeat(CHAT_STORE_LIMITS.metadataBytes - overhead) } });
  repository.close(); repository = createChatRepository({ path }); t.after(() => repository.close());
  const message = repository.getSession('alice', session.id).messages[0];
  assert.equal(message.status, 'cancelled'); assert.equal(message.metadata.interruption, 'server_restarted');
  assert.equal(message.metadata.previousMetadataOmitted, true);
});

test('foreign, unversioned nonempty, future and partial schema databases are rejected without modifying their bytes', async t => {
  const { directory } = await temporary(t);
  for (const [name, ddl] of [
    ['foreign', 'CREATE TABLE users(id INTEGER PRIMARY KEY,secret TEXT); INSERT INTO users(secret) VALUES(\'keep\');'],
    ['unversioned-chat', 'CREATE TABLE chat_sessions(id TEXT PRIMARY KEY);'],
    ['future', 'CREATE TABLE chat_sessions(id TEXT); PRAGMA user_version=2;'],
    ['partial', 'CREATE TABLE chat_sessions(id TEXT); CREATE TABLE chat_messages(id TEXT); PRAGMA user_version=1;'],
  ]) {
    const path = join(directory, `${name}.sqlite`); const db = new DatabaseSync(path); db.exec(ddl); db.close();
    const before = await readFile(path);
    assert.throws(() => createChatRepository({ path }), error('UNSUPPORTED_CHAT_STORE_SCHEMA', 503));
    assert.deepEqual(await readFile(path), before, name);
  }
});

test('a valid store with a foreign table or trigger is rejected rather than silently adopted', async t => {
  const { path } = await temporary(t); const repository = createChatRepository({ path }); repository.close();
  const db = new DatabaseSync(path); db.exec('CREATE TABLE runs(id TEXT);'); db.close();
  assert.throws(() => createChatRepository({ path }), error('UNSUPPORTED_CHAT_STORE_SCHEMA', 503));
});

test('parallel writers allocate unique sequences and keep all messages', async t => {
  const { path } = await temporary(t); const repository = createChatRepository({ path });
  const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' }); repository.close();
  const module = new URL('../index.mjs', import.meta.url).href;
  const code = `const{workerData,parentPort}=require('node:worker_threads'); import(workerData.module).then(({createChatRepository})=>{
    const r=createChatRepository({path:workerData.path});for(let i=0;i<25;i++)r.appendMessage('alice',workerData.id,{role:'user',content:workerData.worker+':'+i});r.close();parentPort.postMessage('done');
  }).catch(e=>{throw e});`;
  await Promise.all(Array.from({ length: 4 }, (_, worker) => new Promise((done, fail) => {
    const thread = new Worker(code, { eval: true, workerData: { module, path, id: session.id, worker } });
    thread.once('error', fail); thread.once('exit', status => status === 0 ? done() : fail(new Error(`Worker exited ${status}`)));
  })));
  const reopened = createChatRepository({ path }); t.after(() => reopened.close());
  const messages = reopened.getSession('alice', session.id).messages;
  assert.deepEqual(messages.map(item => item.sequence), Array.from({ length: 100 }, (_, index) => index + 1));
  assert.equal(new Set(messages.map(item => item.content)).size, 100);
});

test('bounded and validated input cannot inject ownership or sequence changes; message cap is atomic', () => {
  const repository = createChatRepository({ path: ':memory:' });
  try {
    const session = repository.createSession({ owner: 'alice', modelId: 'deepseek-chat' });
    assert.throws(() => repository.getSession('alice', '../path'), error('INVALID_CHAT_ID', 400));
    assert.throws(() => repository.updateSession('alice', session.id, { owner: 'bob' }), error('INVALID_CHAT_INPUT', 400));
    assert.throws(() => repository.updateSession('alice', session.id, { title: 'x'.repeat(161) }), error('INVALID_CHAT_INPUT', 400));
    assert.throws(() => repository.appendMessage('alice', session.id, { role: 'user', content: 'x'.repeat(CHAT_STORE_LIMITS.content + 1) }), error('INVALID_CHAT_INPUT', 400));
    for (const metadata of [{ impossible: Infinity }, { nested: undefined }, { oversized: 'x'.repeat(40_000) }, new Date()]) {
      assert.throws(() => repository.appendMessage('alice', session.id, { role: 'user', content: 'x', metadata }), error('INVALID_CHAT_METADATA', 400));
    }
    for (let index = 0; index < CHAT_STORE_LIMITS.messages; index += 1) repository.appendMessage('alice', session.id, { role: 'user', content: 'x' });
    assert.throws(() => repository.appendMessage('alice', session.id, { role: 'user', content: 'overflow' }), error('CHAT_SESSION_FULL', 409));
    assert.equal(repository.getSession('alice', session.id).messages.length, 1000);
  } finally { repository.close(); }
});

test('database and sidecar symlinks are refused before SQLite opens a target', async t => {
  const { directory } = await temporary(t); const target = join(directory, 'target.sqlite'); const db = new DatabaseSync(target); db.close();
  const path = join(directory, 'link.sqlite'); await symlink(target, path);
  assert.throws(() => createChatRepository({ path }), error('UNSAFE_CHAT_STORE_PATH', 503));
  await symlink(join(directory, 'missing'), join(directory, 'dangling.sqlite'));
  assert.throws(() => createChatRepository({ path: join(directory, 'dangling.sqlite') }), error('UNSAFE_CHAT_STORE_PATH', 503));
});
