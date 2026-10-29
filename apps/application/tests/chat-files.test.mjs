import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { CHAT_FILE_LIMITS, createChatFiles } from '../chat-files.mjs';

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'ca3p-chat-files-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, files: createChatFiles({ root }) };
}
const forbidden = failure => failure.status === 403 && failure.code === 'CHAT_FILE_FORBIDDEN';

test('lists only source and document files with relative paths and reads nested UTF-8 source', async t => {
  const { root, files } = await workspace(t);
  await mkdir(join(root, 'src')); await mkdir(join(root, 'src', 'src'));
  await writeFile(join(root, 'src', 'src', 'index.mjs'), 'export const 인사 = "안녕";');
  await writeFile(join(root, 'README.md'), '# 문서'); await writeFile(join(root, 'Dockerfile'), 'FROM node:24');
  await writeFile(join(root, 'picture.png'), 'not source');
  const listed = await files.list();
  assert.equal(listed.rootLabel, '프로젝트 작업 폴더'); assert.equal(listed.path, '');
  assert.deepEqual(listed.entries.map(entry => entry.name), ['src', 'Dockerfile', 'README.md']);
  const read = await files.read('src/src/index.mjs');
  assert.equal(read.path, 'src/src/index.mjs'); assert.equal(read.content, 'export const 인사 = "안녕";');
  assert.equal(read.language, 'javascript'); assert.equal(read.truncated, false);
  assert.equal(JSON.stringify(listed).includes(root), false); assert.equal(JSON.stringify(read).includes(root), false);
});

test('rejects traversal, absolute paths and credential/runtime directories before reading', async t => {
  const { root, files } = await workspace(t);
  for (const name of ['.env', '.env.example', 'production.env.json', 'auth.json', 'access.txt', 'credentials.json', 'private-key.txt', 'api-key.json', 'private.pem']) await writeFile(join(root, name), 'private value');
  for (const directory of ['.git', '.runtime', 'node_modules', 'data', 'reports', 'private']) {
    await mkdir(join(root, directory)); await writeFile(join(root, directory, 'safe-name.md'), 'private value');
  }
  assert.deepEqual((await files.list()).entries, []);
  for (const path of ['../outside.md', '/etc/passwd', 'C:/secrets.txt', 'src\\file.js', '.', './README.md', 'src//file.md',
    '.env', '.env.example', 'production.env.json', 'auth.json', 'access.txt', 'credentials.json', 'private-key.txt', 'api-key.json', 'private.pem',
    '.runtime/safe-name.md', '.git/safe-name.md', 'node_modules/safe-name.md', 'data/safe-name.md', 'reports/safe-name.md', 'private/safe-name.md']) {
    await assert.rejects(files.read(path), forbidden, path);
  }
  await assert.rejects(files.list('..'), forbidden);
  await assert.rejects(files.read('missing.md'), failure => failure.status === 404 && !failure.message.includes(root));
});

test('symlinks to files or directories and hard-linked host files cannot leave the root', async t => {
  const { root, files } = await workspace(t);
  const outside = await mkdtemp(join(tmpdir(), 'ca3p-chat-outside-')); t.after(() => rm(outside, { recursive: true, force: true }));
  await writeFile(join(outside, 'private.md'), 'private content');
  await symlink(join(outside, 'private.md'), join(root, 'linked.md'));
  await symlink(outside, join(root, 'external'));
  await link(join(outside, 'private.md'), join(root, 'hardlinked.md'));
  assert.deepEqual((await files.list()).entries, []);
  for (const path of ['linked.md', 'external/private.md', 'hardlinked.md']) await assert.rejects(files.read(path), forbidden);
  await assert.rejects(files.list('external'), forbidden);
  const alias = join(outside, 'root-alias'); await symlink(root, alias);
  await assert.rejects(createChatFiles({ root: alias }).list(), forbidden);
});

test('reads are bounded, preserve full-file SHA-256 and size, and refuse oversized/binary/non-UTF8 inputs', async t => {
  const { root, files } = await workspace(t);
  const content = '가'.repeat(5000); await writeFile(join(root, 'within.md'), content);
  const whole = await files.read('within.md'); assert.equal(whole.truncated, false); assert.equal(whole.size, Buffer.byteLength(content));
  const long = '😀'.repeat(5000); await writeFile(join(root, 'long.md'), long);
  const truncated = await files.read('long.md'); assert.equal(truncated.truncated, true); assert.equal(truncated.content.length, CHAT_FILE_LIMITS.text);
  assert.equal(truncated.sha256, createHash('sha256').update(long).digest('hex')); assert.equal(truncated.size, Buffer.byteLength(long));
  await writeFile(join(root, 'too-big.md'), 'x'.repeat(CHAT_FILE_LIMITS.bytes + 1));
  await assert.rejects(files.read('too-big.md'), failure => failure.status === 413);
  await writeFile(join(root, 'binary.txt'), Buffer.from([65, 0, 66]));
  await assert.rejects(files.read('binary.txt'), failure => failure.status === 415);
  await writeFile(join(root, 'encoding.txt'), Buffer.from([0xc3, 0x28]));
  await assert.rejects(files.read('encoding.txt'), failure => failure.status === 415);
});

test('directory listings are capped at 200 safe entries and do not expose unsupported files', async t => {
  const { root, files } = await workspace(t);
  await Promise.all(Array.from({ length: 220 }, (_, index) => writeFile(join(root, `module-${String(index).padStart(3, '0')}.mjs`), 'export {};')));
  const result = await files.list(); assert.equal(result.entries.length, 200);
  assert.equal(result.entries.every(entry => !entry.path.includes('/') && entry.type === 'file'), true);
});
