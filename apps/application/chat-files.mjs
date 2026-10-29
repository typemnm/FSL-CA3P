import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

export const CHAT_FILE_LIMITS = Object.freeze({ bytes: 262_144, text: 8000, entries: 200 });
const defaultRoot = fileURLToPath(new URL('../../', import.meta.url));
const fault = (code, message, status = 400) => Object.assign(new Error(message), { code, status });
const denied = () => fault('CHAT_FILE_FORBIDDEN', '이 파일 또는 폴더는 작업 공간에서 접근할 수 없습니다.', 403);
const unavailable = () => fault('CHAT_FILE_NOT_FOUND', '작업 공간 파일을 찾을 수 없습니다.', 404);
const blockedDirectories = new Set(['node_modules', 'vendor', 'data', 'reports', 'artifacts', 'logs', 'backups', 'backup',
  'dist', 'build', 'coverage', 'venv', 'site-packages', 'private', 'secrets', 'credentials', 'target']);
const allowedExtensions = new Set(['.md', '.mdx', '.txt', '.rst', '.adoc', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.py', '.html', '.htm', '.css', '.scss', '.sass', '.less',
  '.sql', '.sh', '.bash', '.zsh', '.ps1', '.c', '.h', '.cc', '.cpp', '.hpp', '.go', '.rs', '.java', '.kt', '.kts',
  '.swift', '.rb', '.php', '.vue', '.svelte', '.xml', '.graphql', '.gql', '.mermaid']);
const allowedNames = new Set(['dockerfile', 'makefile', 'license', 'notice', 'procfile']);
const languages = { '.md': 'markdown', '.mdx': 'markdown', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.json': 'json', '.yaml': 'yaml',
  '.yml': 'yaml', '.html': 'html', '.htm': 'html', '.css': 'css', '.sql': 'sql', '.sh': 'shell', '.toml': 'toml', '.xml': 'xml' };
function safeName(name) {
  return name && !name.startsWith('.') && !/[\x00-\x1f\x7f\\]/u.test(name)
    && !/(?:^|[._-])env(?:[._-]|$)/iu.test(name)
    && !/^(?:auth|access|credentials?|secrets?|passwords?|tokens?)(?:[._-]|$)/iu.test(name)
    && !/(?:^|[._-])(?:credentials?|secrets?|passwords?|private[-_]?key|api[-_]?key)(?:[._-]|$)/iu.test(name)
    && !/\.(?:key|pem|p12|pfx|crt|cer|der|sqlite|sqlite3|db|log|bak|env)$/iu.test(name);
}
function components(value) {
  if (typeof value !== 'string' || value.length > 1000 || value.startsWith('/') || /^[A-Za-z]:/u.test(value)
    || value.includes('\\') || /[\x00-\x1f\x7f]/u.test(value)) throw denied();
  if (!value) return [];
  const parts = value.split('/');
  if (parts.some(part => !safeName(part) || part === '..' || part === '.' || blockedDirectories.has(part.toLowerCase()))) throw denied();
  return parts;
}
function readableName(name) { return allowedExtensions.has(extname(name).toLowerCase()) || allowedNames.has(name.toLowerCase()) || /^dockerfile\.[a-z0-9_-]+$/iu.test(name); }
const sameFile = (first, second) => first.dev === second.dev && first.ino === second.ino;

/** Read-only source/document access. No shell, writes, arbitrary host paths, or runtime artifacts. */
export function createChatFiles({ root = process.env.CA3P_CHAT_WORKSPACE_ROOT ?? defaultRoot } = {}) {
  const workspaceRoot = resolve(root);
  async function inspect(parts) {
    let base;
    try {
      const rootStat = await lstat(workspaceRoot);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw denied();
      base = await realpath(workspaceRoot);
      let candidate = workspaceRoot; let stat = rootStat; const visited = [];
      for (const part of parts) {
        if (!stat.isDirectory()) throw unavailable();
        candidate = join(candidate, part); visited.push(part); stat = await lstat(candidate);
        if (stat.isSymbolicLink()) throw denied();
        const actual = await realpath(candidate); const nested = relative(base, actual);
        // A real path must have exactly the requested location, not a link or alias.
        if (!nested || nested === '..' || nested.startsWith(`..${sep}`) || actual !== join(base, ...visited)) throw denied();
      }
      return { base, path: candidate, stat };
    } catch (failure) {
      if (['ENOENT', 'ENOTDIR'].includes(failure.code)) throw unavailable();
      if (failure.status) throw failure;
      throw denied();
    }
  }
  async function confirm(location) {
    try {
      const current = await lstat(location.path);
      const actual = await realpath(location.path);
      const nested = relative(location.base, actual);
      if (!sameFile(current, location.stat) || current.isSymbolicLink() || nested === '..' || nested.startsWith(`..${sep}`)) throw denied();
    } catch (failure) {
      if (failure.status) throw failure;
      if (['ENOENT', 'ENOTDIR'].includes(failure.code)) throw unavailable();
      throw denied();
    }
  }
  return {
    async list(relativePath = '') {
      const parts = components(relativePath); const location = await inspect(parts);
      if (!location.stat.isDirectory()) throw fault('CHAT_FILE_NOT_DIRECTORY', '폴더를 선택해 주세요.');
      let names;
      try { names = await readdir(location.path, { withFileTypes: true }); }
      catch (failure) { if (['ENOENT', 'ENOTDIR'].includes(failure.code)) throw unavailable(); throw denied(); }
      await confirm(location);
      const entries = [];
      for (const entry of names.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
        if (!safeName(entry.name) || blockedDirectories.has(entry.name.toLowerCase()) || entry.isSymbolicLink()) continue;
        if (!entry.isDirectory() && (!entry.isFile() || !readableName(entry.name))) continue;
        try {
          const checked = await inspect([...parts, entry.name]);
          if (!checked.stat.isDirectory() && (!checked.stat.isFile() || checked.stat.nlink > 1)) continue;
          entries.push({ name: entry.name, path: [...parts, entry.name].join('/'), type: checked.stat.isDirectory() ? 'directory' : 'file',
            size: checked.stat.isFile() ? checked.stat.size : 0 });
        } catch (failure) { if ([403, 404].includes(failure.status)) continue; throw failure; }
        if (entries.length >= CHAT_FILE_LIMITS.entries) break;
      }
      entries.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name, 'en') : a.type === 'directory' ? -1 : 1));
      return { path: parts.join('/'), entries, rootLabel: '프로젝트 작업 폴더' };
    },
    async read(relativePath) {
      const parts = components(relativePath);
      if (!parts.length || !readableName(parts.at(-1))) throw denied();
      const location = await inspect(parts);
      if (!location.stat.isFile() || location.stat.nlink > 1) throw denied();
      if (location.stat.size > CHAT_FILE_LIMITS.bytes) throw fault('CHAT_FILE_TOO_LARGE', '256 KiB 이하의 텍스트 파일만 읽을 수 있습니다.', 413);
      let handle;
      try {
        handle = await open(location.path, constants.O_RDONLY | constants.O_NOFOLLOW);
        const stat = await handle.stat();
        if (!stat.isFile() || !sameFile(location.stat, stat) || stat.nlink > 1) throw denied();
        await confirm(location);
        const buffer = Buffer.alloc(CHAT_FILE_LIMITS.bytes + 1);
        let length = 0;
        while (length < buffer.length) {
          const read = await handle.read(buffer, length, buffer.length - length, null);
          if (!read.bytesRead) break;
          length += read.bytesRead;
        }
        const after = await handle.stat();
        if (length > CHAT_FILE_LIMITS.bytes || after.size > CHAT_FILE_LIMITS.bytes) throw fault('CHAT_FILE_TOO_LARGE', '256 KiB 이하의 텍스트 파일만 읽을 수 있습니다.', 413);
        if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || length !== after.size) throw fault('CHAT_FILE_CHANGED', '읽는 중 파일이 변경되었습니다. 다시 시도해 주세요.', 409);
        await confirm(location);
        const bytes = buffer.subarray(0, length);
        if (bytes.includes(0)) throw fault('CHAT_FILE_NOT_TEXT', '텍스트 파일만 읽을 수 있습니다.', 415);
        let content;
        try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
        catch { throw fault('CHAT_FILE_NOT_TEXT', 'UTF-8 텍스트 파일만 읽을 수 있습니다.', 415); }
        const truncated = content.length > CHAT_FILE_LIMITS.text;
        if (truncated) {
          content = content.slice(0, CHAT_FILE_LIMITS.text);
          if (/[\uD800-\uDBFF]$/u.test(content)) content = content.slice(0, -1);
        }
        return { path: parts.join('/'), content, sha256: createHash('sha256').update(bytes).digest('hex'), size: length,
          truncated, language: languages[extname(parts.at(-1)).toLowerCase()] ?? 'text' };
      } catch (failure) {
        if (failure.status) throw failure;
        if (['ENOENT', 'ENOTDIR'].includes(failure.code)) throw unavailable();
        throw denied();
      } finally { await handle?.close(); }
    },
  };
}
