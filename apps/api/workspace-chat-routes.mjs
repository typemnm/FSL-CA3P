import { createWorkspaceChatService } from '../application/workspace-chat.mjs';
import { createChatFiles } from '../application/chat-files.mjs';
import { createChatRepository } from '../../packages/chat-store/index.mjs';
import { createWorkspaceChatModel } from '../../packages/models/workspace-chat.mjs';

const fail = (status, message) => Object.assign(new Error(message), { status });

/** HTTP/auth boundaries stay separate from conversation and provider logic. */
export function createWorkspaceChatRoutes({ service, runProvider, platformProvider } = {}) {
  let chat = service;
  const get = () => chat ??= createWorkspaceChatService({ repository: createChatRepository(),
    model: createWorkspaceChatModel(), files: createChatFiles(), runProvider, platformProvider });
  return {
    async handle({ req, res, pathname, origin, currentUser, json, readJson }) {
      if (!pathname.startsWith('/api/chat/')) return false;
      const owner = currentUser.user.name;
      const send = value => { if (!res.destroyed) json(res, 200, value); return true; };
      const requireMethod = methods => {
        if (!methods.includes(req.method)) throw fail(405, `Use ${methods.join(', ')}.`);
      };
      const body = async allowed => {
        const value = await readJson(req, 32_768);
        if (!value || typeof value !== 'object' || Array.isArray(value)
          || Object.keys(value).some(key => !allowed.includes(key))) throw fail(400, '지원하는 채팅 요청 형식을 사용하세요.');
        return value;
      };
      if (pathname === '/api/chat/models') {
        requireMethod(['GET']); return send({ models: await get().listModels() });
      }
      if (pathname === '/api/chat/files' || pathname === '/api/chat/file') {
        requireMethod(['GET']);
        const path = new URL(req.url, origin).searchParams.get('path') ?? '';
        return send(await (pathname.endsWith('/files') ? get().listFiles(path) : get().readFile(path)));
      }
      if (pathname === '/api/chat/sessions') {
        requireMethod(['GET', 'POST']);
        if (req.method === 'GET') return send({ sessions: await get().listSessions(owner) });
        return send({ session: await get().createSession(owner, await body(['modelId', 'title'])) });
      }
      const match = /^\/api\/chat\/sessions\/([a-zA-Z0-9_-]+)(?:\/(messages|compact))?$/.exec(pathname);
      if (!match) throw fail(404, '채팅 경로를 찾을 수 없습니다.');
      const [, id, action] = match;
      if (!action) {
        requireMethod(['GET', 'PATCH', 'DELETE']);
        if (req.method === 'GET') return send({ session: await get().getSession(owner, id) });
        if (req.method === 'PATCH') return send({ session: await get().updateSession(owner, id, await body(['title', 'modelId'])) });
        await get().deleteSession(owner, id); return send({ deleted: true });
      }
      requireMethod(['POST']);
      const input = await body(action === 'messages' ? ['content', 'files', 'runId'] : []);
      const controller = new AbortController();
      const abort = () => { if (!res.writableEnded) controller.abort(); };
      res.on('close', abort);
      try {
        const session = action === 'messages'
          ? await get().sendMessage(owner, id, input, { signal: controller.signal })
          : await get().compact(owner, id, { signal: controller.signal });
        return send({ session });
      } finally { res.removeListener('close', abort); }
    },
    async close() { await chat?.close?.(); },
  };
}
