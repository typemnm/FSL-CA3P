import { createAttackTemplateManagement } from '../application/attack-templates.mjs';

const ROOT = '/api/attack-templates';
const MAX_IMPORT_BYTES = 1024 * 1024;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = (status, message) => Object.assign(new Error(message), { status });

/** Human catalog management uses dashboard authorization, never an agent capability. */
export function createAttackTemplateRoutes({ catalog } = {}) {
  const templates = createAttackTemplateManagement({ catalog });
  return {
    async handle({ req, res, pathname, origin, auth, json, readJson }) {
      if (pathname !== ROOT && !pathname.startsWith(ROOT + '/')) return false;
      const send = (status, value, extra) => {
        // Packets and payloads are source data. Keep their exact strings, including
        // credential-like attack samples, so copying/editing cannot alter semantics.
        json(res, status, value, extra, { preserveSource: true });
        return true;
      };
      try {
        if (pathname === ROOT) {
          if (req.method === 'GET') {
            const filters = {};
            const params = new URL(req.url, origin).searchParams;
            for (const [key, value] of params) {
              if (!['q', 'attackType', 'runtime', 'framework', 'library'].includes(key)
                || Object.hasOwn(filters, key) || value.length > (key === 'q' ? 256 : 128)) {
                throw fail(400, '템플릿 검색 조건을 확인하세요.');
              }
              filters[key] = value;
            }
            return send(200, templates.list(filters));
          }
          if (req.method !== 'POST') return send(405, { error: 'Use GET or POST.' }, { Allow: 'GET, POST' });
          auth.requireUser(req, { mutate: true, admin: true });
          const result = await templates.import(await readJson(req, MAX_IMPORT_BYTES));
          return send(result.dryRun || !result.created ? 200 : 201, result);
        }
        const match = /^\/api\/attack-templates\/([a-zA-Z0-9][a-zA-Z0-9._:-]{0,127})$/.exec(pathname);
        if (!match) throw fail(404, '템플릿을 찾을 수 없습니다.');
        const id = match[1];
        if (req.method === 'GET') {
          return send(200, templates.get(id));
        }
        if (!['PUT', 'DELETE'].includes(req.method)) {
          return send(405, { error: 'Use GET, PUT or DELETE.' }, { Allow: 'GET, PUT, DELETE' });
        }
        auth.requireUser(req, { mutate: true, admin: true });
        const body = await readJson(req, MAX_IMPORT_BYTES);
        const allowed = req.method === 'PUT' ? ['template', 'expectedRevision'] : ['expectedRevision'];
        if (!record(body) || Object.keys(body).some(key => !allowed.includes(key))
          || typeof body.expectedRevision !== 'string' || !/^[a-f0-9]{64}$/.test(body.expectedRevision)
          || (req.method === 'PUT' && !record(body.template))) {
          throw fail(400, '템플릿과 조회 시 받은 expectedRevision을 확인하세요.');
        }
        if (req.method === 'DELETE') return send(200, await templates.remove(id, body.expectedRevision));
        return send(200, await templates.update(id, body.template, body.expectedRevision));
      } catch (failure) {
        if (!Number.isInteger(failure.status)) throw failure;
        return send(failure.status, { error: failure.message,
          ...(typeof failure.code === 'string' ? { code: failure.code } : {}),
          ...(Number.isInteger(failure.index) ? { index: failure.index } : {}),
          ...(typeof failure.field === 'string' ? { field: failure.field } : {}) });
      }
    },
  };
}
