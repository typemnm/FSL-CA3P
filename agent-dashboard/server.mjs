import { createDashboardServer } from './local-server.mjs';
import { createAuthentication } from '../apps/api/auth.mjs';
import { createRunService } from '../apps/application/run-service.mjs';
import { createCiResultsService } from '../apps/application/ci-results.mjs';

const port = Number(process.env.PORT || 4173);
const host = process.env.DASHBOARD_HOST || '127.0.0.1';
const publicOrigins = (process.env.DASHBOARD_PUBLIC_ORIGIN ?? '').split(',').filter(Boolean);
const auth = createAuthentication();
const runtime = createRunService();
const ciResults = createCiResultsService();
const server = createDashboardServer({ runtime, auth, publicOrigins, ciResults });
server.listen(port, host, () => {
  console.log(`CA3P Integration Platform\nListening on ${host}:${port}\nLocal: http://127.0.0.1:${port}\nAuthentication: credentials in .runtime/access.txt\nModes: fixture; isolated rule baseline; registered DeepSeek models`);
});
server.on('error', error => { console.error(`CA3P server failed: ${error.code || error.message}`); process.exitCode = 1; });
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => { await server.shutdown(); });
}
