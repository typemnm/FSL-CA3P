import { createDashboardServer } from './local-server.mjs';

const port = Number(process.env.PORT || 4173);
const server = createDashboardServer();
server.listen(port, '127.0.0.1', () => {
  console.log(`CA3P Agent Loop · local integration\nLocal: http://127.0.0.1:${port}\nModes: core fixture; explicit isolated local board + DeepSeek`);
});
server.on('error', error => { console.error(`CA3P server failed: ${error.code || error.message}`); process.exitCode = 1; });
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => { await server.shutdown(); });
}
