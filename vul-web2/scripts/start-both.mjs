import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const daehanEnv = { ...process.env, PORT: process.env.DAEHAN_PORT || '4101' };
const wonchangEnv = { ...process.env, PORT: process.env.WONCHANG_PORT || '4102' };
const children = [
  spawn(process.execPath, [join(root, 'src', 'server.mjs'), 'daehan'], {
    cwd: root, stdio: 'inherit', env: daehanEnv
  }),
  spawn(process.execPath, [join(root, 'wonchang', 'src', 'server.mjs')], {
    cwd: join(root, 'wonchang'), stdio: 'inherit', env: wonchangEnv
  })
];

function stop() {
  for (const child of children) if (!child.killed) child.kill();
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const child of children) child.on('exit', code => {
  if (code && code !== 0) {
    stop();
    process.exitCode = code;
  }
});
