#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, basename } from 'node:path';
import { fuzz } from './fuzzer.mjs';

const HELP = `HTML/JS XSS fuzzer → JSON
node cli.mjs --html index.html --js app.js --profile fsl-ca3p --out result.json
node cli.mjs --input request.json --out result.json
cat request.json | node cli.mjs
Options: --html FILE --js FILE (repeatable) --input FILE --out FILE
         --profile generic|fsl-ca3p --max-cases N --settle-ms N --browser FILE
JS array paths in JSON must match script URLs in HTML.
`;
async function main() {
  const args = process.argv.slice(2), opts = {}, jsFiles = [];
  const allowed = new Set(['--html', '--js', '--input', '--out', '--profile', '--max-cases', '--settle-ms', '--browser']);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') { process.stdout.write(HELP); return; }
    const key = args[i];
    if (!allowed.has(key) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Invalid option: ${key}`);
    const value = args[++i];
    if (key === '--js') jsFiles.push(value); else opts[key] = value;
  }
  let input;
  if (opts['--input']) input = JSON.parse(await readFile(resolve(opts['--input']), 'utf8'));
  else if (opts['--html']) input = { html: await readFile(resolve(opts['--html']), 'utf8'),
    js: await Promise.all(jsFiles.map(async file => ({ path: '/' + basename(file), code: await readFile(resolve(file), 'utf8') }))) };
  else {
    if (process.stdin.isTTY) throw new Error('Provide --html/--js, --input, or stdin JSON.');
    let raw = '';
    for await (const chunk of process.stdin) raw += chunk;
    input = JSON.parse(raw);
  }
  if (opts['--profile']) input.profile = opts['--profile'];
  if (opts['--max-cases']) input.maxCases = Number(opts['--max-cases']);
  if (opts['--settle-ms']) input.settleMs = Number(opts['--settle-ms']);
  const report = await fuzz(input, { executablePath: opts['--browser'] });
  const json = JSON.stringify(report, null, 2) + '\n';
  if (opts['--out']) await writeFile(resolve(opts['--out']), json);
  else process.stdout.write(json);
}
main().catch(error => {
  process.stdout.write(JSON.stringify({ schemaVersion: '1.0', error: { code: 'FUZZER_ERROR', message: error.message } }) + '\n');
  process.exitCode = 1;
});
