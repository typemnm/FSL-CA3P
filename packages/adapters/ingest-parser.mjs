#!/usr/bin/env node
/** Product entry point for a saved web-parser result; no target requests or exploit execution. */
import { readFile, stat, writeFile, access } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { syncParserAdvisories } from './integrations/casper-db.mjs';

export async function main(args = process.argv.slice(2)) {
  if (args.includes('--help')) {
    console.log('node packages/adapters/ingest-parser.mjs --report FILE --db ABSOLUTE_SQLITE --target ID [--output NEW_JSON]');
    return 0;
  }
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!['--report', '--db', '--target', '--output'].includes(key) || !args[index + 1]
      || Object.hasOwn(options, key)) throw new TypeError('Invalid or duplicate parser ingestion option.');
    options[key] = args[index + 1];
  }
  if (!options['--report'] || !options['--target'] || !isAbsolute(options['--db'] ?? '')) {
    throw new TypeError('--report, --target and an absolute --db are required.');
  }
  const reportPath = resolve(options['--report']);
  const output = options['--output'] && resolve(options['--output']);
  if (output) {
    if (output === reportPath || output === resolve(options['--db']) || !output.endsWith('.json')) throw new TypeError('Output must be a new JSON file.');
    try { await access(output); throw new Error('Output already exists.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!(await stat(dirname(output))).isDirectory()) throw new TypeError('Output parent must be an existing directory.');
  }
  if ((await stat(reportPath)).size > 8_000_000) throw new TypeError('Parser report exceeds 8 MB.');
  const report = JSON.parse((await readFile(reportPath, 'utf8')).replace(/^\uFEFF/u, ''));
  if (!['3.4', 'structure-1.0', 'web-parser-1'].includes(report.schemaVersion)) throw new TypeError('Expected parser 3.4, structure-1.0 or web-parser-1 output.');
  const origin = new URL(report.target?.origin ?? report.startUrl ?? report.site?.origin).origin;
  const result = await syncParserAdvisories({ report, origin,
    targetId: options['--target'], databasePath: resolve(options['--db']) });
  const body = JSON.stringify(result, null, 2) + '\n';
  if (output) await writeFile(output, body, { flag: 'wx' });
  process.stdout.write(body);
  return result.collection_complete ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    console.error(JSON.stringify({ status: 'failed', message: error.message })); process.exitCode = 2;
  });
}
