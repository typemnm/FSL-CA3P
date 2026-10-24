#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { scan } from './parser.mjs';
import { parseDependencyManifest } from './dependency-parser.mjs';

async function main(args) {
  const values = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (!['--url', '--manifest', '--ecosystem', '--out', '--max-pages'].includes(key)
      || Object.hasOwn(values, key) || !args[i + 1] || args[i + 1].startsWith('--')) {
      throw new Error('Usage: node site-analysis.mjs [--url LOOPBACK_URL] [--manifest FILE --ecosystem npm|maven] [--max-pages 1..30] [--out FILE]');
    }
    values[key] = args[++i];
  }
  if (!values['--url'] && !values['--manifest']) throw new Error('Provide --url or --manifest.');
  if (!!values['--manifest'] !== !!values['--ecosystem']) throw new Error('--manifest and --ecosystem must be paired.');
  const result = { schemaVersion: '1.0' };
  if (values['--url']) {
    const maxPages = values['--max-pages'] ? Number(values['--max-pages']) : 20;
    result.site = await scan(values['--url'], { maxPages, hideBody: true });
  } else if (values['--max-pages']) throw new Error('--max-pages requires --url.');
  if (values['--manifest']) {
    const file = values['--manifest'];
    const content = await readFile(file, 'utf8');
    result.dependencies = parseDependencyManifest(content, {
      ecosystem: values['--ecosystem'], sourceFile: basename(file),
    });
  }
  const output = JSON.stringify(result, null, 2) + '\n';
  if (values['--out']) await writeFile(values['--out'], output, 'utf8');
  else process.stdout.write(output);
}
main(process.argv.slice(2)).catch(error => {
  process.stderr.write('Parser error: ' + error.message + '\n');
  process.exitCode = 1;
});
