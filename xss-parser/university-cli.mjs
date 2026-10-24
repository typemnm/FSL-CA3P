#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { scanUniversityFixture } from './university-fixtures.mjs';

const args = process.argv.slice(2);
const choice = args[0];
if (!['daehan', 'wonchang'].includes(choice)
  || args.length > 3 || (args.length > 1 && args[1] !== '--out')
  || (args.length === 3 && (!args[2] || args[2].startsWith('-')))) {
  process.stderr.write('Usage: node university-cli.mjs <daehan|wonchang> [--out result.json]\n');
  process.exitCode = 2;
} else {
  try {
    const result = await scanUniversityFixture(choice);
    const output = JSON.stringify(result, null, 2) + '\n';
    if (args[2]) await writeFile(args[2], output, 'utf8');
    else process.stdout.write(output);
  } catch (error) {
    process.stderr.write('University scan failed: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
