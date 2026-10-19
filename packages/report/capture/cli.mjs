#!/usr/bin/env node
/**
 * node cli.mjs --origin <url> --out <dir> --expected-origin <url>
 *   [--selector <s>] [--full-page] [--session '<json>'] [--allow-session '<json array>']
 * Prints exactly one JSON line; errors become {ok:false,error:{code,message}}.
 */

import { parseArgs } from 'node:util';
import { capture } from './screenshot.mjs';

function json(flag, text) {
  if (text === undefined) return undefined;
  try { return JSON.parse(text); }
  catch { throw Object.assign(new Error(`--${flag} is not valid JSON.`), { code: 'INVALID_ARGUMENTS' }); }
}

async function main() {
  const { values } = parseArgs({
    options: {
      origin: { type: 'string' },
      out: { type: 'string' },
      selector: { type: 'string' },
      'full-page': { type: 'boolean', default: false },
      session: { type: 'string' },
      'allow-session': { type: 'string' },
      'expected-origin': { type: 'string' },
    },
    strict: true,
  });
  const captures = await capture(values.origin, {
    selector: values.selector,
    fullPage: values['full-page'],
    sessionSwitch: json('session', values.session),
    allowSessionSwitches: json('allow-session', values['allow-session']),
    outDir: values.out,
    expectedOrigin: values['expected-origin'],
  });
  return { ok: true, captures };
}

let result;
try { result = await main(); }
catch (error) {
  const code = typeof error?.code === 'string' && !error.code.startsWith('ERR_') ? error.code : 'INVALID_ARGUMENTS';
  result = { ok: false, error: { code, message: String(error?.message ?? error).split('\n')[0] } };
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exitCode = result.ok ? 0 : 1;
