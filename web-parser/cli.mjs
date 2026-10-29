#!/usr/bin/env node
import { open, readFile, rename, rm } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { collect, collectEach } from './collect.mjs';

const USAGE = 'usage: web-parser (--url <URL> | --urls-file <file>)... [--out <file>] [--timeout-ms N] '
  + '[--wait-until load|networkidle] [--user-agent UA] [--ignore-https-errors true|false]';

try {
  const { values } = parseArgs({
    options: {
      url: { type: 'string', multiple: true },
      'urls-file': { type: 'string' },
      out: { type: 'string' },
      'timeout-ms': { type: 'string' },
      'wait-until': { type: 'string' },
      'user-agent': { type: 'string' },
      'ignore-https-errors': { type: 'string' },
    },
  });
  const urls = [...(values.url ?? [])];
  if (values['urls-file'] !== undefined) {
    // One URL per line; blank lines and whole-line `#` comments are skipped.
    const lines = (await readFile(values['urls-file'], 'utf8')).split(/\r?\n/).map((l) => l.trim());
    urls.push(...lines.filter((l) => l && !l.startsWith('#')));
  }
  if (!urls.length) throw new Error(USAGE);
  const opts = {};
  if (values['timeout-ms'] !== undefined) opts.timeoutMs = Number(values['timeout-ms']);
  if (values['wait-until'] !== undefined) opts.waitUntil = values['wait-until'];
  if (values['user-agent'] !== undefined) opts.userAgent = values['user-agent'];
  if (values['ignore-https-errors'] !== undefined) {
    const v = values['ignore-https-errors'];
    if (v !== 'true' && v !== 'false') throw new Error('--ignore-https-errors must be true or false');
    opts.ignoreHTTPSErrors = v === 'true';
  }

  // A temp file next to --out, opened before any visit (an unwritable location fails fast instead of discarding the
  // results) and renamed over --out only on success, so a failed run never destroys earlier results.
  const tmp = values.out ? `${values.out}.${process.pid}.tmp` : null;
  const file = tmp ? await open(tmp, 'w') : null;
  const write = (s) => (file ? file.write(s) : new Promise((resolve, reject) => process.stdout.write(s, (e) => (e ? reject(e) : resolve()))));
  try {
    // One URL: its TargetInfo (failure exits 1). Several: the collectEach array, per-URL failures inside it, written
    // entry by entry so the whole array never sits in one string.
    if (urls.length === 1) await write(`${JSON.stringify(await collect(urls[0], opts), null, 2)}\n`);
    else {
      const results = await collectEach(urls, opts);
      await write('[\n');
      for (const [k, r] of results.entries()) {
        let json;
        try {
          json = JSON.stringify(r, null, 2);
        } catch (err) { // e.g. one entry over V8's maximum string length
          json = JSON.stringify({ url: r.url, ok: false, error: { message: `serialize: ${err.message}` } }, null, 2);
        }
        await write(`${k ? ',\n' : ''}${json}`);
      }
      await write('\n]\n');
    }
    if (file) {
      await file.close();
      await rename(tmp, values.out);
    }
  } finally {
    await file?.close().catch(() => {});
    if (tmp) await rm(tmp, { force: true });
  }
} catch (err) {
  process.stderr.write(`${JSON.stringify({ error: { message: err.message } })}\n`);
  process.exitCode = 1;
}
