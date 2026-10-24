import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { scan } from './parser.mjs';
import { parseDependencyManifest } from './dependency-parser.mjs';

const FIXTURES = {
  daehan: { origin: 'http://127.0.0.1:4101', ecosystem: 'npm', manifest: '../vul-web2/package-lock.json' },
  wonchang: { origin: 'http://127.0.0.1:4102', ecosystem: 'maven', manifest: '../vul-web2/wonchang/pom.xml' },
};

/** Explicit fixture names, never arbitrary local file paths or target URLs. */
export async function scanUniversityFixture(site, { scanImpl = scan, readImpl = readFile, signal,
  maxPages = 20, waitMs = 250, timeoutMs = 10000 } = {}) {
  const fixture = Object.hasOwn(FIXTURES, site) ? FIXTURES[site] : null;
  if (!fixture) throw new TypeError('Unknown university fixture: expected daehan or wonchang.');
  const manifestFile = resolve(import.meta.dirname, fixture.manifest);
  const content = await readImpl(manifestFile, 'utf8');
  const dependencies = parseDependencyManifest(content, {
    ecosystem: fixture.ecosystem, sourceFile: fixture.manifest,
  });
  const report = await scanImpl(fixture.origin + '/', {
    signal, maxPages, waitMs, timeoutMs, hideBody: true,
  });
  if (report.schemaVersion !== '3.4' || report.summary?.scope !== 'visited-client-pages'
    || !Array.isArray(report.pages) || !report.pages.every(page => {
      try { return new URL(page.url).origin === fixture.origin; } catch { return false; }
    }) || new URL(report.startUrl).origin !== fixture.origin) {
    throw new Error('University parser returned a report outside the selected fixture.');
  }
  return { site, origin: fixture.origin, report, dependencies };
}

export const UNIVERSITY_FIXTURE_ORIGINS = Object.freeze({
  daehan: FIXTURES.daehan.origin, wonchang: FIXTURES.wonchang.origin,
});
