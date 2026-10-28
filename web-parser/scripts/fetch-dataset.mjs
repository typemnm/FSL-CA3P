#!/usr/bin/env node
// Downloads the fingerprint dataset (not kept in the repo) from a pinned enthec/webappanalyzer commit into
// data/webappanalyzer/, where fingerprint.mjs loads it. Idempotent: files already present and parseable are kept.
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';

const REPO = 'enthec/webappanalyzer';
const COMMIT = 'd91f7e510e93457041bea874e8a9ffb011e3e4fe';
// upstream path -> path under data/webappanalyzer/ (upstream `src/` prefix dropped)
const FILES = ['categories.json', 'groups.json', ...'_abcdefghijklmnopqrstuvwxyz'.split('').map((c) => `technologies/${c}.json`)]
  .map((path) => [`src/${path}`, path]);
const DEST = new URL('../data/webappanalyzer/', import.meta.url);

// shortcut: a valid file is assumed to be from COMMIT; delete data/webappanalyzer/ by hand after changing COMMIT.
const valid = async (dest) => {
  try {
    JSON.parse(await readFile(dest, 'utf8'));
    return true;
  } catch {
    return false;
  }
};

async function fetchOne(src, dest) {
  const url = `https://raw.githubusercontent.com/${REPO}/${COMMIT}/${src}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const text = await res.text();
  try {
    JSON.parse(text);
  } catch (err) {
    throw new Error(`${url}: not JSON (${err.message})`);
  }
  // Temp file + rename: an interrupted run never leaves a partial file under the final name.
  const tmp = new URL(`${dest.href}.${process.pid}.tmp`);
  try {
    await writeFile(tmp, text);
    await rename(tmp, dest);
  } finally {
    await rm(tmp, { force: true });
  }
}

try {
  const todo = [];
  for (const [src, path] of FILES) {
    const dest = new URL(path, DEST);
    if (!(await valid(dest))) todo.push([src, dest]);
  }
  if (todo.length) {
    await mkdir(new URL('technologies/', DEST), { recursive: true });
    await Promise.all(todo.map(([src, dest]) => fetchOne(src, dest)));
    console.log(`fetch-dataset: downloaded ${todo.length} file(s) from ${REPO}@${COMMIT.slice(0, 7)}`);
  }
} catch (err) {
  console.error(`fetch-dataset: ${err.message}`);
  process.exitCode = 1;
}
