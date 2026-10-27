#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { scan } from './parser.mjs';
import { readInventory } from './dependency-inventory.mjs';
import { MODULE_ID } from './web-dependencies.mjs';

const HELP = `web-parser: 로컬 URL → 웹 구조 + 공개 라이브러리/리소스 의존 관계
사용법: node cli.mjs --url http://127.0.0.1:4101/ --structure --out output/site.json
필수: --url URL          승인된 HTTP(S) loopback 주소
선택: --out FILE         결과 JSON (생략하면 stdout)
      --structure        작은 구조용 출력 (생략하면 기존 상세 3.4)
      --max-pages N      1~30, 기본 10
      --wait-ms N        0~5000, 기본 500
      --timeout-ms N     1000~30000, 기본 10000
      --browser FILE     Chromium 실행 파일
      --headed           브라우저 창 표시
      --hide-body        상세 본문 미리보기 가림
      --npm-lock FILE    선택적 로컬 npm 자료 (URL 관찰과 별도 출처)
      --maven-pom FILE   선택적 로컬 Maven 자료 (URL 관찰과 별도 출처)
      --help, -h         도움말
파일 없이 URL만으로 라이브러리 식별 단서/JS·CSS 참조를 수집합니다.
서버 내부 의존성 및 실제 설치 버전·취약점 여부를 확정하지 않습니다.
`;

export function parseArgs(args) {
  const flags = new Set(['--structure', '--headed', '--hide-body']);
  const options = new Set(['--url', '--out', '--max-pages', '--wait-ms', '--timeout-ms', '--browser', '--npm-lock', '--maven-pom']);
  const values = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === '--help' || key === '-h') return { help: true };
    if (Object.hasOwn(values, key)) throw new Error('Duplicate option: ' + key);
    if (flags.has(key)) { values[key] = true; continue; }
    if (!options.has(key) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Invalid option: ' + key);
    values[key] = args[++i];
  }
  if (!values['--url']) throw new Error('Provide --url with a local address.');
  return { url: values['--url'], out: values['--out'],
    inputs: [{ kind: 'npm', file: values['--npm-lock'] }, { kind: 'maven', file: values['--maven-pom'] }].filter(item => item.file),
    options: { structure: !!values['--structure'], headed: !!values['--headed'], hideBody: !!values['--hide-body'],
      maxPages: values['--max-pages'] === undefined ? undefined : Number(values['--max-pages']),
      waitMs: values['--wait-ms'] === undefined ? undefined : Number(values['--wait-ms']),
      timeoutMs: values['--timeout-ms'] === undefined ? undefined : Number(values['--timeout-ms']),
      browserPath: values['--browser'] }
  };
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArgs(args);
  if (parsed.help) { process.stdout.write(HELP); return; }
  const inventory = parsed.inputs.length ? await readInventory(parsed.inputs) : null;
  const result = await scan(parsed.url, parsed.options);
  // Keep URL observations and file evidence separate. Never replace the URL inventory.
  if (inventory) result.dependencies.sources = inventory.sources;
  const json = JSON.stringify(result, null, 2) + '\n';
  if (parsed.out) await writeFile(resolve(parsed.out), json, 'utf8');
  else process.stdout.write(json);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    process.stdout.write(JSON.stringify({ moduleId: MODULE_ID,
      schemaVersion: process.argv.includes('--structure') ? 'structure-1.0' : '3.4',
      error: { code: 'PARSER_ERROR', message: error.message } }) + '\n');
    process.exitCode = 1;
  });
}
