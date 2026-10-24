#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { scan } from './parser.mjs';
import { readInventory } from './dependency-inventory.mjs';

const HELP = `로컬 웹사이트 구성요소 → JSON
사용법:
  node cli.mjs --url http://127.0.0.1:3000/ --out site.json

필수: --url URL          로컬 웹사이트 주소
선택: --out FILE         결과 JSON 파일 (생략하면 터미널 출력)
      --max-pages N      방문할 최대 페이지 수 (기본 10, 1~30)
      --wait-ms N        페이지 로드 후 대기 ms (기본 500, 0~5000)
      --timeout-ms N     페이지 이동 제한 ms (기본 10000, 1000~30000)
      --browser FILE     Chrome/Chromium 실행 파일
      --headed           브라우저 창 표시
      --hide-body        게시글 본문 미리보기 가림
      --structure        구조용 축약 출력
      --npm-lock FILE    대상 npm lockfile
      --maven-pom FILE   대상 Maven POM
      --help, -h         도움말
`;

function parseArgs(args) {
  const allowed = new Set(['--url', '--out', '--max-pages', '--wait-ms', '--timeout-ms', '--browser', '--npm-lock', '--maven-pom']);
  const values = {};
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    if (key === '--help' || key === '-h') return { help: true };
    if (key === '--headed' || key === '--hide-body' || key === '--structure') {
      values[key] = true;
      continue;
    }
    if (!allowed.has(key) || !args[index + 1] || args[index + 1].startsWith('--') || key in values) {
      throw new Error('Invalid or duplicate option: ' + key);
    }
    values[key] = args[++index];
  }
  if (!values['--url']) throw new Error('Provide --url with a local address.');
  if (!values['--structure'] && (values['--npm-lock'] || values['--maven-pom'])) throw new Error('의존성 입력에는 --structure가 필요합니다.');
  return {
    dependencies: [{kind:'npm',file:values['--npm-lock']},{kind:'maven',file:values['--maven-pom']}].filter(x => x.file),
    url: values['--url'],
    out: values['--out'],
    options: {
      structure: !!values['--structure'],
      maxPages: values['--max-pages'] === undefined ? undefined : Number(values['--max-pages']),
      waitMs: values['--wait-ms'] === undefined ? undefined : Number(values['--wait-ms']),
      timeoutMs: values['--timeout-ms'] === undefined ? undefined : Number(values['--timeout-ms']),
      browserPath: values['--browser'],
      headed: !!values['--headed'],
      hideBody: !!values['--hide-body']
    }
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); return; }
  const inventory = args.options.structure ? await readInventory(args.dependencies) : null;
  const result = await scan(args.url, args.options);
  if (inventory) result.dependencies = inventory;
  const json = JSON.stringify(result, null, 2) + '\n';
  if (args.out) await writeFile(resolve(args.out), json, 'utf8');
  else process.stdout.write(json);
}

main().catch(error => {
  process.stdout.write(JSON.stringify({
    schemaVersion: process.argv.includes('--structure') ? 'structure-1.0' : '3.4', error: { code: 'PARSER_ERROR', message: error.message }
  }) + '\n');
  process.exitCode = 1;
});
