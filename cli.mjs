#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { scan } from './parser.mjs';

const HELP = `로컬 웹사이트 입력 지점 파서 → JSON
사용법:
  node cli.mjs --url http://127.0.0.1:3000/ --out report.json
  node cli.mjs --url http://localhost:3000/ --max-pages 5 --headed

필수 옵션:
  --url URL          검사할 로컬 주소 (localhost, 127.0.0.1, [::1])

선택 옵션:
  --out FILE         JSON 저장 경로. 생략하면 터미널에 출력
  --max-pages N      같은 출처의 링크를 따라갈 최대 페이지 수 (기본 10, 1~30)
  --wait-ms N        페이지가 뜬 뒤 기다릴 시간 (기본 500, 0~5000)
  --timeout-ms N     한 페이지 이동의 제한 시간 (기본 10000, 1000~30000)
  --browser FILE     Chrome/Chromium 실행 파일 경로
  --headed           Chrome 창을 화면에 표시
  --help, -h         도움말
`;

function parseArgs(args) {
  const allowed = new Set(['--url', '--out', '--max-pages', '--wait-ms', '--timeout-ms', '--browser']);
  const values = {};
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    if (key === '--help' || key === '-h') return { help: true };
    if (key === '--headed') {
      values.headed = true;
      continue;
    }
    if (!allowed.has(key) || !args[index + 1] || args[index + 1].startsWith('--') || key in values) {
      throw new Error('Invalid or duplicate option: ' + key);
    }
    values[key] = args[++index];
  }
  if (!values['--url']) throw new Error('Provide --url with a local address.');
  return {
    url: values['--url'],
    out: values['--out'],
    options: {
      maxPages: values['--max-pages'] === undefined ? undefined : Number(values['--max-pages']),
      waitMs: values['--wait-ms'] === undefined ? undefined : Number(values['--wait-ms']),
      timeoutMs: values['--timeout-ms'] === undefined ? undefined : Number(values['--timeout-ms']),
      browserPath: values['--browser'],
      headed: !!values.headed
    }
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    return;
  }
  const report = await scan(args.url, args.options);
  const json = JSON.stringify(report, null, 2) + '\n';
  if (args.out) await writeFile(resolve(args.out), json, 'utf8');
  else process.stdout.write(json);
}

main().catch(error => {
  process.stdout.write(JSON.stringify({
    schemaVersion: '1.0',
    error: { code: 'PARSER_ERROR', message: error.message }
  }) + '\n');
  process.exitCode = 1;
});
