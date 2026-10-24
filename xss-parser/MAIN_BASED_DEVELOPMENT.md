# main 기반 파서 확장

이 브랜치는 `main`의 기존 `xss-parser/`를 확장합니다. 다른 모듈이나 루프는 수정하지 않습니다.

기존 CLI와 JSON schema 3.4는 그대로 사용합니다.

## 브라우저 구조 파싱

```sh
cd xss-parser
npm install
node cli.mjs --url http://127.0.0.1:4101/ --out daehan-site.json
node cli.mjs --url http://127.0.0.1:4102/ --out wonchang-site.json
```

사이트 서버는 별도 로컬 실습 환경에서 실행해야 합니다. 파서는 같은 출처의 읽기 요청만 하고 로그인 및 공격 페이로드 제출은 하지 않습니다. 일부 GET은 서버에 조회수 등의 부작용을 남길 수 있습니다.

## 의존성 파일 분석

```sh
node site-analysis.mjs --manifest ../vul-web2/package-lock.json --ecosystem npm --out daehan-deps.json
node site-analysis.mjs --manifest ../vul-web2/wonchang/pom.xml --ecosystem maven --out wonchang-deps.json
```

위 `vul-web2` 경로는 대상 소스를 별도로 내려받았을 때의 예시입니다. `main`에는 이 폴더가 없습니다. `--manifest`는 사용자가 지정한 실제 파일 경로를 읽습니다.

## 둘을 한 번에

```sh
node site-analysis.mjs --url http://127.0.0.1:4101/ --max-pages 20 --manifest /path/to/package-lock.json --ecosystem npm --out result.json
```

결과는 `site` (기존 3.4 보고서) 및 `dependencies`(직접 의존성 정보)로 구분됩니다. 의존성 분석은 과제에 선정한 6개 CVE에 대한 **버전 일치**만 표시합니다. 전체 SCA, 전이 의존성 해결, 실제 악용 가능성 또는 OWASP 판정은 하지 않습니다. 서버에서 `package-lock.json` 또는 `pom.xml`을 읽는 기능은 없습니다.

`npm test`로 파서 회귀 테스트를 실행합니다. 새 대학의 실제 브라우저 통합 테스트는 서비스 구동 후 별도로 필요합니다.
