// University exercises use only local lab addresses. Pin every request to the
// chosen origin; never accept a path, credentials, query or redirect target.
export function validateUniversityOrigin(value) {
  const invalid = () => Object.assign(new TypeError('대학 실습 주소는 http://내부IP:포트 형식이어야 합니다. 경로·인증정보·외부 주소는 사용할 수 없습니다.'), { status: 400 });
  if (typeof value !== 'string' || value.length > 256 || value !== value.trim()) throw invalid();
  const input = /^[a-z][a-z0-9+.-]*:\/\//iu.test(value) ? value : `http://${value}`;
  let url;
  try { url = new URL(input); } catch { throw invalid(); }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash
    || url.pathname !== '/' || !/^http:\/\/[^/?#]+\/?$/iu.test(input)) throw invalid();
  const hostname = url.hostname;
  const aliases = ['localhost', 'host.docker.internal', 'daehan', 'wonchang'];
  const octets = hostname.split('.');
  const ipv4 = octets.length === 4 && octets.every(part => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
  const [a, b] = octets.map(Number);
  const privateAddress = ipv4 && (a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
  // URL's legacy numeric-address normalization must not turn alternate forms
  // such as decimal/hex addresses into an accepted lab IP.
  const authorityHost = input.slice('http://'.length).replace(/\/$/u, '').split(':')[0].toLowerCase();
  if (hostname !== authorityHost || (!privateAddress && !aliases.includes(hostname))) throw invalid();
  return url.origin;
}
