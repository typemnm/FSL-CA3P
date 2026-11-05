import test from 'node:test';
import assert from 'node:assert/strict';
import { validateUniversityOrigin } from '../university-target.mjs';

test('university lab addresses normalize IP:port and support native and Docker networks', () => {
  for (const host of ['127.0.0.1', '10.1.2.3', '172.16.0.2', '172.31.255.2', '192.168.0.84',
    'localhost', 'host.docker.internal', 'daehan', 'wonchang']) {
    assert.equal(validateUniversityOrigin(`${host}:4101`), `http://${host}:4101`);
    assert.equal(validateUniversityOrigin(`http://${host}:4101/`), `http://${host}:4101`);
  }
  assert.equal(validateUniversityOrigin('192.168.0.84:80'), 'http://192.168.0.84');
  assert.equal(validateUniversityOrigin('http://192.168.0.84'), 'http://192.168.0.84');
});

test('university lab validation rejects public, ambiguous and non-origin targets', () => {
  for (const input of [null, '', 'https://127.0.0.1:4101',
    'http://127.0.0.1:4101/path', 'http://127.0.0.1:4101/?x=1', 'http://127.0.0.1:4101/#x',
    'http://user:pass@127.0.0.1:4101', 'http://example.com:4101', 'http://8.8.8.8:4101',
    'http://169.254.169.254:4101', 'http://172.32.0.1:4101', 'http://0.0.0.0:4101',
    'http://2130706433:4101', 'http://0x7f000001:4101', 'http://127.1:4101',
    'http://127.000.000.001:4101', ' http://127.0.0.1:4101', 'http://127.0.0.1:4101\\evil']) {
    assert.throws(() => validateUniversityOrigin(input), { status: 400 }, String(input));
  }
});
