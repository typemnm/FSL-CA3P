import test from 'node:test';
import assert from 'node:assert/strict';
import { createTunnelOriginDetector } from '../tunnel-origin.mjs';

test('Quick Tunnel detector ignores the API endpoint and accepts a fragmented public URL', () => {
  const detect = createTunnelOriginDetector();
  assert.equal(detect('DNS lookup failed for https://api.trycloudflare.com:443\n'), null);
  assert.equal(detect('Your quick tunnel: https://live-chargers-space-aca'), null);
  assert.equal(detect('demics.trycloudflare.com\n'), 'https://live-chargers-space-academics.trycloudflare.com');
});

test('Quick Tunnel detector rejects lookalike hosts and bounds retained output', () => {
  const detect = createTunnelOriginDetector();
  assert.equal(detect('https://demo.trycloudflare.com.evil'), null);
  assert.equal(detect('x'.repeat(10_000)), null);
  assert.equal(detect('https://valid-tunnel.trycloudflare.com'), 'https://valid-tunnel.trycloudflare.com');
});
