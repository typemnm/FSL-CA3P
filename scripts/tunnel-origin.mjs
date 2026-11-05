const TUNNEL_ORIGIN = /https:\/\/(?!api\.)[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com(?![a-z0-9.-])/i;

/** Cloudflared may split the public URL across stdout/stderr chunks. */
export function createTunnelOriginDetector() {
  let output = '';
  return chunk => {
    output += String(chunk);
    const origin = TUNNEL_ORIGIN.exec(output)?.[0] ?? null;
    output = output.slice(-8192);
    return origin;
  };
}
