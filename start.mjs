#!/usr/bin/env node

// Local workspace entry point. The lab process starts only on explicit UI action.
const usage = `CA3P local workspace

Usage:
  node start.mjs
  node start.mjs --port 4174
  npm start -- --port 4174

Options:
  --port, -p  Local dashboard port (1-65535, default: PORT or 4173)
  --help, -h  Show this help

The dashboard binds to 127.0.0.1 by default. Enter a URL and review its parser
results before choosing a supported judgment engine. Registered university lab
checks may call DeepSeek; external URLs use read-only HTTP observation.
Stop the dashboard with Ctrl+C.`;

function resolveOptions(args) {
  let port = process.env.PORT ?? '4173';
  let help = false;
  let explicitPort = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--port' || arg === '-p') {
      if (explicitPort || !args[index + 1]) throw new Error('Provide --port once with a value.');
      port = args[++index];
      explicitPort = true;
    } else if (arg.startsWith('--port=')) {
      if (explicitPort) throw new Error('Provide --port only once.');
      port = arg.slice('--port='.length);
      explicitPort = true;
    } else {
      throw new Error(`Unknown option: ${arg}. Use --help for usage.`);
    }
  }
  if (help) return { help: true };
  if (!/^\d+$/.test(String(port)) || !Number.isSafeInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535) {
    throw new Error('PORT / --port must be an integer between 1 and 65535.');
  }
  return { help: false, port: Number(port) };
}

try {
  const options = resolveOptions(process.argv.slice(2));
  if (options.help) {
    console.log(usage);
  } else {
    const nodeMajor = Number(process.versions.node.split('.')[0]);
    if (nodeMajor < 24) throw new Error('Node.js 24 or newer is required.');
    process.env.PORT = String(options.port);
    console.log('Starting CA3P local dashboard. Lab checks require an explicit action in the UI.');
    // Resolve relative to this script, independent of the current working directory.
    await import(new URL('./agent-dashboard/server.mjs', import.meta.url).href);
  }
} catch (error) {
  console.error(`CA3P start failed: ${error.message}`);
  process.exitCode = 1;
}
