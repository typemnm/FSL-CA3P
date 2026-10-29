/** Download public weights without reports, then start an offline-only local model. */
import { execFileSync } from 'node:child_process';

const model = process.env.CASPER_DB_REPORT_LLM_MODEL || 'qwen3-vl:8b-instruct';
if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,160}$/.test(model) || /cloud/i.test(model)) throw new Error('Use a local model tag.');
const docker = (args, capture = true) => execFileSync('docker', args, {
  encoding: 'utf8', windowsHide: true, stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
});
const name = 'ca3p-report-llm', download = 'ca3p-report-model-download';
const network = 'ca3p-report-private', volume = 'ca3p-report-llm-models';
const image = 'ollama/ollama:0.32.5';
const exists = (kind, id) => { try { return JSON.parse(docker([kind, 'inspect', id]))[0]; } catch { return null; } };
const previous = exists('container', name);
if (previous) {
  const existingNetwork = exists('network', network);
  if (!existingNetwork?.Internal || !previous.NetworkSettings.Networks[network] || Object.keys(previous.NetworkSettings.Networks).length !== 1 || Object.keys(previous.HostConfig.PortBindings || {}).length) throw new Error('Existing model container is not isolated.');
  if (!previous.State.Running) docker(['start', name]);
  process.stdout.write('Existing isolated local report model is available.\n');
  process.exit(0);
}
if (exists('container', download)) throw new Error('A model download is already present; inspect it first.');
let net = exists('network', network);
if (!net) {
  docker(['network', 'create', '--internal', '--subnet', '172.29.120.0/24', network]);
  net = exists('network', network);
}
if (!net.Internal || !net.IPAM.Config.some(item => item.Subnet === '172.29.120.0/24')) throw new Error('The report model network must be internal with its expected subnet.');
docker(['volume', 'create', volume]);
try {
  // No report, application volume or credential file is mounted during download.
  docker(['run', '-d', '--name', download, '-v', `${volume}:/root/.ollama`,
    '-e', 'OLLAMA_NO_CLOUD=1', image]);
  docker(['exec', download, 'ollama', 'pull', model], false);
} finally {
  docker(['rm', '-f', download]);
}
docker(['run', '-d', '--name', name, '--restart', 'unless-stopped', '--network', network, '--network-alias', 'report-llm',
  '--ip', '172.29.120.2', ...(process.argv.includes('--gpu') ? ['--gpus', 'all'] : []),
  '-v', `${volume}:/root/.ollama`, '-e', 'OLLAMA_NO_CLOUD=1', '-e', 'OLLAMA_DEBUG=0',
  '-e', 'OLLAMA_NUM_PARALLEL=1', '-e', 'OLLAMA_MAX_LOADED_MODELS=1',
  '-e', 'OLLAMA_CONTEXT_LENGTH=32768', '-e', 'OLLAMA_FLASH_ATTENTION=1',
  '-e', 'OLLAMA_KV_CACHE_TYPE=q8_0', image]);
process.stdout.write('Local report model started on an internal network with no published port.\n');
