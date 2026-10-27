import { spawn } from 'node:child_process';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import protocol from '../../../agent/src/protocol.js';
import { createRunEvidenceStore } from './run-evidence.mjs';

const { parseEnvelope, replyTo } = protocol;
const ROOT = fileURLToPath(new URL('../../../casper-db/', import.meta.url));
const DEFAULT_DATABASE = join(ROOT, 'data/cases.sqlite3');
const MAX_OUTPUT_BYTES = 1_000_000;
const PROGRAM = String.raw`
import json, sys
from pathlib import Path
from casper_db.attack_catalog import (
    prepare_catalog_database, list_attack_patterns, lookup_attack_info)
from casper_db.import_workflow import digest
request=json.load(sys.stdin)
database=Path(request['database'])
operation=request['operation']
if operation=='bootstrap':
    catalog=None
    if request.get('catalogPath'):
        path=Path(request['catalogPath'])
        if not path.is_file() or path.stat().st_size>1_000_000:
            raise ValueError('catalog must be a regular JSON file under 1 MB')
        body=path.read_bytes()
        if len(body)>1_000_000:
            raise ValueError('catalog exceeds 1 MB')
        catalog=json.loads(body.decode('utf-8-sig'))
        from casper_db.attack_catalog import _blocks
        _blocks(catalog)
    result=prepare_catalog_database(database,catalog=catalog,
        source_ref=Path(request['catalogPath']).as_uri() if catalog is not None else None)
elif operation=='lookup':
    info=lookup_attack_info(database,request['query'])
    result={'attackInfo':info,'contentHash':digest(info)}
elif operation=='list':
    result=list_attack_patterns(database)
else:
    raise ValueError('unsupported knowledge catalog operation')
json.dump(result,sys.stdout,ensure_ascii=False)
`;

function absolutePath(value, name) {
  if (typeof value !== 'string' || !isAbsolute(value)) throw new TypeError(`${name} must be an absolute path.`);
  return resolve(value);
}

function exchangePython(request, { python, signal } = {}) {
  return new Promise((resolveResult, rejectResult) => {
    const child = spawn(python ?? process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'), ['-c', PROGRAM], {
      cwd: ROOT, shell: false, windowsHide: true, signal, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONPATH: join(ROOT, 'src'), PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
    });
    const output = []; let outputBytes = 0; let errorOutput = ''; let oversized = false;
    child.stdout.on('data', chunk => {
      if (oversized) return;
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) { oversized = true; child.kill(); }
      else output.push(chunk);
    });
    child.stderr.on('data', chunk => { errorOutput = (errorOutput + chunk.toString('utf8')).slice(-4000); });
    child.on('error', rejectResult);
    child.on('close', code => {
      if (oversized) return rejectResult(new Error('Knowledge catalog output exceeded 1 MB.'));
      if (code !== 0) return rejectResult(new Error(`Knowledge catalog failed: ${errorOutput || code}`));
      try { resolveResult(JSON.parse(Buffer.concat(output).toString('utf8'))); } catch { rejectResult(new Error('Knowledge catalog returned invalid JSON.')); }
    });
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') rejectResult(error); });
    child.stdin.end(JSON.stringify(request));
  });
}

/** Catalog ownership is casper-db. The retired receiver is accepted only for compatibility. */
export function createKnowledgeDb({ databasePath = process.env.CASPER_DB_PATH ?? DEFAULT_DATABASE,
  reportsDir, catalogPath, python } = {}) {
  const database = absolutePath(databasePath, 'databasePath');
  const source = catalogPath === undefined ? undefined : absolutePath(catalogPath, 'catalogPath');
  const evidenceStore = createRunEvidenceStore(reportsDir === undefined ? {} : { reportsDir });
  let initialized;
  async function initialize(signal) {
    initialized ??= exchangePython({ database, catalogPath: source, operation: 'bootstrap' }, { python, signal });
    await initialized;
  }
  return {
    async readCatalog({ signal } = {}) {
      await initialize(signal);
      return exchangePython({ database, operation: 'list' }, { python, signal });
    },
    async exchange(serializedRequest, { signal } = {}) {
      const request = parseEnvelope(serializedRequest);
      if (!['casper-db', 'pentest-db'].includes(request.receiver)
        || request.sender !== 'agent' || request.type !== 'storage.request') {
        throw new TypeError('Knowledge DB accepts agent storage.request envelopes only.');
      }
      if (request.payload.operation !== 'get_attack_info') return evidenceStore.exchange(serializedRequest);
      await initialize(signal);
      const result = await exchangePython({ database, operation: 'lookup', query: {
        vulnType: request.payload.vulnType, target: request.payload.target,
      } }, { python, signal });
      return JSON.stringify(replyTo(request, request.receiver, 'storage.attack_info', {
        operation: 'get_attack_info', attackInfo: result.attackInfo,
        evidenceId: `knowledge-catalog-sha256:${result.contentHash}`,
      }));
    },
    readRun: runId => evidenceStore.readRun(runId),
  };
}

export async function readKnowledgeCatalog(options = {}) {
  return createKnowledgeDb(options).readCatalog();
}
