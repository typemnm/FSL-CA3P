/** Small synchronous client for existing Node tools; data ownership stays in the unified DB. */
import { execFileSync } from 'node:child_process';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('./', import.meta.url));
const PROGRAM = String.raw`
import json, sys
from pathlib import Path
from casper_db.attack_catalog import prepare_catalog_database, lookup_attack_info, list_attack_patterns
request=json.load(sys.stdin)
database=Path(request['database'])
prepare_catalog_database(database)
result = list_attack_patterns(database) if request['operation']=='catalog' else lookup_attack_info(database,request['query'])
json.dump(result,sys.stdout,ensure_ascii=False)
`;

function requestKnowledgeSync(request, {
  databasePath = process.env.CASPER_DB_PATH ?? join(ROOT, 'data/cases.sqlite3'),
  python = process.env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'),
} = {}) {
  if (typeof databasePath !== 'string' || !isAbsolute(databasePath)) {
    throw new TypeError('Knowledge database path must be absolute.');
  }
  return JSON.parse(execFileSync(python, ['-c', PROGRAM], {
    cwd: ROOT, input: JSON.stringify({ database: databasePath, ...request }), encoding: 'utf8',
    windowsHide: true, timeout: 10_000, maxBuffer: 1_000_000,
    env: { ...process.env, PYTHONPATH: join(ROOT, 'src'), PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
  }));
}

export function lookupAttackInfoSync(query, options) {
  return requestKnowledgeSync({ operation: 'lookup', query }, options);
}

export function readAttackCatalogSync(options) {
  return requestKnowledgeSync({ operation: 'catalog' }, options);
}
