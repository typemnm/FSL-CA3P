import { spawn } from 'node:child_process';
import { access, mkdir } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventoryFromParser, knowledgeContextDigest } from './parser-inventory.mjs';
import { knowledgeParserReport } from './parser-report.mjs';
export { inventoryFromParser } from './parser-inventory.mjs';

const ROOT = fileURLToPath(new URL('../../../casper-db/', import.meta.url));
const PYTHON_SOURCE = join(ROOT, 'src');
const DEFAULT_DB = join(ROOT, 'data', 'cases.sqlite3');
const MAX_OUTPUT_BYTES = 1_000_000;
const MAX_OBSERVATIONS = 48;
const PYTHON_CODE = String.raw`
import json, sys, sqlite3
from pathlib import Path
from casper_db.repository import CaseStore, initialize_database, SCHEMA_VERSION
from casper_db.matching import assess_observation
from casper_db.reference_context import build_reference_context
from casper_db.knowledge import query_knowledge
from casper_db.case_policy import same_reviewed_route

request = json.load(sys.stdin)
db = Path(request['database'])
if request.get('operation') == 'sync_knowledge':
    from casper_db.advisory_sync import sync_knowledge
    json.dump(sync_knowledge(db, request['sync'], apply=True), sys.stdout, ensure_ascii=False)
    sys.exit(0)
# Existing data requires explicit migration. Only a new/empty file initializes
# during lookup, including concurrent first-use requests.
if db.exists():
    with sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True) as connection:
        # Both checks must see one snapshot: a concurrent initializer may commit
        # between statements, otherwise version 0 can be paired with new tables.
        connection.execute('BEGIN')
        version=connection.execute('PRAGMA user_version').fetchone()[0]
        empty=not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone()
    if version == 0 and empty:
        initialize_database(db)
    elif version != SCHEMA_VERSION:
        raise ValueError('explicit database migration is required before read-only lookup')
else:
    initialize_database(db)
store = CaseStore(db)
target_id = request['targetId']
cases = store.list_for_target(target_id)
assessments = [assess_observation(store, item).model_dump() for item in request['observations']]
workspace = request.get('intakeWorkspace')
if workspace is None and (db.parent / 'workspace.json').is_file():
    workspace = str(db.parent)
context = build_reference_context(target_id, workspace=Path(workspace) if workspace else None,
    external_database=Path(request['externalDatabase']) if request.get('externalDatabase') else None,
    cve_ids=request.get('cveIds', []))
context['unresolved_requests'] = []
for item in request.get('unresolvedRequests', []):
    related = []
    for case in cases:
        if case.method != item['method']:
            continue
        exact = case.endpoint == item['endpoint']
        route = case.route_template and same_reviewed_route(
            case.route_template, case.endpoint, item['endpoint'], case.parameter)
        if exact or route:
            related.append({'case_id':case.case_id, 'case_revision':case.revision,
                'basis':'exact_endpoint' if exact else 'reviewed_route', 'decision':'manual_review'})
    context['unresolved_requests'].append({**item, 'related_cases':related})
result = {'targetId': target_id, 'readyCaseCount': len(cases), 'assessments': assessments,
    'referenceContext':context}
result['knowledgeContext'] = query_knowledge(db, {
    'target_id':target_id, 'observations':request['observations'],
    **({'inventory':request['softwareInventory']} if request.get('softwareInventory') is not None else {})},
    external_database=Path(request['externalDatabase']) if request.get('externalDatabase') else None)
json.dump(result, sys.stdout, ensure_ascii=False)
`;

function absoluteDatabasePath(value) {
  if (value === undefined) return DEFAULT_DB;
  if (typeof value !== 'string' || !isAbsolute(value)) {
    throw new Error('CASPER_DB_PATH must be an absolute path.');
  }
  return resolve(value);
}

/** Translate only explicit parser API hints to historical-case lookup locations. */
export function parserReferenceLocations(report, { targetId = 'vul-web-1', origin, locationHints = [] } = {}) {
  report = knowledgeParserReport(report, { origin });
  if (!report || !Array.isArray(report.pages) || typeof origin !== 'string') {
    throw new TypeError('A parser report and exact target origin are required.');
  }
  const allowed = new URL(origin);
  const seen = new Set();
  const observations = [];
  const unresolvedRequests = [];
  if (report.inputLocations !== undefined) {
    if (report.inputLocations?.schema_version !== 'casper-parser-locations-1'
      || !Array.isArray(report.inputLocations.observations)) {
      throw new TypeError('Unsupported explicit parser location contract.');
    }
    const reported = report.inputLocations.observations.map(item => {
      if (item?.target_id !== targetId) throw new TypeError('Parser location target does not match this run.');
      const { target_id, ...hint } = item;
      return hint;
    });
    locationHints = [...locationHints, ...reported];
  }
  if (!Array.isArray(locationHints) || locationHints.length > MAX_OBSERVATIONS) {
    throw new TypeError('locationHints must be a bounded array of explicit input locations.');
  }
  for (const page of report.pages) {
    for (const entry of page.behaviors || []) {
      const behavior = typeof entry === 'string' ? report.behaviors?.find(item => item.id === entry) : entry;
      if (!behavior) continue;
      for (const api of behavior.api || []) {
        if (!api || typeof api.url !== 'string' || typeof api.method !== 'string') continue;
        let url;
        try { url = new URL(api.url, allowed.origin); } catch { continue; }
        if (url.origin !== allowed.origin || /[{}]/u.test(url.pathname)) continue;
        const method = api.method.toUpperCase();
        if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method)) continue;
        const fields = [];
        for (const key of api.bodyKeys || []) {
          if (typeof key === 'string' && key.length > 0) fields.push([key, 'body']);
        }
        for (const key of url.searchParams.keys()) fields.push([key, 'query']);
        const items = fields.map(([parameter, parameter_location]) =>
          ({ target_id: targetId, endpoint: url.pathname, method, parameter, parameter_location }));
        for (const hint of locationHints) {
          if (!hint || hint.endpoint !== url.pathname || hint.method !== method) continue;
          if (Object.keys(hint).some(key => !['endpoint', 'method', 'parameter', 'parameter_location', 'parameter_not_applicable'].includes(key))) {
            throw new TypeError('location hint contains unsupported fields.');
          }
          if (hint.parameter_not_applicable === true && fields.length) {
            throw new TypeError('Non-applicable input hint contradicts observed query/body inputs.');
          }
          items.push({ ...hint, target_id: targetId });
        }
        if (!items.length) {
          const id = `${method} ${url.pathname}`;
          if (!unresolvedRequests.some(item => `${item.method} ${item.endpoint}` === id)) {
            unresolvedRequests.push({ endpoint: url.pathname, method, reason: 'input_location_not_observed' });
            if (unresolvedRequests.length > MAX_OBSERVATIONS) throw new Error('Too many unresolved parser locations.');
          }
        }
        for (const item of items) {
          const id = JSON.stringify(item);
          if (seen.has(id)) continue;
          seen.add(id);
          observations.push(item);
          if (observations.length > MAX_OBSERVATIONS) throw new Error('Too many parser locations.');
        }
      }
    }
  }
  return { observations, unresolvedRequests };
}

export function observationsFromParser(report, options = {}) {
  return parserReferenceLocations(report, options).observations;
}

function runPython(input, { python, signal, timeoutMs = 30_000 } = {}) {
  const command = python || process.env.CASPER_DB_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
  return new Promise((resolveOutput, rejectOutput) => {
    const child = spawn(command, ['-c', PYTHON_CODE], {
      cwd: ROOT,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONPATH: PYTHON_SOURCE, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
      signal,
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.stdout.on('data', chunk => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) child.kill();
      else stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      if (Buffer.concat(stderr).length < 8192) stderr.push(chunk);
    });
    child.on('error', error => rejectOutput(new Error(`casper-db Python process failed: ${error.message}`)));
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut) return rejectOutput(new Error('casper-db operation exceeded its total time limit.'));
      if (outputBytes > MAX_OUTPUT_BYTES) return rejectOutput(new Error('casper-db output exceeded 1 MB.'));
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString('utf8').slice(-2000);
        return rejectOutput(new Error(`casper-db lookup failed: ${detail || `exit ${code}`}`));
      }
      try { resolveOutput(JSON.parse(Buffer.concat(stdout).toString('utf8'))); }
      catch { rejectOutput(new Error('casper-db returned invalid JSON.')); }
    });
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') rejectOutput(error); });
    child.stdin.end(JSON.stringify(input));
  });
}

export async function matchCasperHistory({ report, origin, targetId = 'vul-web-1', databasePath,
  intakeWorkspace = process.env.CASPER_DB_INTAKE_WORKSPACE,
  externalDatabase = process.env.CASPER_DB_EXTERNAL_PATH, cveIds = [], locationHints = [],
  softwareInventory, python, signal } = {}) {
  softwareInventory ??= inventoryFromParser(report, { targetId }).inventory;
  const { observations, unresolvedRequests } = parserReferenceLocations(report, { targetId, origin, locationHints });
  for (const path of [intakeWorkspace, externalDatabase]) {
    if (path !== undefined && (typeof path !== 'string' || !isAbsolute(path))) {
      throw new TypeError('Reference sources must be absolute paths.');
    }
  }
  const database = absoluteDatabasePath(databasePath ?? process.env.CASPER_DB_PATH);
  try { await access(database); }
  catch { await mkdir(dirname(database), { recursive: true }); }
  const result = await runPython({ database, targetId, observations, unresolvedRequests,
    intakeWorkspace, externalDatabase, cveIds, softwareInventory }, { python, signal });
  if (!result || result.targetId !== targetId || !Array.isArray(result.assessments)
    || result.assessments.length !== observations.length || !Number.isInteger(result.readyCaseCount)) {
    throw new Error('casper-db response does not match the parser lookup contract.');
  }
  return { source: 'casper-db', targetId, readyCaseCount: result.readyCaseCount, observations,
    assessments: result.assessments, referenceContext: result.referenceContext,
    ...(result.knowledgeContext ? { knowledgeContext: result.knowledgeContext } : {}) };
}

/** Collect into the owned source DB; callers preserve the returned context in run evidence. */
export async function syncParserAdvisories({ report, origin, targetId = 'vul-web-1', databasePath,
  softwareInventory, providers = ['github', 'nvd'],
  maxPages = 2, maxRequests = 20, timeoutSeconds = 180, python, signal } = {}) {
  const { observations } = parserReferenceLocations(report, { targetId, origin });
  const converted = inventoryFromParser(report, { targetId });
  softwareInventory ??= converted.inventory;
  if (!softwareInventory) throw new TypeError('Observed software inventory is required for advisory sync.');
  const database = absoluteDatabasePath(databasePath ?? process.env.CASPER_DB_PATH);
  const result = await runPython({ database, operation: 'sync_knowledge', sync: {
    query: { target_id: targetId, observations, inventory: softwareInventory },
    providers, max_pages: maxPages, max_requests: maxRequests, timeout_seconds: timeoutSeconds,
    input_truncated: converted.coverage.truncated, omitted_components: converted.coverage.omitted,
  } }, { python, signal, timeoutMs: timeoutSeconds * 1000 + 5000 });
  if (result?.schema_version !== 'casper-knowledge-sync-1' || result.target_id !== targetId) {
    throw new Error('Advisory sync returned a different parser target.');
  }
  if (converted.coverage.truncated) {
    result.collection_complete = false;
    result.status = 'partial';
  }
  return { ...result, input_coverage: converted.coverage };
}

/** Collection writes the source DB; historical lookups keep the queued snapshot.
 * The returned provider records are frozen in the run's immutable JSON evidence.
 */
export async function prepareParserKnowledge({ report, origin, targetId = 'vul-web-1', databasePath,
  sourceDatabasePath, python, signal, sync = syncParserAdvisories } = {}) {
  const converted = inventoryFromParser(report, { targetId });
  let collection = { status: 'not_observed', collection_complete: false, database_written: false };
  if (converted.inventory) {
    collection = await sync({ report, origin, targetId, databasePath: sourceDatabasePath ?? databasePath,
      softwareInventory: converted.inventory, python, signal });
  }
  const history = await matchCasperHistory({ report, origin, targetId, databasePath,
    softwareInventory: converted.inventory, python, signal });
  const context = history.knowledgeContext ?? { schema_version: 'casper-knowledge-context-1',
    target_id: targetId, automatic_execution_allowed: false, database_written: false,
    external: { status: 'not_requested', candidates: [] } };
  if (collection.knowledge) context.external = collection.knowledge.external;
  context.input_coverage = converted.coverage;
  context.collection = { status: collection.status, collection_complete: collection.collection_complete,
    database_written: collection.database_written, request_count: collection.request_count ?? 0,
    elapsed_seconds: collection.elapsed_seconds ?? 0, journal_id: collection.journal_id ?? null,
    coverage: collection.coverage ?? null, jobs: collection.jobs ?? [], errors: collection.errors ?? [] };
  context.inventory = converted.inventory;
  context.contentDigest = knowledgeContextDigest(context, converted.inventory, converted.coverage, collection);
  return { ...history, knowledgeContext: context };
}
