import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync, writeFileSync, renameSync, lstatSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { assertIdentifier, redact, digest, TERMINAL_STATUSES, ACTIVE_STATUSES } from '../contracts/index.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, validateGeneralLoopBudget } from '../contracts/general-loop-budget.mjs';

export const DEFAULT_STORE_PATH = resolve(process.env.CA3P_STORE_PATH ?? fileURLToPath(new URL('../../.runtime/runs.sqlite', import.meta.url)));
const now = () => new Date().toISOString();
const json = value => JSON.stringify(redact(value));
const parse = value => value ? JSON.parse(value) : null;
const fault = (code, message, status = 409) => Object.assign(new Error(message), { code, status });
const SUBTASK_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SUBTASK_DIGEST = /^[a-f0-9]{64}$/u;
const SUBTASK_TERMINAL = new Set(['completed', 'failed', 'cancelled', 'timed_out', 'interrupted']);
const SUBTASK_FINISH = new Set(['completed', 'failed', 'cancelled', 'timed_out']);
function subtaskIdentifier(value, name) {
  if (typeof value !== 'string' || !SUBTASK_ID.test(value)) {
    throw fault('INVALID_SUBTASK', `${name} must be a safe identifier.`, 400);
  }
  return value;
}
function subtaskJson(value, name, maxBytes) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fault('INVALID_SUBTASK', `${name} must be an object.`, 400);
  }
  let serialized;
  try { serialized = json(value); }
  catch { throw fault('INVALID_SUBTASK', `${name} must be JSON data.`, 400); }
  if (!serialized || Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    throw fault('INVALID_SUBTASK', `${name} exceeds its size limit.`, 400);
  }
  return serialized;
}

/** One transaction owns each dispatch intent. An expired lease is never resumed. */
export function createRunRepository({ path = DEFAULT_STORE_PATH, clock = Date.now } = {}) {
  const storePath = path === ':memory:' ? path : resolve(path);
  if (storePath !== ':memory:') mkdirSync(dirname(storePath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(storePath);
  const version = db.prepare('PRAGMA user_version').get().user_version;
  const existing = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
  if ((version !== 0 && version !== 1) || (version === 0 && existing.length && !existing.some(table => table.name === 'runs'))) {
    db.close(); throw fault('UNSUPPORTED_STORE_SCHEMA', 'Refusing to alter an unsupported or unrelated SQLite database.', 503);
  }
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS runs (
      id TEXT PRIMARY KEY, status TEXT NOT NULL, mode TEXT NOT NULL, model_id TEXT NOT NULL,
      manifest_json TEXT NOT NULL, state_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE REFERENCES runs(id), status TEXT NOT NULL,
      options_json TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
      lease_owner TEXT, lease_epoch INTEGER NOT NULL DEFAULT 0, lease_until INTEGER, created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs(status, created_at);
    CREATE TABLE IF NOT EXISTS run_events (
      run_id TEXT NOT NULL REFERENCES runs(id), sequence INTEGER NOT NULL, source_id TEXT NOT NULL,
      event_json TEXT NOT NULL, PRIMARY KEY(run_id, sequence), UNIQUE(run_id, source_id));
    CREATE TABLE IF NOT EXISTS action_intents (
      run_id TEXT NOT NULL REFERENCES runs(id), action_id TEXT NOT NULL, lease_epoch INTEGER NOT NULL,
      status TEXT NOT NULL, request_digest TEXT NOT NULL, result_json TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(run_id, action_id));
    CREATE TABLE IF NOT EXISTS run_subtasks (
      run_id TEXT NOT NULL REFERENCES runs(id), id TEXT NOT NULL,
      source_finding_id TEXT NOT NULL, source_finding_digest TEXT NOT NULL,
      kind TEXT NOT NULL, agent_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled','timed_out','interrupted')),
      input_json TEXT NOT NULL, result_json TEXT, error_code TEXT,
      created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL,
      PRIMARY KEY(run_id, id), UNIQUE(run_id, source_finding_id, source_finding_digest, kind));
    CREATE INDEX IF NOT EXISTS run_subtasks_status_idx ON run_subtasks(run_id, status);
    CREATE TABLE IF NOT EXISTS model_calls (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), sequence INTEGER NOT NULL,
      metadata_json TEXT NOT NULL, UNIQUE(run_id, sequence));
    CREATE TABLE IF NOT EXISTS artifacts (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), kind TEXT NOT NULL,
      path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, metadata_json TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS review_audit (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), check_id TEXT NOT NULL,
      review_json TEXT NOT NULL, recorded_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS experiment_control (
      id INTEGER PRIMARY KEY CHECK(id=1), status TEXT NOT NULL, owner TEXT,
      epoch INTEGER NOT NULL DEFAULT 0, last_reset_at TEXT, summary_json TEXT, error TEXT);
    INSERT OR IGNORE INTO experiment_control(id,status) VALUES (1,'ready');
    CREATE TABLE IF NOT EXISTS pending_target_resets (
      id INTEGER PRIMARY KEY CHECK(id=1), obligations_json TEXT NOT NULL);
    INSERT OR IGNORE INTO pending_target_resets(id,obligations_json) VALUES (1,'[]');
    CREATE TABLE IF NOT EXISTS general_loop_budget (
      id INTEGER PRIMARY KEY CHECK(id=1), limits_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    PRAGMA user_version=1;`);
  db.prepare('INSERT OR IGNORE INTO general_loop_budget(id,limits_json,updated_at) VALUES (1,?,?)')
    .run(JSON.stringify(GENERAL_LOOP_BUDGET_DEFAULTS), now());
  let closed = false;
  function transaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function getRun(id) {
    assertIdentifier(id, 'runId');
    const row = db.prepare('SELECT * FROM runs WHERE id=?').get(id);
    if (!row) return null;
    const state = parse(row.state_json);
    return { ...state, manifest: parse(row.manifest_json),
      reviewAudit: db.prepare('SELECT review_json,recorded_at FROM review_audit WHERE run_id=? ORDER BY recorded_at,id').all(id)
        .map(item => ({ ...parse(item.review_json), recordedAt: item.recorded_at })),
      modelCalls: db.prepare('SELECT metadata_json FROM model_calls WHERE run_id=? ORDER BY sequence').all(id).map(item => parse(item.metadata_json)),
      artifacts: db.prepare('SELECT * FROM artifacts WHERE run_id=? ORDER BY id').all(id)
        .map(item => ({ id: item.id, runId: item.run_id, kind: item.kind, path: item.path, sha256: item.sha256, size: item.size, ...parse(item.metadata_json) })) };
  }
  function experimentState() {
    const row = db.prepare('SELECT * FROM experiment_control WHERE id=1').get();
    return { status: row.status, epoch: row.epoch, lastResetAt: row.last_reset_at,
      summary: parse(row.summary_json), error: row.error };
  }
  function pendingTargetResets() {
    const value = parse(db.prepare('SELECT obligations_json FROM pending_target_resets WHERE id=1').get().obligations_json);
    if (!Array.isArray(value)) throw fault('INVALID_RESET_OBLIGATIONS', 'Stored target reset obligations are invalid.', 503);
    return value;
  }
  function getGeneralLoopBudget() {
    try {
      const row = db.prepare('SELECT limits_json FROM general_loop_budget WHERE id=1').get();
      return validateGeneralLoopBudget(parse(row?.limits_json));
    } catch {
      throw fault('INVALID_GENERAL_LOOP_BUDGET_STORE', 'Stored general loop budget is invalid.', 503);
    }
  }
  function deleteRunRecords() {
    const counts = {};
    for (const table of ['review_audit', 'artifacts', 'model_calls', 'action_intents', 'run_subtasks', 'run_events', 'jobs', 'runs']) {
      counts[table] = db.prepare(`SELECT count(*) AS count FROM ${table}`).get().count;
      db.exec(`DELETE FROM ${table}`);
    }
    return counts;
  }
  function compactRunStore() {
    db.exec('VACUUM');
    const checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
    if (checkpoint.busy) throw fault('RESET_CHECKPOINT_BUSY', 'SQLite cleanup is waiting for another reader. Retry the reset.');
  }
  function assertExperimentReady() {
    if (experimentState().status !== 'ready') {
      throw fault('EXPERIMENT_RESET_REQUIRED', '실험 초기화 또는 검토가 진행 중이거나 이전 초기화에 실패했습니다. 초기화를 완료한 뒤 다시 실행하세요.');
    }
  }
  function assertResetOwner(owner) {
    const row = db.prepare('SELECT status,owner FROM experiment_control WHERE id=1').get();
    if (row.status !== 'resetting' || row.owner !== owner) throw fault('RESET_LOCK_LOST', 'Experiment reset lock no longer belongs to this request.');
  }
  function activeRunCount() {
    return db.prepare(`SELECT count(*) AS count FROM runs WHERE status IN (${ACTIVE_STATUSES.map(() => '?').join(',')})`).get(...ACTIVE_STATUSES).count
      + db.prepare("SELECT count(*) AS count FROM jobs WHERE status IN ('queued','leased')").get().count;
  }
  function assertLease(lease, { allowCancelled = false } = {}) {
    const job = db.prepare('SELECT * FROM jobs WHERE run_id=?').get(lease.runId);
    if (!job || job.status !== 'leased' || job.lease_owner !== lease.owner
      || job.lease_epoch !== lease.epoch || job.lease_until <= clock()) {
      throw fault('LEASE_LOST', 'Worker no longer owns this run.');
    }
    if (!allowCancelled && job.cancel_requested) throw fault('RUN_CANCELLED', 'Run cancellation was requested.');
    return job;
  }
  function subtaskFromRow(row) {
    return row ? { id: row.id, parentRunId: row.run_id,
      sourceFindingId: row.source_finding_id, sourceFindingDigest: row.source_finding_digest,
      kind: row.kind, agentId: row.agent_id, status: row.status,
      input: parse(row.input_json), result: parse(row.result_json), errorCode: row.error_code,
      createdAt: row.created_at, startedAt: row.started_at, completedAt: row.completed_at,
      updatedAt: row.updated_at } : null;
  }
  function getSubtask(runId, id) {
    assertIdentifier(runId, 'runId'); subtaskIdentifier(id, 'subtask ID');
    return subtaskFromRow(db.prepare('SELECT * FROM run_subtasks WHERE run_id=? AND id=?').get(runId, id));
  }
  function terminalizeSubtasks(runId, status, errorCode) {
    const finished = now();
    db.prepare("UPDATE run_subtasks SET status=?,error_code=?,completed_at=?,updated_at=? WHERE run_id=? AND status IN ('queued','running')")
      .run(status, errorCode, finished, finished, runId);
  }
  function withSubtaskStatuses(state, runId, overallStatus) {
    if (!state.multiAgent || !Array.isArray(state.multiAgent.tasks)) return state;
    const tasks = new Map(db.prepare('SELECT id,status,error_code,completed_at FROM run_subtasks WHERE run_id=?')
      .all(runId).map(row => [row.id, row]));
    return { ...state, multiAgent: { ...state.multiAgent,
      ...(overallStatus ? { status: overallStatus, completedAt: now() } : {}),
      tasks: state.multiAgent.tasks.map(item => {
        const stored = tasks.get(item?.id);
        return stored ? { ...item, status: stored.status,
          ...(stored.error_code ? { errorCode: stored.error_code } : {}),
          ...(stored.completed_at ? { completedAt: stored.completed_at } : {}) } : item;
      }) } };
  }
  function reconcileSubtaskState(runId, overallStatus) {
    const row = db.prepare('SELECT state_json FROM runs WHERE id=?').get(runId);
    if (!row) return;
    const state = parse(row.state_json);
    if (!state.multiAgent || !Array.isArray(state.multiAgent.tasks)) return;
    db.prepare('UPDATE runs SET state_json=?,updated_at=? WHERE id=?')
      .run(json(withSubtaskStatuses(state, runId, overallStatus)), now(), runId);
  }
  function recoverExpired() {
    return transaction(() => {
      const expired = db.prepare("SELECT * FROM jobs WHERE status='leased' AND lease_until<=?").all(clock());
      for (const job of expired) {
        const state = parse(db.prepare('SELECT state_json FROM runs WHERE id=?').get(job.run_id).state_json);
        state.status = 'interrupted';
        state.error = 'Worker lease expired. Mutation results may be unknown; start a new isolated run.';
        state.interruption = { at: now(), reason: 'lease_expired', mutationRetryAllowed: false };
        db.prepare("UPDATE jobs SET status='interrupted', lease_epoch=lease_epoch+1 WHERE id=?").run(job.id);
        db.prepare("UPDATE runs SET status='interrupted', state_json=?, updated_at=? WHERE id=?").run(json(state), now(), job.run_id);
        db.prepare("UPDATE action_intents SET status='unknown', updated_at=? WHERE run_id=? AND status='reserved'").run(now(), job.run_id);
        terminalizeSubtasks(job.run_id, 'interrupted', 'PARENT_LEASE_EXPIRED');
        reconcileSubtaskState(job.run_id, 'interrupted');
      }
      return expired.map(item => item.run_id);
    });
  }
  const api = {
    path: storePath,
    experimentState,
    pendingTargetResets,
    getGeneralLoopBudget,
    getSubtask,
    listSubtasks(runId) {
      assertIdentifier(runId, 'runId');
      return db.prepare('SELECT * FROM run_subtasks WHERE run_id=? ORDER BY created_at,id').all(runId).map(subtaskFromRow);
    },
    createSubtask(lease, { id, sourceFindingId, sourceFindingDigest, kind = 'finding-followup', agentId, input = {} } = {}) {
      subtaskIdentifier(id, 'subtask ID'); subtaskIdentifier(sourceFindingId, 'source finding ID');
      subtaskIdentifier(kind, 'subtask kind'); subtaskIdentifier(agentId, 'agent ID');
      if (typeof sourceFindingDigest !== 'string' || !SUBTASK_DIGEST.test(sourceFindingDigest)) {
        throw fault('INVALID_SUBTASK', 'source finding digest must be SHA-256.', 400);
      }
      const inputJson = subtaskJson(input, 'subtask input', 256 * 1024);
      return transaction(() => {
        assertLease(lease);
        const existing = db.prepare('SELECT * FROM run_subtasks WHERE run_id=? AND source_finding_id=? AND source_finding_digest=? AND kind=?')
          .get(lease.runId, sourceFindingId, sourceFindingDigest, kind);
        if (existing) {
          if (existing.id !== id || existing.agent_id !== agentId || existing.input_json !== inputJson) {
            throw fault('SUBTASK_CONFLICT', 'This finding was assigned with different subtask details.');
          }
          return subtaskFromRow(existing);
        }
        if (getSubtask(lease.runId, id)) throw fault('SUBTASK_CONFLICT', 'Subtask ID belongs to a different finding.');
        const created = now();
        db.prepare('INSERT INTO run_subtasks(run_id,id,source_finding_id,source_finding_digest,kind,agent_id,status,input_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
          .run(lease.runId, id, sourceFindingId, sourceFindingDigest, kind, agentId, 'queued', inputJson, created, created);
        return getSubtask(lease.runId, id);
      });
    },
    startSubtask(lease, id) {
      subtaskIdentifier(id, 'subtask ID');
      return transaction(() => {
        assertLease(lease);
        const task = getSubtask(lease.runId, id);
        if (!task) throw fault('SUBTASK_NOT_FOUND', 'Subtask does not belong to this run.', 404);
        if (task.status === 'running') return task;
        if (task.status !== 'queued') throw fault('SUBTASK_NOT_QUEUED', 'Subtask is no longer queued.');
        const started = now();
        db.prepare("UPDATE run_subtasks SET status='running',started_at=?,updated_at=? WHERE run_id=? AND id=?")
          .run(started, started, lease.runId, id);
        return getSubtask(lease.runId, id);
      });
    },
    finishSubtask(lease, id, { status, result, errorCode = null } = {}) {
      subtaskIdentifier(id, 'subtask ID');
      if (!SUBTASK_FINISH.has(status) || (errorCode !== null && (typeof errorCode !== 'string'
        || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(errorCode))) || (status === 'completed' && result === undefined)) {
        throw fault('INVALID_SUBTASK', 'Invalid subtask completion.', 400);
      }
      const resultJson = result === undefined ? null : subtaskJson(result, 'subtask result', 2 * 1024 * 1024);
      return transaction(() => {
        assertLease(lease, { allowCancelled: true });
        const task = getSubtask(lease.runId, id);
        if (!task) throw fault('SUBTASK_NOT_FOUND', 'Subtask does not belong to this run.', 404);
        if (SUBTASK_TERMINAL.has(task.status)) {
          if (task.status === status && JSON.stringify(task.result) === (resultJson ?? 'null')
            && task.errorCode === errorCode) return task;
          throw fault('SUBTASK_ALREADY_FINISHED', 'Subtask result is immutable.');
        }
        if (task.status !== 'running') throw fault('SUBTASK_NOT_RUNNING', 'Subtask has not started.');
        // The worker may record a cancelled task after the parent cancellation.
        // A late successful result must not be published once cancellation is set.
        if (status === 'completed' && db.prepare('SELECT cancel_requested FROM jobs WHERE run_id=?').get(lease.runId).cancel_requested) {
          throw fault('RUN_CANCELLED', 'Run cancellation was requested.');
        }
        const completed = now();
        db.prepare('UPDATE run_subtasks SET status=?,result_json=?,error_code=?,completed_at=?,updated_at=? WHERE run_id=? AND id=?')
          .run(status, resultJson, errorCode, completed, completed, lease.runId, id);
        return getSubtask(lease.runId, id);
      });
    },
    setGeneralLoopBudget(limits) {
      const validated = validateGeneralLoopBudget(limits);
      return transaction(() => {
        db.prepare('UPDATE general_loop_budget SET limits_json=?,updated_at=? WHERE id=1')
          .run(JSON.stringify(validated), now());
        return getGeneralLoopBudget();
      });
    },
    activeRunCount,
    recoverAbandonedExperimentOperation() {
      return transaction(() => {
        const row = db.prepare('SELECT status,owner FROM experiment_control WHERE id=1').get();
        const pid = /^api-(\d+)-(?:reset|mutation)-/.exec(row.owner ?? '')?.[1];
        if (!['resetting', 'reviewing'].includes(row.status) || !pid) return false;
        try { process.kill(Number(pid), 0); return false; }
        catch (failure) { if (failure.code !== 'ESRCH') return false; }
        db.prepare("UPDATE experiment_control SET status='failed',owner=NULL,error=? WHERE id=1")
          .run('이전 초기화 또는 검토 프로세스가 중단되었습니다. 전체 초기화를 다시 수행하세요.');
        return true;
      });
    },
    beginExperimentReset(owner) {
      assertIdentifier(owner, 'reset owner');
      return transaction(() => {
        const state = experimentState();
        if (!['ready', 'failed'].includes(state.status)) throw fault('EXPERIMENT_BUSY', '다른 초기화 또는 검토 작업이 진행 중입니다.');
        if (activeRunCount()) throw fault('RUN_ACTIVE', '실행과 보고서 생성을 중지하고 완료를 기다린 뒤 초기화하세요.');
        db.prepare("UPDATE experiment_control SET status='resetting',owner=?,error=NULL WHERE id=1").run(owner);
        return { ...experimentState(), previousStatus: state.status };
      });
    },
    failExperimentReset(owner) {
      return transaction(() => {
        assertResetOwner(owner);
        db.prepare("UPDATE experiment_control SET status='failed',owner=NULL,error=? WHERE id=1")
          .run('초기화를 완료하지 못했습니다. 새 실행을 시작하기 전에 초기화를 다시 시도하세요.');
        return experimentState();
      });
    },
    completeExperimentReset(owner, summary = {}) {
      // Remove freed SQLite content as well as query-visible rows. External copies,
      // filesystem snapshots and provider records are outside this application's control.
      db.exec('PRAGMA secure_delete=ON');
      const result = transaction(() => {
        assertResetOwner(owner);
        if (activeRunCount()) throw fault('RUN_ACTIVE', 'A worker is still active.');
        const counts = deleteRunRecords();
        db.prepare("UPDATE pending_target_resets SET obligations_json='[]' WHERE id=1").run();
        return { ...summary, deleted: counts };
      });
      compactRunStore();
      transaction(() => {
        assertResetOwner(owner);
        db.prepare("UPDATE experiment_control SET status='ready',owner=NULL,epoch=epoch+1,last_reset_at=?,summary_json=?,error=NULL WHERE id=1")
          .run(now(), json(result));
      });
      return { ...result, epoch: experimentState().epoch, completedAt: experimentState().lastResetAt };
    },
    completeRunHistoryClear(owner, { newTargetObligations = [], wasFailed = false, summary = {} } = {}) {
      if (!Array.isArray(newTargetObligations) || typeof wasFailed !== 'boolean') {
        throw fault('INVALID_HISTORY_CLEAR', 'Invalid run history clear request.', 400);
      }
      db.exec('PRAGMA secure_delete=ON');
      const result = transaction(() => {
        assertResetOwner(owner);
        if (activeRunCount()) throw fault('RUN_ACTIVE', 'A worker is still active.');
        const obligations = [...new Map([...pendingTargetResets(), ...newTargetObligations]
          .map(value => [JSON.stringify(value), value])).values()];
        const counts = deleteRunRecords();
        db.prepare('UPDATE pending_target_resets SET obligations_json=? WHERE id=1').run(json(obligations));
        return { ...summary, deleted: counts, pendingTargetResetCount: obligations.length };
      });
      compactRunStore();
      const clearedAt = now();
      const needsFullReset = wasFailed || result.pendingTargetResetCount > 0;
      transaction(() => {
        assertResetOwner(owner);
        db.prepare('UPDATE experiment_control SET status=?,owner=NULL,epoch=epoch+1,summary_json=?,error=? WHERE id=1')
          .run(needsFullReset ? 'failed' : 'ready', json({ ...result, kind: 'run-history-clear', clearedAt }),
            needsFullReset ? '대상 복원 또는 이전 초기화 실패로 전체 실험 초기화가 필요합니다.' : null);
      });
      return { ...result, epoch: experimentState().epoch, clearedAt, experimentStatus: experimentState().status };
    },
    beginExperimentMutation(owner) {
      assertIdentifier(owner, 'mutation owner');
      return transaction(() => {
        assertExperimentReady();
        db.prepare("UPDATE experiment_control SET status='reviewing',owner=? WHERE id=1").run(owner);
      });
    },
    endExperimentMutation(owner) {
      return transaction(() => {
        const row = db.prepare('SELECT status,owner FROM experiment_control WHERE id=1').get();
        if (row.status !== 'reviewing' || row.owner !== owner) throw fault('MUTATION_LOCK_LOST', 'Experiment mutation lock no longer belongs to this request.');
        db.prepare("UPDATE experiment_control SET status='ready',owner=NULL WHERE id=1").run();
      });
    },
    createRun({ id, mode, modelId, manifest, state, options = {} }) {
      assertIdentifier(id, 'runId');
      if (manifest?.runId !== id || state?.id !== id) throw fault('RUN_ID_MISMATCH', 'Manifest and state must share runId.', 400);
      return transaction(() => {
        assertExperimentReady();
        db.prepare('INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)').run(id, 'queued', mode, modelId, json(manifest), json({ ...state, status: 'queued' }), now(), now());
        db.prepare('INSERT INTO jobs(id,run_id,status,options_json,created_at) VALUES (?,?,?,?,?)').run(randomUUID(), id, 'queued', json(options), now());
        return getRun(id);
      });
    },
    getRun,
    listRuns({ status, mode, modelId, limit = 50, offset = 0 } = {}) {
      limit = Number(limit); offset = Number(offset);
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200 || !Number.isSafeInteger(offset) || offset < 0) {
        throw fault('INVALID_PAGINATION', 'limit must be 1..200 and offset a non-negative integer.', 400);
      }
      const terms = []; const values = [];
      for (const [column, value] of [['status', status], ['mode', mode], ['model_id', modelId]]) if (value) { terms.push(`${column}=?`); values.push(value); }
      const where = terms.length ? ` WHERE ${terms.join(' AND ')}` : '';
      const total = db.prepare(`SELECT count(*) AS count FROM runs${where}`).get(...values).count;
      const items = db.prepare(`SELECT id FROM runs${where} ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`).all(...values, limit, offset)
        .map(row => getRun(row.id));
      return { items, total, limit, offset };
    },
    claimNext(owner, { leaseMs = 15_000 } = {}) {
      assertIdentifier(owner, 'lease owner');
      recoverExpired();
      return transaction(() => {
        if (experimentState().status !== 'ready') return null;
        const job = db.prepare("SELECT * FROM jobs WHERE status='queued' AND cancel_requested=0 ORDER BY created_at,id LIMIT 1").get();
        if (!job) return null;
        const epoch = job.lease_epoch + 1;
        db.prepare("UPDATE jobs SET status='leased',lease_owner=?,lease_epoch=?,lease_until=? WHERE id=?").run(owner, epoch, clock() + leaseMs, job.id);
        const state = getRun(job.run_id);
        state.status = 'preparing';
        db.prepare("UPDATE runs SET status='preparing',state_json=?,updated_at=? WHERE id=?").run(json(state), now(), job.run_id);
        return { runId: job.run_id, owner, epoch, options: parse(job.options_json), mode: state.mode, modelId: state.modelId };
      });
    },
    assertLease,
    heartbeat(lease, { leaseMs = 15_000 } = {}) {
      return transaction(() => {
        const job = assertLease(lease, { allowCancelled: true });
        db.prepare('UPDATE jobs SET lease_until=? WHERE id=?').run(clock() + leaseMs, job.id);
        return { cancelRequested: Boolean(job.cancel_requested) };
      });
    },
    saveState(lease, state) {
      return transaction(() => {
        const job = assertLease(lease, { allowCancelled: true });
        if (state.id !== lease.runId) throw fault('RUN_ID_MISMATCH', 'Runtime runId changed.');
        for (const event of state.events ?? []) {
          if (db.prepare('SELECT 1 FROM run_events WHERE run_id=? AND source_id=?').get(lease.runId, event.id)) continue;
          const sequence = db.prepare('SELECT COALESCE(MAX(sequence),0)+1 AS n FROM run_events WHERE run_id=?').get(lease.runId).n;
          db.prepare('INSERT INTO run_events VALUES (?,?,?,?)').run(lease.runId, sequence, event.id, json({ ...event, sequence }));
        }
        const events = api.listEvents(lease.runId);
        const status = job.cancel_requested && ACTIVE_STATUSES.includes(state.status)
          ? 'stopping' : state.status;
        const next = withSubtaskStatuses({ ...state, status, events,
          modelId: getRun(lease.runId).modelId }, lease.runId);
        db.prepare('UPDATE runs SET status=?,state_json=?,updated_at=? WHERE id=?').run(next.status, json(next), now(), lease.runId);
        return getRun(lease.runId);
      });
    },
    listEvents(id, { after = 0, limit = 1000 } = {}) {
      assertIdentifier(id, 'runId');
      if (!Number.isSafeInteger(Number(after)) || Number(after) < 0 || !Number.isSafeInteger(Number(limit)) || Number(limit) < 1 || Number(limit) > 5000) {
        throw fault('INVALID_EVENT_CURSOR', 'Invalid event cursor or limit.', 400);
      }
      return db.prepare('SELECT event_json FROM run_events WHERE run_id=? AND sequence>? ORDER BY sequence LIMIT ?').all(id, Number(after), Number(limit)).map(item => parse(item.event_json));
    },
    reserveAction(lease, { actionId, request }) {
      assertIdentifier(actionId, 'actionId');
      return transaction(() => {
        assertLease(lease);
        if (db.prepare('SELECT 1 FROM action_intents WHERE run_id=? AND action_id=?').get(lease.runId, actionId)) {
          throw fault('ACTION_ALREADY_RESERVED', 'A mutation was already reserved. It will not be resent.');
        }
        db.prepare('INSERT INTO action_intents VALUES (?,?,?,?,?,?,?,?)').run(lease.runId, actionId, lease.epoch, 'reserved', digest(request), null, now(), now());
        return actionId;
      });
    },
    completeAction(lease, actionId, result) {
      return transaction(() => {
        assertLease(lease, { allowCancelled: true });
        const update = db.prepare("UPDATE action_intents SET status='completed',result_json=?,updated_at=? WHERE run_id=? AND action_id=? AND lease_epoch=? AND status='reserved'")
          .run(json(result), now(), lease.runId, actionId, lease.epoch);
        if (update.changes !== 1) throw fault('ACTION_RESERVATION_LOST', 'Mutation reservation no longer belongs to this worker.');
      });
    },
    listActions(id) { return db.prepare('SELECT * FROM action_intents WHERE run_id=? ORDER BY created_at').all(id); },
    recordReview(id, review) {
      return transaction(() => {
        if (!['ready', 'reviewing'].includes(experimentState().status)) assertExperimentReady();
        const state = getRun(id);
        if (!state) throw fault('RUN_NOT_FOUND', 'Run not found.', 404);
        const checks = state.historyWrite?.checks ?? [];
        const index = checks.findIndex(item => item.check_id === review.check_id);
        if (index < 0) throw fault('CHECK_NOT_LINKED', 'Check does not belong to this run.', 404);
        if (review.run_id !== id) throw fault('RUN_ID_MISMATCH', 'Review runId does not match.', 400);
        checks[index] = redact(review);
        state.reviewItems = (state.reviewItems ?? []).map(item => ({ ...item,
          status: review.review_status === 'reviewed' ? 'reviewed' : item.status }));
        db.prepare('INSERT INTO review_audit VALUES (?,?,?,?,?)').run(randomUUID(), id, review.check_id, json(review), now());
        db.prepare('UPDATE runs SET state_json=?,updated_at=? WHERE id=?').run(json(state), now(), id);
        return getRun(id);
      });
    },
    recordModelCall(lease, metadata) {
      return transaction(() => {
        assertLease(lease, { allowCancelled: true });
        const sequence = db.prepare('SELECT COALESCE(MAX(sequence),0)+1 AS n FROM model_calls WHERE run_id=?').get(lease.runId).n;
        db.prepare('INSERT INTO model_calls VALUES (?,?,?,?)').run(randomUUID(), lease.runId, sequence, json({ ...metadata, sequence }));
      });
    },
    finish(lease, status) {
      if (!TERMINAL_STATUSES.includes(status)) throw fault('INVALID_TERMINAL_STATUS', 'Invalid terminal status.');
      return transaction(() => {
        assertLease(lease, { allowCancelled: true });
        if (status === 'completed' && db.prepare("SELECT 1 FROM run_subtasks WHERE run_id=? AND status IN ('queued','running') LIMIT 1").get(lease.runId)) {
          throw fault('SUBTASKS_ACTIVE', 'Finish all subtasks before completing their parent run.');
        }
        db.prepare('UPDATE jobs SET status=?,lease_until=NULL WHERE run_id=?').run(status, lease.runId);
        db.prepare("UPDATE action_intents SET status='unknown',updated_at=? WHERE run_id=? AND status='reserved'").run(now(), lease.runId);
        terminalizeSubtasks(lease.runId, status === 'cancelled' ? 'cancelled' : 'interrupted',
          status === 'cancelled' ? 'PARENT_CANCELLED' : 'PARENT_FINISHED');
        const state = withSubtaskStatuses(getRun(lease.runId), lease.runId,
          status === 'cancelled' ? 'cancelled' : status === 'interrupted' ? 'interrupted'
            : status === 'failed' ? 'partial' : undefined);
        state.status = status;
        db.prepare('UPDATE runs SET status=?,state_json=?,updated_at=? WHERE id=?').run(status, json(state), now(), lease.runId);
        return getRun(lease.runId);
      });
    },
    requestCancel(id) {
      return transaction(() => {
        const state = getRun(id);
        if (!state) throw fault('RUN_NOT_FOUND', 'Run not found.', 404);
        if (TERMINAL_STATUSES.includes(state.status)) return state;
        const queued = state.status === 'queued'; state.status = queued ? 'cancelled' : 'stopping';
        db.prepare("UPDATE jobs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE run_id=?").run(id);
        db.prepare("UPDATE run_subtasks SET status='cancelled',error_code='PARENT_CANCELLED',completed_at=?,updated_at=? WHERE run_id=? AND status='queued'")
          .run(now(), now(), id);
        db.prepare('UPDATE runs SET status=?,state_json=?,updated_at=? WHERE id=?').run(state.status, json(state), now(), id);
        reconcileSubtaskState(id, queued ? 'cancelled' : undefined);
        return withSubtaskStatuses(state, id, queued ? 'cancelled' : undefined);
      });
    },
    recoverExpired,
    interruptOwner(owner, reason = 'Worker process exited.') {
      return transaction(() => {
        const jobs = db.prepare("SELECT * FROM jobs WHERE status='leased' AND lease_owner=?").all(owner);
        for (const job of jobs) {
          const state = getRun(job.run_id); state.status = 'interrupted'; state.error = reason;
          state.interruption = { at: now(), reason, mutationRetryAllowed: false };
          db.prepare("UPDATE jobs SET status='interrupted',lease_epoch=lease_epoch+1,lease_until=NULL WHERE id=?").run(job.id);
          db.prepare("UPDATE runs SET status='interrupted',state_json=?,updated_at=? WHERE id=?").run(json(state), now(), job.run_id);
          db.prepare("UPDATE action_intents SET status='unknown',updated_at=? WHERE run_id=? AND status='reserved'").run(now(), job.run_id);
          terminalizeSubtasks(job.run_id, 'interrupted', 'PARENT_INTERRUPTED');
          reconcileSubtaskState(job.run_id, 'interrupted');
        }
        return jobs.map(item => item.run_id);
      });
    },
    writeArtifact(id, kind, value, metadata = {}) {
      assertIdentifier(id, 'runId'); assertIdentifier(kind, 'artifact kind');
      if (!getRun(id)) throw fault('RUN_NOT_FOUND', 'Run not found.', 404);
      const bytes = Buffer.from(json(value)); const sha256 = digest(bytes);
      const directory = join(dirname(storePath === ':memory:' ? resolve('.runtime/runs.sqlite') : storePath), 'artifacts', digest(id));
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const path = join(directory, `${sha256}.json`); const temporary = `${path}.${randomUUID()}.tmp`;
      writeFileSync(temporary, bytes, { mode: 0o600, flag: 'wx' }); renameSync(temporary, path);
      const artifactId = digest(`${id}:${kind}:${sha256}`);
      db.prepare('INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?,?)').run(artifactId, id, kind, path, sha256, bytes.length, json(metadata));
      return { id: artifactId, runId: id, kind, path, sha256, size: bytes.length };
    },
    writeBinaryArtifact(id, kind, value, metadata = {}) {
      assertIdentifier(id, 'runId'); assertIdentifier(kind, 'artifact kind');
      if (!getRun(id)) throw fault('RUN_NOT_FOUND', 'Run not found.', 404);
      if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > 50 * 1024 * 1024) {
        throw fault('INVALID_ARTIFACT', 'Binary artifacts must contain between 1 byte and 50 MiB.', 400);
      }
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)
        || Object.keys(metadata).some(key => ['id', 'runId', 'kind', 'path', 'sha256', 'size'].includes(key))) {
        throw fault('INVALID_ARTIFACT', 'Artifact metadata cannot change its identity or storage path.', 400);
      }
      const filename = metadata.filename;
      if (typeof filename !== 'string' || !filename || filename.length > 240
        || basename(filename) !== filename || /[\\/\u0000-\u001f\u007f]/u.test(filename)
        || (kind === 'hwpx-report' && !filename.toLowerCase().endsWith('.hwpx'))) {
        throw fault('INVALID_ARTIFACT', 'Provide a safe artifact file name.', 400);
      }
      const bytes = Buffer.from(value); const sha256 = digest(bytes);
      const directory = join(dirname(storePath === ':memory:' ? resolve('.runtime/runs.sqlite') : storePath), 'artifacts', digest(id));
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const path = join(directory, `${sha256}${kind === 'hwpx-report' ? '.hwpx' : '.bin'}`);
      // The file is discoverable through the API only after the DB insert.
      // Exclusive creation keeps an existing download immutable and works on
      // filesystems that do not support hard links. An interrupted unpublished
      // write is rejected by the digest check instead of being overwritten.
      try { writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' }); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const info = lstatSync(path);
        if (!info.isFile() || info.isSymbolicLink() || digest(readFileSync(path)) !== sha256) {
          throw fault('ARTIFACT_CHANGED', 'Stored artifact hash no longer matches.', 500);
        }
      }
      const artifactId = digest(`${id}:${kind}:${sha256}`);
      db.prepare('INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?,?)')
        .run(artifactId, id, kind, path, sha256, bytes.length, json(metadata));
      return { ...redact(metadata), id: artifactId, runId: id, kind, path, sha256, size: bytes.length };
    },
    getArtifact(id) {
      const artifact = db.prepare('SELECT * FROM artifacts WHERE id=?').get(id);
      return artifact ? { id: artifact.id, runId: artifact.run_id, kind: artifact.kind,
        path: artifact.path, sha256: artifact.sha256, size: artifact.size, ...parse(artifact.metadata_json) } : null;
    },
    importLegacyRun(record) {
      const report = record?.report?.report ?? record?.report;
      const id = record?.runId ?? report?.runId;
      assertIdentifier(id, 'legacy runId');
      if (getRun(id)) return getRun(id);
      const state = { id, coreRunId: id, status: report?.status === 'completed' ? 'completed' : 'failed',
        mode: 'legacy-import', simulated: report?.simulated ?? null, targetContacted: report?.targetContacted ?? null,
        target: report?.target?.origin ?? null, startedAt: report?.startedAt ?? now(), report,
        events: [], snapshots: {}, reviewItems: [], provenanceIncomplete: true };
      const manifest = { schemaVersion: '1.0', runId: id, provenance: 'legacy-import',
        source: { commitSha: null }, model: null, data: null, policy: null,
        missingValuesMean: 'unavailable', legacyUiRunId: record.legacyUiRunId ?? null };
      transaction(() => {
        if (!['ready', 'reviewing'].includes(experimentState().status)) assertExperimentReady();
        db.prepare('INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)').run(id, state.status, state.mode, 'unavailable', json(manifest), json(state), state.startedAt, now());
        for (const [index, item] of (record.events ?? []).entries()) {
          const event = item.event ?? item;
          db.prepare('INSERT INTO run_events VALUES (?,?,?,?)').run(id, index + 1, item.messageId ?? `legacy-${index + 1}`, json({ ...event, sequence: index + 1, provenance: 'legacy-import' }));
        }
        state.events = api.listEvents(id);
        db.prepare('UPDATE runs SET state_json=? WHERE id=?').run(json(state), id);
      });
      return getRun(id);
    },
    close() { if (!closed) { closed = true; db.close(); } },
  };
  return api;
}

export const readArtifactBytes = artifact => {
  const bytes = readFileSync(artifact.path);
  if (digest(bytes) !== artifact.sha256) throw fault('ARTIFACT_CHANGED', 'Stored artifact hash no longer matches.', 500);
  return bytes;
};
