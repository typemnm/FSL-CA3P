import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, readFile, readdir, unlink, open } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import protocol from '../../../agent/src/protocol.js';

const { parseEnvelope, replyTo } = protocol;
const DEFAULT_REPORTS_DIR = fileURLToPath(new URL('../../../reports/pentest-db-runs/', import.meta.url));
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function absolutePath(value, name) {
  if (typeof value !== 'string' || !isAbsolute(value)) {
    throw new TypeError(`${name} must be an absolute path.`);
  }
  return resolve(value);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function runDirectory(reportsDir, runId) {
  if (typeof runId !== 'string' || !RUN_ID.test(runId)) {
    throw new TypeError('run-evidence runId must be a safe string of at most 128 characters.');
  }
  // Never turn a request-controlled run ID into a path component.
  return join(reportsDir, digest(runId));
}

function assertStorageRequest(request) {
  if (request.sender !== 'agent' || request.type !== 'storage.request'
    || !['casper-db', 'pentest-db'].includes(request.receiver)) {
    throw new TypeError('run-evidence accepts agent storage.request envelopes only.');
  }
  runDirectory(DEFAULT_REPORTS_DIR, request.runId);
}

// A synced temporary file is linked into place only after it is complete. The
// hard link makes the final name atomic and refuses to replace an existing event
// or report, including when two gateway instances write concurrently.
async function createAtomicJson(path, value, matchesExisting) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const body = `${JSON.stringify(value, null, 2)}\n`;
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(body, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    try {
      await link(temporary, path);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      let existing;
      try { existing = JSON.parse(await readFile(path, 'utf8')); }
      catch { throw new Error('Existing run-evidence artifact is unreadable.'); }
      if (!matchesExisting(existing, value)) {
        throw new Error('A different run-evidence artifact already exists for this request.');
      }
    }
  } finally {
    if (handle) await handle.close();
    await unlink(temporary).catch(error => {
      if (error.code !== 'ENOENT') throw error;
    });
  }
}

function sameJson(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Immutable execution artifacts; the old receiver name is a wire compatibility alias. Each event and final
 * report gets its own immutable, atomic file under reports/pentest-db-runs.
 */
export function createRunEvidenceStore({ reportsDir = DEFAULT_REPORTS_DIR } = {}) {
  const root = absolutePath(reportsDir, 'reportsDir');

  return {
    async exchange(serializedRequest) {
      const request = parseEnvelope(serializedRequest);
      assertStorageRequest(request);
      const operation = request.payload.operation;
      const directory = runDirectory(root, request.runId);
      if (operation === 'append') {
        const event = request.payload.event;
        if (!isRecord(event) || typeof event.stage !== 'string' || !event.stage
          || !isRecord(event.request) || !isRecord(event.response)) {
          throw new TypeError('run-evidence append requires a structured event.');
        }
        const eventDir = join(directory, 'events');
        await mkdir(eventDir, { recursive: true });
        const file = join(eventDir, `${digest(request.messageId)}.json`);
        const record = {
          schemaVersion: '1.0', runId: request.runId, messageId: request.messageId,
          iteration: request.iteration, recordedAt: new Date().toISOString(), event,
        };
        await createAtomicJson(file, record, (old, next) =>
          old.runId === next.runId && old.messageId === next.messageId
          && old.iteration === next.iteration && sameJson(old.event, next.event));
        return JSON.stringify(replyTo(request, request.receiver, 'storage.appended', {
          ok: true, eventType: event.stage,
        }));
      }
      if (operation === 'finalize') {
        const report = request.payload.report;
        if (!isRecord(report) || report.runId !== request.runId
          || !['completed', 'failed'].includes(report.status)) {
          throw new TypeError('run-evidence finalize requires a matching terminal run report.');
        }
        await mkdir(directory, { recursive: true });
        const file = join(directory, 'report.json');
        const record = {
          schemaVersion: '1.0', runId: request.runId,
          storedAt: new Date().toISOString(),
          provenance: {
            source: 'agent-supplied-run-report', storage: 'run-evidence-json',
            verifiedByStorage: false,
          },
          report,
        };
        await createAtomicJson(file, record, (old, next) =>
          old.runId === next.runId && sameJson(old.report, next.report));
        return JSON.stringify(replyTo(request, request.receiver, 'storage.finalized', {
          ok: true, artifactRef: pathToFileURL(file).href,
        }));
      }
      throw new Error(`Unsupported run-evidence operation: ${String(operation)}`);
    },

    async readRun(runId) {
      const directory = runDirectory(root, runId);
      const eventDir = join(directory, 'events');
      let files;
      try { files = (await readdir(eventDir)).filter(name => /^[a-f0-9]{64}\.json$/u.test(name)); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        files = [];
      }
      const events = await Promise.all(files.map(async name => JSON.parse(await readFile(join(eventDir, name), 'utf8'))));
      events.sort((a, b) => a.recordedAt.localeCompare(b.recordedAt) || a.messageId.localeCompare(b.messageId));
      let report = null;
      try { report = JSON.parse(await readFile(join(directory, 'report.json'), 'utf8')); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (!events.length && !report) return null;
      if (events.some(item => item.runId !== runId) || (report && report.runId !== runId)) {
        throw new Error('Stored run-evidence artifact has a mismatched runId.');
      }
      return { runId, events, report };
    },
  };
}
