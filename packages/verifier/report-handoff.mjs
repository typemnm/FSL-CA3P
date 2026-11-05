import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';

const SCHEMA = 'verification-handoff/1';

function integrityError(message) {
  const error = new Error(message);
  error.code = 'HANDOFF_INTEGRITY';
  return error;
}

// Re-hashes one image and rejects anything that does not resolve inside outDir/images/.
async function checkImage(outDir, { file, sha256, bytes, label }) {
  const imagesDir = resolve(outDir, 'images');
  const path = resolve(outDir, file);
  if (!path.startsWith(imagesDir + sep)) throw integrityError(`image outside images/: ${file}`);
  const data = await readFile(path);
  const digest = `sha256:${createHash('sha256').update(data).digest('hex')}`;
  if (digest !== sha256 || data.length !== bytes) throw integrityError(`image hash mismatch: ${file}`);
  return { file, sha256, bytes, label };
}

export async function writeReportHandoff(result, { outDir }) {
  const images = [];
  for (const artifact of result.artifacts) images.push(await checkImage(outDir, artifact));
  const path = resolve(outDir, 'verification.json');
  await writeFile(path, JSON.stringify({ schemaVersion: SCHEMA, result, images }, null, 2));
  return { path, files: images.map(image => image.file) };
}

export async function readReportHandoff(dir) {
  const handoff = JSON.parse(await readFile(resolve(dir, 'verification.json'), 'utf8'));
  if (handoff.schemaVersion !== SCHEMA) throw integrityError('unsupported handoff schemaVersion');
  for (const image of handoff.images) await checkImage(dir, image);
  return handoff;
}
