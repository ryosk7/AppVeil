import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

// Conservative observability metrics, NOT AI reverse-engineering resistance.
export function characterizeArtifact(filename, knownMarkers = []) {
  const bytes = readFileSync(filename);
  const text = bytes.toString('latin1');
  const type = /\.(?:mjs|cjs|js)$/i.test(filename) ? 'javascript'
    : /\.wasm$/i.test(filename) ? 'wasm'
    : 'native-or-other';
  return {
    artifact: path.basename(filename),
    type,
    bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    // Marker results indicate artifact-level plaintext exposure only.
    visibleMarkers: knownMarkers.filter(m => typeof m === 'string' && m.length >= 4 && text.includes(m)),
    // This count is not a measure of security or semantic recoverability.
    indicativeStringCount: (text.match(/[\x20-\x7e]{8,}/g) || []).length
  };
}
export function compareArtifacts(paths, markers = []) {
  if (paths.length < 2) throw new Error('Provide at least two artifact paths');
  return { schemaVersion: 1, warning: 'Artifact observability metrics are NOT AI reverse engineering resistance or confidentiality guarantees.', samples: paths.map(p => characterizeArtifact(p, markers)) };
}
