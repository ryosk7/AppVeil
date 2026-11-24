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
const TARGET_NAME = /^[a-z][a-z0-9-]{0,31}$/;
/** Parse `target:reason` for an artifact that was not produced, so its absence is explicit. */
export function parseNotChecked(spec) {
  const i = typeof spec === 'string' ? spec.indexOf(':') : -1;
  const target = i > 0 ? spec.slice(0, i) : '', reason = i > 0 ? spec.slice(i + 1).trim() : '';
  if (!TARGET_NAME.test(target) || !reason || reason.length > 200) throw new Error(`Invalid --not-checked value (expected <target>:<reason>): ${spec}`);
  return { target, status: 'not-checked', reason };
}
export function compareArtifacts(paths, markers = [], { notChecked = [] } = {}) {
  if (paths.length < 2) throw new Error('Provide at least two artifact paths');
  const skipped = notChecked.map(parseNotChecked);
  const names = skipped.map(x => x.target);
  if (new Set(names).size !== names.length) throw new Error('Duplicate --not-checked target');
  const samples = paths.map(p => ({ status: 'produced', ...characterizeArtifact(p, markers) }));
  return {
    schemaVersion: 1,
    warning: 'Artifact observability metrics are NOT AI reverse engineering resistance or confidentiality guarantees.',
    samples,
    // Targets that were attempted but not produced. Absent from `samples`, never counted as passed.
    notChecked: skipped
  };
}
