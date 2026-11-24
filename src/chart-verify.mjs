import { readFileSync, statSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { parseTar } from './oci-layers.mjs';

/**
 * Offline verification of a published Olares chart archive (issue #26): every image reference in
 * values.yaml and in templates, whether it is digest-pinned, whether it matches a known-affected
 * digest or tag, and version consistency between Chart.yaml and OlaresManifest.yaml. Nothing in the
 * chart is rendered or executed. Optional `resolve` asks the registry (read-only) for a tag's digest.
 */
const MAX_CHART = 16 * 1024 * 1024;
const DIGEST = /@(sha256:[0-9a-f]{64})$/;

function topLevelScalar(text, key) {
  const m = new RegExp(`^${key.replace('.', '\\.')}:\\s*['"]?([^'"#\\s]+)`, 'm').exec(text);
  return m ? m[1] : null;
}
function nestedScalar(text, parent, key) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(l => new RegExp(`^${parent}:\\s*(?:#.*)?$`).test(l));
  if (start < 0) return null;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^[^\s#]/.test(lines[i])) break;
    const m = new RegExp(`^\\s+${key}:\\s*['"]?([^'"#\\s]+)`).exec(lines[i]);
    if (m) return m[1];
  }
  return null;
}
/** values.yaml `image:` section entries (one level of `key: ref`). */
function valuesImages(text) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(l => /^image:\s*(?:#.*)?$/.test(l));
  const out = {};
  if (start < 0) return out;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^[^\s#]/.test(lines[i])) break;
    const m = /^\s{2,}([A-Za-z0-9_-]+):\s*['"]?([^\s#'"]+)/.exec(lines[i]);
    if (m) out[m[1]] = m[2];
  }
  return out;
}
export function parseImageRef(ref) {
  const digest = DIGEST.exec(ref)?.[1] ?? null;
  const noDigest = ref.replace(DIGEST, '');
  const lastSlash = noDigest.lastIndexOf('/');
  const colon = noDigest.indexOf(':', lastSlash + 1);
  const repository = colon > 0 ? noDigest.slice(0, colon) : noDigest;
  const tag = colon > 0 ? noDigest.slice(colon + 1) : null;
  return { ref, repository, tag, digest };
}

export function readChartArchive(buffer) {
  if (buffer.length > MAX_CHART) throw new Error('Chart archive too large');
  let tar;
  try { tar = gunzipSync(buffer, { maxOutputLength: 64 * 1024 * 1024 }); } catch { throw new Error('Chart archive is not gzip'); }
  const files = new Map();
  for (const e of parseTar(tar, { maxEntries: 2000 })) if (e.type === '0' || e.type === '\0') files.set(e.name, e.data.toString('utf8'));
  return files;
}

export function verifyChart(buffer, { affected = { digests: [] }, requireDigest = false, resolve = null } = {}) {
  const files = readChartArchive(buffer);
  const find = suffix => [...files.keys()].find(k => k.split('/').length === 2 && k.endsWith(`/${suffix}`));
  const chartFile = find('Chart.yaml'), valuesFile = find('values.yaml'), manifestFile = find('OlaresManifest.yaml');
  if (!chartFile || !valuesFile) throw new Error('Chart archive must contain <chart>/Chart.yaml and <chart>/values.yaml');
  const chartYaml = files.get(chartFile), values = files.get(valuesFile), manifest = manifestFile ? files.get(manifestFile) : null;
  const chart = { name: topLevelScalar(chartYaml, 'name'), version: topLevelScalar(chartYaml, 'version'), appVersion: topLevelScalar(chartYaml, 'appVersion') };
  const olares = manifest ? { manifestVersion: topLevelScalar(manifest, 'olaresManifest.version'), version: nestedScalar(manifest, 'metadata', 'version'), versionName: nestedScalar(manifest, 'spec', 'versionName') } : null;
  const refs = [];
  for (const [key, ref] of Object.entries(valuesImages(values))) refs.push({ source: `values.yaml:image.${key}`, ...parseImageRef(ref) });
  for (const [name, text] of files) {
    if (!/\/templates\/.+\.ya?ml$/.test(name)) continue;
    for (const m of text.matchAll(/^\s*image:\s*['"]?([^\s{'"#][^\s'"#]*)/gm)) refs.push({ source: name.split('/').slice(1).join('/'), ...parseImageRef(m[1]) });
  }
  const affectedByDigest = new Map(affected.digests.map(d => [d.digest, d]));
  const affectedRefs = new Map(affected.digests.flatMap(d => d.refs.map(r => [r, d])));
  const problems = [];
  for (const r of refs) {
    if (r.tag === 'latest' || (!r.tag && !r.digest)) problems.push({ ref: r.ref, problem: 'mutable or missing tag' });
    if (resolve && !r.digest) {
      const res = resolve(`${r.repository}${r.tag ? `:${r.tag}` : ''}`);
      r.resolvedDigest = res.digest ?? null;
      if (!res.digest) r.resolveError = res.error;
    }
    const d = r.digest ?? r.resolvedDigest;
    const hit = (d && affectedByDigest.get(d)) || affectedRefs.get(r.ref);
    if (hit) problems.push({ ref: r.ref, problem: `references a known-affected ${hit.app} image (${hit.digest})` });
    if (requireDigest && !r.digest) problems.push({ ref: r.ref, problem: 'not digest-pinned (policy requires @sha256)' });
    if (resolve && !r.digest && !r.resolvedDigest) problems.push({ ref: r.ref, problem: `digest could not be resolved: ${r.resolveError}` });
  }
  const versions = [chart.version, olares?.version, olares?.versionName].filter(Boolean);
  if (new Set(versions).size > 1) problems.push({ ref: null, problem: `version mismatch between Chart.yaml (${chart.version}) and OlaresManifest.yaml (${olares?.version}/${olares?.versionName})` });
  return {
    schemaVersion: 1,
    chart, olares,
    images: refs,
    digestPinned: refs.filter(r => r.digest).length, total: refs.length,
    pass: problems.length === 0,
    problems,
    note: 'Verifies which images the chart deploys, not that those images are clean. Audit each published digest separately (inspect-image --layers, verify-image-report).'
  };
}

/** Read-only registry lookup via `docker buildx imagetools inspect` (no pull, no run). */
export function dockerResolver(ref) {
  const p = spawnSync('docker', ['buildx', 'imagetools', 'inspect', ref, '--format', '{{json .Manifest}}'], { encoding: 'utf8', timeout: 60000 });
  if (p.status !== 0) return { error: (p.stderr || p.error?.message || 'docker failed').trim().split('\n')[0].slice(0, 200) };
  try { const m = JSON.parse(p.stdout); return DIGEST.test(`@${m.digest}`) ? { digest: m.digest } : { error: 'no digest in manifest' }; }
  catch { return { error: 'unparseable imagetools output' }; }
}

export function verifyChartFile(file, options = {}) {
  if (statSync(file).size > MAX_CHART) throw new Error('Chart archive too large');
  return verifyChart(readFileSync(file), options);
}
