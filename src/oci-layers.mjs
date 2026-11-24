import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';
import { classifyPath, classifyContent, contentLimit } from './inspect.mjs';

/**
 * Offline audit of a `docker save` image archive: every layer (including files later deleted by
 * whiteouts or overwritten) plus the image config and history. Nothing in the image is executed or
 * extracted to disk. Output is metadata only: paths, rule IDs, layer digests, key NAMES, never values.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxArchiveBytes: 4 * 1024 ** 3,
  maxLayerBytes: 2 * 1024 ** 3,
  maxEntries: 500_000,
  maxLayers: 256,
  maxJsonBytes: 16 * 1024 ** 2
});

const BLOCK = 512;
function field(buf, off, len) {
  const end = buf.indexOf(0, off);
  return buf.toString('utf8', off, end >= 0 && end < off + len ? end : off + len);
}
function octal(buf, off, len) {
  // GNU base-256 encoding for large sizes.
  if (buf[off] & 0x80) {
    let v = 0n;
    for (let i = 1; i < len; i++) v = (v << 8n) | BigInt(buf[off + i]);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Tar entry size too large');
    return Number(v);
  }
  const s = field(buf, off, len).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) throw new Error('Malformed tar header (numeric field)');
  return parseInt(s, 8);
}
function checksumOk(h) {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
  return sum === octal(h, 148, 8);
}
function parsePax(data) {
  const out = {};
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) throw new Error('Malformed pax header');
    const len = Number(data.toString('ascii', i, sp));
    if (!Number.isSafeInteger(len) || len <= 0 || i + len > data.length) throw new Error('Malformed pax header');
    const rec = data.toString('utf8', sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}
/** Normalize an archive member path. Absolute paths and `..` traversal fail closed. */
export function normalizeMemberPath(name) {
  if (typeof name !== 'string' || name.includes('\0')) throw new Error('Invalid tar member path');
  const stripped = name.replace(/^(\.\/)+/, '');
  if (stripped.startsWith('/') || stripped.split('/').includes('..')) throw new Error(`Unsafe tar member path rejected: ${JSON.stringify(name.slice(0, 200))}`);
  return path.posix.normalize(stripped).replace(/\/$/, '').replace(/^\.$/, '');
}

/** Parse an uncompressed tar buffer into { name, type, size, data } entries (data is a subarray, not copied). */
export function parseTar(buf, { maxEntries = DEFAULT_LIMITS.maxEntries } = {}) {
  const entries = [];
  let off = 0, longName = null, pax = null;
  while (off + BLOCK <= buf.length) {
    const h = buf.subarray(off, off + BLOCK);
    if (h.every(b => b === 0)) break;
    if (!checksumOk(h)) throw new Error(`Malformed tar header checksum at offset ${off}`);
    const size = octal(h, 124, 12);
    const type = String.fromCharCode(h[156] || 0x30);
    const dataStart = off + BLOCK, dataEnd = dataStart + size;
    if (dataEnd > buf.length) throw new Error('Truncated tar entry');
    const data = buf.subarray(dataStart, dataEnd);
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;
    if (type === 'L') { longName = field(data, 0, data.length); continue; }
    if (type === 'x') { pax = parsePax(data); continue; }
    if (type === 'g') continue;
    const magic = h.toString('ascii', 257, 262);
    const prefix = magic === 'ustar' ? field(h, 345, 155) : '';
    const raw = pax?.path ?? longName ?? (prefix ? `${prefix}/${field(h, 0, 100)}` : field(h, 0, 100));
    longName = null; pax = null;
    if (entries.length >= maxEntries) throw new Error(`Tar entry limit (${maxEntries}) exceeded`);
    entries.push({ name: normalizeMemberPath(raw), type, size, data });
  }
  return entries;
}

function decompressLayer(blob, limits) {
  if (blob[0] === 0x1f && blob[1] === 0x8b) return { compression: 'gzip', tar: gunzipSync(blob, { maxOutputLength: limits.maxLayerBytes }) };
  if (blob[0] === 0x28 && blob[1] === 0xb5 && blob[2] === 0x2f && blob[3] === 0xfd) return { compression: 'zstd', tar: null };
  return { compression: 'none', tar: blob };
}

const SECRET_NAME = /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH|SESSION_?KEY|SIGNING_?KEY|NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN)(?:_|$)/i;
const isSecretName = name => SECRET_NAME.test(name);

/** Scan image config Env and build history for secret-like variable NAMES (values never reported). */
export function scanImageConfig(config) {
  const findings = [];
  const env = config?.config?.Env ?? config?.container_config?.Env ?? [];
  if (!Array.isArray(env)) throw new Error('Malformed image config Env');
  for (const kv of env) {
    if (typeof kv !== 'string') continue;
    const name = kv.split('=', 1)[0];
    if (isSecretName(name)) findings.push({ rule: 'CONFIG_ENV_SECRET_NAME', severity: 'high', path: `config:Env/${name}`, message: 'Image config sets a secret-like environment variable (value omitted)' });
  }
  const history = Array.isArray(config?.history) ? config.history : [];
  history.forEach((h, i) => {
    const cmd = typeof h?.created_by === 'string' ? h.created_by : '';
    const names = new Set();
    // Legacy builder: `|N A=1 /bin/sh -c ...`; BuildKit: `RUN |N A=1 /bin/sh -c ...`.
    const argPrefix = /^(?:RUN\s+)?\|\d+\s+((?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+)/.exec(cmd);
    if (argPrefix) for (const m of argPrefix[1].matchAll(/([A-Za-z_][A-Za-z0-9_]*)=/g)) names.add(m[1]);
    for (const m of cmd.matchAll(/\b(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)/g)) names.add(m[1]);
    for (const name of names) if (isSecretName(name)) findings.push({ rule: 'HISTORY_SECRET_NAME', severity: 'high', path: `config:history/${i}/${name}`, message: 'Build history references a secret-like build arg or env (value omitted)' });
  });
  return findings;
}

function readJsonMember(members, name, limits) {
  const m = members.get(name);
  if (!m) throw new Error(`Image archive member not found: ${name}`);
  if (m.size > limits.maxJsonBytes) throw new Error(`Image archive JSON member too large: ${name}`);
  try { return JSON.parse(m.data.toString('utf8')); } catch { throw new Error(`Malformed JSON in image archive: ${name}`); }
}

/** Audit a docker-save archive buffer. Returns a schemaVersion 1 report. */
export function auditImageArchive(archive, limits = DEFAULT_LIMITS) {
  limits = { ...DEFAULT_LIMITS, ...limits };
  const members = new Map(parseTar(archive, limits).filter(e => e.type === '0' || e.type === '\0').map(e => [e.name, e]));
  const manifest = readJsonMember(members, 'manifest.json', limits);
  if (!Array.isArray(manifest) || manifest.length !== 1) throw new Error('Expected manifest.json with exactly one image (save one image per archive)');
  const { Config, Layers, RepoTags } = manifest[0] ?? {};
  if (typeof Config !== 'string' || !Array.isArray(Layers) || Layers.some(l => typeof l !== 'string')) throw new Error('Malformed manifest.json');
  if (Layers.length > limits.maxLayers) throw new Error(`Layer limit (${limits.maxLayers}) exceeded`);
  const config = readJsonMember(members, normalizeMemberPath(Config), limits);
  const findings = scanImageConfig(config);
  const layers = [];
  // Track the layer that last provided each path, so earlier copies can be labeled overwritten or deleted.
  const occurrences = [];
  const byPath = new Map(); // path -> occurrences not yet superseded
  Layers.forEach((layerPath, index) => {
    const member = members.get(normalizeMemberPath(layerPath));
    if (!member) throw new Error(`Layer blob not found in archive: ${layerPath}`);
    const digest = `sha256:${createHash('sha256').update(member.data).digest('hex')}`;
    const { compression, tar } = decompressLayer(member.data, limits);
    if (!tar) {
      layers.push({ index, digest, compression, status: 'not-checked', reason: `${compression} layers are not supported by this scanner` });
      return;
    }
    const entries = parseTar(tar, limits);
    let files = 0;
    const whiteouts = [], opaque = [];
    for (const e of entries) {
      const base = path.posix.basename(e.name), dir = path.posix.dirname(e.name);
      if (base === '.wh..wh..opq') { opaque.push(dir === '.' ? '' : dir); continue; }
      if (base.startsWith('.wh.')) { whiteouts.push(path.posix.join(dir === '.' ? '' : dir, base.slice(4))); continue; }
      if (e.type !== '0' && e.type !== '\0') continue;
      files++;
      const found = classifyPath(e.name);
      const limit = contentLimit(e.name);
      if (limit) found.push(...classifyContent(e.name, e.data));
      // A file written again in a later layer supersedes earlier copies, which stay recoverable.
      const earlier = byPath.get(e.name);
      if (earlier) { for (const o of earlier) if (o.layer < index) o.supersededBy = { layer: index, how: 'overwritten' }; byPath.set(e.name, earlier.filter(o => o.layer === index)); }
      for (const f of found) {
        const o = { ...f, layer: index, layerDigest: digest };
        occurrences.push(o);
        if (!byPath.has(e.name)) byPath.set(e.name, []);
        byPath.get(e.name).push(o);
      }
    }
    for (const o of occurrences) {
      if (o.layer >= index || o.supersededBy) continue;
      if (whiteouts.some(w => o.path === w || o.path.startsWith(`${w}/`)) || opaque.some(d => d === '' || o.path.startsWith(`${d}/`))) {
        o.supersededBy = { layer: index, how: 'deleted' };
      }
    }
    layers.push({ index, digest, compression, status: 'scanned', files, whiteouts: whiteouts.length + opaque.length });
  });
  for (const o of occurrences) {
    const { supersededBy, ...f } = o;
    findings.push({
      ...f,
      finalFilesystem: supersededBy ? supersededBy.how : 'present',
      ...(supersededBy ? { message: `${f.message}; ${supersededBy.how} in layer ${supersededBy.layer} but still recoverable from layer ${f.layer}` } : {})
    });
  }
  findings.sort((a, b) => (a.layer ?? -1) - (b.layer ?? -1) || a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule));
  const complete = layers.every(l => l.status === 'scanned');
  return {
    schemaVersion: 1,
    kind: 'appveil-image-layer-audit',
    image: { repoTags: Array.isArray(RepoTags) ? RepoTags.filter(t => typeof t === 'string') : [], configDigest: `sha256:${createHash('sha256').update(members.get(normalizeMemberPath(Config)).data).digest('hex')}` },
    complete,
    layers,
    findings,
    limitations: 'Metadata only. Checks file paths, first-party source-map content and sourceMappingURL references in every layer, plus secret-like variable NAMES in config and history. It does not detect secrets inside file contents, does not stop reverse engineering, and an empty result is not proof of a clean image.'
  };
}

export function auditImageArchiveFile(filename, limits = DEFAULT_LIMITS) {
  const size = statSync(filename).size;
  const max = limits.maxArchiveBytes ?? DEFAULT_LIMITS.maxArchiveBytes;
  if (size > max) throw new Error(`Image archive larger than ${max} bytes`);
  return auditImageArchive(readFileSync(filename), limits);
}
