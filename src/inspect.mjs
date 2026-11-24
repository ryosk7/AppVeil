import { readdirSync, readFileSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { scanSecrets, SECRET_FILE_LIMIT } from './secret-patterns.mjs';

const SKIP = new Set(['.git', 'proc', 'sys', 'dev']);
export const severityRank = s => ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[s] ?? 0;
const rules = [
  { id: 'SOURCE_MAP', severity: 'high', test: p => /\.map$/i.test(p), message: 'Source map shipped' },
  { id: 'TYPESCRIPT_SOURCE', severity: 'medium', test: p => /\.(?:ts|tsx)$/i.test(p) && !/\.d\.ts$/i.test(p), message: 'TypeScript source shipped' },
  { id: 'ENV_FILE', severity: 'high', test: p => /(^|\/)\.env(?:\.|$)/i.test(p), message: 'Environment file shipped; inspect for secrets' },
  { id: 'PRIVATE_KEY', severity: 'critical', test: p => /\.(?:pem|key|p12|pfx)$/i.test(p), message: 'Potential private key or certificate material' },
  { id: 'NPMRC', severity: 'medium', test: p => /(^|\/)\.npmrc$/i.test(p), message: 'npm configuration shipped; check token settings' }
];
export const FIRST_PARTY_MAP_ROOTS = Object.freeze(['app/apps/server/dist/', 'app/packages/contracts/dist/', 'app/packages/db/dist/', 'app/web/']);
const isFirstPartyMap = rel => FIRST_PARTY_MAP_ROOTS.some(prefix => rel.startsWith(prefix));
const MAP_LIMIT = 8 * 1024 * 1024, JS_LIMIT = 2 * 1024 * 1024;
const oversizeMap = rel => ({ rule: 'SOURCE_MAP_OVERSIZE', severity: 'medium', path: rel, message: 'Map too large for embedded-source check' });

/** Path-only rules shared by directory and image-layer scans. */
export function classifyPath(rel) {
  return rules.filter(rule => rule.test(rel)).map(rule => ({ rule: rule.id, severity: rule.severity, path: rel, message: rule.message }));
}
/** Maximum bytes to read for content rules on this path, or 0 when no content rule applies. */
export function contentLimit(rel) {
  if (rel.endsWith('.map') && isFirstPartyMap(rel)) return MAP_LIMIT;
  if (/\.(?:js|mjs|cjs)$/i.test(rel)) return JS_LIMIT;
  return SECRET_FILE_LIMIT;
}
/** Content rules. Output never includes file contents. */
export function classifyContent(rel, bytes) {
  const findings = [];
  if (rel.endsWith('.map') && isFirstPartyMap(rel)) {
    if (bytes.length > MAP_LIMIT) return [oversizeMap(rel)];
    try {
      const json = JSON.parse(bytes.toString('utf8'));
      if (Array.isArray(json.sourcesContent) && json.sourcesContent.some(v => typeof v === 'string' && v.length > 0)) {
        findings.push({ rule: 'EMBEDDED_SOURCE_CONTENT', severity: 'critical', path: rel, message: 'Application source map includes nonempty sourcesContent (contents omitted)' });
      }
    } catch { findings.push({ rule: 'SOURCE_MAP_UNPARSED', severity: 'medium', path: rel, message: 'Map metadata could not be parsed' }); }
  }
  if (/\.(?:js|mjs|cjs)$/i.test(rel) && bytes.length <= JS_LIMIT && /sourceMappingURL\s*=/.test(bytes.toString('utf8'))) {
    findings.push({ rule: 'SOURCEMAP_REFERENCE', severity: 'medium', path: rel, message: 'JavaScript references a source map' });
  }
  findings.push(...scanSecrets(rel, bytes));
  return findings;
}
export function scanTree(root, { maxFiles = 100000, maxDepth = 40, maxContentBytes = 2 * 1024 ** 3 } = {}) {
  const findings = [];
  let contentBytes = 0, budgetReported = false;
  const stack = [{ dir: root, relative: '', depth: 0 }];
  let files = 0;
  while (stack.length) {
    const { dir, relative, depth } = stack.pop();
    if (depth > maxDepth) { findings.push({ rule: 'SCAN_LIMIT', severity: 'high', path: relative, message: 'Maximum directory depth reached' }); continue; }
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); }
    catch (e) { findings.push({ rule: 'SCAN_ERROR', severity: 'high', path: relative, message: `Cannot read directory: ${e.code ?? 'unknown'}` }); continue; }
    for (const entry of entries) {
      const rel = path.posix.join(relative, entry.name);
      if (entry.isSymbolicLink()) continue; // Do not follow links out of the inspected root.
      if (entry.isDirectory()) {
        if (!SKIP.has(entry.name)) stack.push({ dir: path.join(dir, entry.name), relative: rel, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      if (++files > maxFiles) { findings.push({ rule: 'SCAN_LIMIT', severity: 'high', path: rel, message: 'Maximum file count reached' }); return findings; }
      findings.push(...classifyPath(rel));
      const file = path.join(dir, entry.name);
      const limit = contentLimit(rel);
      if (limit) {
        const firstPartyMap = rel.endsWith('.map') && isFirstPartyMap(rel);
        const unreadable = () => { if (firstPartyMap) findings.push({ rule: 'SOURCE_MAP_UNPARSED', severity: 'medium', path: rel, message: 'Map metadata could not be parsed' }); };
        let size, contents;
        try { size = lstatSync(file).size; } catch { unreadable(); continue; }
        if (size > limit) { if (firstPartyMap) findings.push(oversizeMap(rel)); continue; }
        if (contentBytes + size > maxContentBytes) {
          // Never let a skipped content scan look like a clean one.
          if (!budgetReported) findings.push({ rule: 'CONTENT_SCAN_INCOMPLETE', severity: 'high', path: rel, message: `Content-scan byte budget (${maxContentBytes}) exhausted; remaining files were checked by path only` });
          budgetReported = true;
          continue;
        }
        contentBytes += size;
        // A first-party map that cannot be read is reported. Other unreadable files are skipped (best-effort scan).
        try { contents = readFileSync(file); } catch { unreadable(); continue; }
        findings.push(...classifyContent(rel, contents));
      }
    }
  }
  return findings.sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule));
}
