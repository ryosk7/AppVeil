import { readdirSync, readFileSync, lstatSync } from 'node:fs';
import path from 'node:path';

const SKIP = new Set(['.git', 'proc', 'sys', 'dev']);
export const severityRank = s => ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[s] ?? 0;
const rules = [
  { id: 'SOURCE_MAP', severity: 'high', test: p => /\.map$/i.test(p), message: 'Source map shipped' },
  { id: 'TYPESCRIPT_SOURCE', severity: 'medium', test: p => /\.(?:ts|tsx)$/i.test(p) && !/\.d\.ts$/i.test(p), message: 'TypeScript source shipped' },
  { id: 'ENV_FILE', severity: 'high', test: p => /(^|\/)\.env(?:\.|$)/i.test(p), message: 'Environment file shipped; inspect for secrets' },
  { id: 'PRIVATE_KEY', severity: 'critical', test: p => /\.(?:pem|key|p12|pfx)$/i.test(p), message: 'Potential private key or certificate material' },
  { id: 'NPMRC', severity: 'medium', test: p => /(^|\/)\.npmrc$/i.test(p), message: 'npm configuration shipped; check token settings' }
];
export function scanTree(root, { maxFiles = 100000, maxDepth = 40 } = {}) {
  const findings = [];
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
      for (const rule of rules) if (rule.test(rel)) findings.push({ rule: rule.id, severity: rule.severity, path: rel, message: rule.message });
      // Only inspect our known app build directories. Never include embedded source text in output.
      if (rel.endsWith('.map') && ['app/apps/server/dist/', 'app/packages/contracts/dist/', 'app/packages/db/dist/', 'app/web/'].some(prefix => rel.startsWith(prefix))) {
        try {
          const mapFile = path.join(dir, entry.name);
          if (lstatSync(mapFile).size <= 8 * 1024 * 1024) {
            const json = JSON.parse(readFileSync(mapFile, 'utf8'));
            if (Array.isArray(json.sourcesContent) && json.sourcesContent.some(v => typeof v === 'string' && v.length > 0)) {
              findings.push({ rule: 'EMBEDDED_SOURCE_CONTENT', severity: 'critical', path: rel, message: 'Application source map includes nonempty sourcesContent (contents omitted)' });
            }
          } else findings.push({ rule: 'SOURCE_MAP_OVERSIZE', severity: 'medium', path: rel, message: 'Map too large for embedded-source check' });
        } catch { findings.push({ rule: 'SOURCE_MAP_UNPARSED', severity: 'medium', path: rel, message: 'Map metadata could not be parsed' }); }
      }
      if (/\.(?:js|mjs|cjs)$/i.test(rel)) {
        try {
          const file = path.join(dir, entry.name);
          if (lstatSync(file).size > 2 * 1024 * 1024) continue;
          const contents = readFileSync(file, 'utf8');
          if (/sourceMappingURL\s*=/.test(contents)) findings.push({ rule: 'SOURCEMAP_REFERENCE', severity: 'medium', path: rel, message: 'JavaScript references a source map' });
        } catch { /* File may not be readable. The scan is best-effort. */ }
      }
    }
  }
  return findings.sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule));
}
