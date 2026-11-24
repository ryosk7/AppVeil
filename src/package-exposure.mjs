import { readdirSync, readFileSync, lstatSync } from 'node:fs';
import path from 'node:path';

/**
 * First-party package exposure policy (issue: core-tech protection).
 *
 * The first-party source-exposure policy (src/image-policy.mjs) deliberately excludes node_modules.
 * But a shared first-party library published to a private registry (e.g. @ryosk7/ragturbo) ships
 * INSIDE node_modules, and its runtime image needs only compiled .js. Type declarations (.d.ts),
 * raw TypeScript, Python sources, .proto schemas and source maps are not needed at runtime and
 * reveal the library's full API surface, types and logic to anyone who holds the image.
 *
 * This analyzer walks the installed copies of configured first-party scopes and reports, per package,
 * which non-runtime artifacts are present. Metadata only: it reports paths and counts, never file
 * contents. It increases the measured cost of reconstruction for anyone WITHOUT host root; it does
 * NOT hide anything from the Olares administrator (see research/CORE_TECH_PROTECTION.md).
 */
export const NON_RUNTIME = Object.freeze([
  { id: 'DECLARATION_FILE', severity: 'medium', test: p => /\.d\.(?:ts|mts|cts)$/i.test(p), message: 'TypeScript declaration file reveals the package API surface and types' },
  { id: 'SOURCE_MAP', severity: 'high', test: p => /\.(?:js|mjs|cjs)\.map$/i.test(p), message: 'Source map can reconstruct original source' },
  { id: 'TYPESCRIPT_SOURCE', severity: 'high', test: p => /\.(?:ts|mts|cts|tsx)$/i.test(p) && !/\.d\.(?:ts|mts|cts)$/i.test(p), message: 'Original TypeScript source shipped' },
  { id: 'PYTHON_SOURCE', severity: 'high', test: p => /\.py$/i.test(p), message: 'Python source shipped' },
  { id: 'PROTO_SCHEMA', severity: 'low', test: p => /\.proto$/i.test(p), message: 'Protobuf schema reveals the wire interface' },
  { id: 'TS_BUILD_INFO', severity: 'low', test: p => /tsconfig.*\.json$|\.tsbuildinfo$/i.test(p), message: 'Build configuration shipped' }
]);
const DEFAULT_LIMITS = Object.freeze({ maxFiles: 200000, maxDepth: 40 });

/** Find installed first-party packages under <root>/node_modules for the given scopes (e.g. "@ryosk7"). */
export function findFirstPartyPackages(root, scopes) {
  const out = [];
  for (const scope of scopes) {
    if (!/^@[a-z0-9][a-z0-9._-]*$/i.test(scope)) throw new Error(`Invalid scope: ${scope}`);
    const scopeDir = path.join(root, 'node_modules', scope);
    let entries;
    try { entries = readdirSync(scopeDir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) if (e.isDirectory() && !e.isSymbolicLink()) out.push({ name: `${scope}/${e.name}`, dir: path.join(scopeDir, e.name) });
  }
  return out;
}

function walk(dir, { maxFiles, maxDepth }) {
  const files = [];
  const stack = [{ d: dir, rel: '', depth: 0 }];
  while (stack.length) {
    const { d, rel, depth } = stack.pop();
    if (depth > maxDepth) continue;
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const r = path.posix.join(rel, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') stack.push({ d: path.join(d, e.name), rel: r, depth: depth + 1 }); continue; }
      if (!e.isFile()) continue;
      if (files.length >= maxFiles) return files;
      files.push(r);
    }
  }
  return files;
}

/** Evaluate one package directory. Returns { package, findings, counts, jsFiles }. */
export function evaluatePackage(name, dir, limits = DEFAULT_LIMITS) {
  const files = walk(dir, { ...DEFAULT_LIMITS, ...limits });
  const findings = [];
  const counts = {};
  let jsFiles = 0;
  for (const rel of files) {
    if (/\.(?:js|mjs|cjs)$/i.test(rel) && !/\.js\.map$/i.test(rel)) jsFiles++;
    for (const rule of NON_RUNTIME) {
      if (rule.test(rel)) { findings.push({ rule: rule.id, severity: rule.severity, package: name, path: rel, message: rule.message }); counts[rule.id] = (counts[rule.id] ?? 0) + 1; break; }
    }
  }
  return { package: name, findings, counts, jsFiles, totalFiles: files.length };
}

/**
 * Audit every installed first-party package. `strictRules` (default: everything except PROTO/BUILD_INFO)
 * decides which findings fail the policy. Returns a schemaVersion 1 report.
 */
export function auditFirstPartyExposure(root, { scopes, strictRules = ['DECLARATION_FILE', 'SOURCE_MAP', 'TYPESCRIPT_SOURCE', 'PYTHON_SOURCE'], limits } = {}) {
  if (!Array.isArray(scopes) || !scopes.length) throw new Error('Provide at least one first-party scope, e.g. @ryosk7');
  const packages = findFirstPartyPackages(root, scopes).map(p => evaluatePackage(p.name, p.dir, limits));
  const strict = new Set(strictRules);
  const violations = packages.flatMap(p => p.findings.filter(f => strict.has(f.rule)));
  const countsByRule = {};
  for (const p of packages) for (const [k, v] of Object.entries(p.counts)) countsByRule[k] = (countsByRule[k] ?? 0) + v;
  return {
    schemaVersion: 1,
    policy: 'first-party-package-exposure-v1',
    scopes,
    packages: packages.map(p => ({ package: p.package, jsFiles: p.jsFiles, totalFiles: p.totalFiles, counts: p.counts })),
    pass: violations.length === 0,
    violations: violations.map(v => ({ rule: v.rule, package: v.package, path: v.path })),
    countsByRule,
    ceiling: 'Reduces what a non-root attacker (image puller, competitor, accidental leak) can read. Does NOT hide compiled .js from the Olares administrator; that is a licensing boundary, not a technical one. See research/CORE_TECH_PROTECTION.md.'
  };
}
