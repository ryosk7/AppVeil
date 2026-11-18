import { readFileSync } from 'node:fs';
const protectedRoots = [
  'app/apps/server/dist/',
  'app/packages/contracts/dist/',
  'app/packages/db/dist/',
  'app/web/'
];
const restrictedRules = new Set([
  'SOURCE_MAP',
  'EMBEDDED_SOURCE_CONTENT',
  'SOURCEMAP_REFERENCE',
  'TYPESCRIPT_SOURCE',
  'ENV_FILE',
  'PRIVATE_KEY',
  'SOURCE_MAP_UNPARSED',
  'SOURCE_MAP_OVERSIZE'
]);

export function evaluateImagePolicy(report) {
  if (report?.schemaVersion !== 1 || !Array.isArray(report.findings)) {
    throw new TypeError('Expected AppVeil schemaVersion 1 image report');
  }
  const firstParty = report.findings.filter(x => typeof x.path === 'string' && protectedRoots.some(root => x.path.startsWith(root)));
  const failures = firstParty.filter(x => restrictedRules.has(x.rule));
  const summary = {};
  for (const f of firstParty) summary[f.rule] = (summary[f.rule] ?? 0) + 1;
  return {
    schemaVersion: 1,
    policy: 'olares-first-party-source-exposure-v1',
    pass: failures.length === 0,
    checkedFirstPartyFindings: firstParty.length,
    violations: failures.map(x => ({ rule: x.rule, path: x.path })),
    countsByRule: summary,
    limitation: 'Checks exported filesystem paths, not historical image layers, JS reverse engineering, secrets embedded in JS, or all vendor packages.'
  };
}
export function evaluateImagePolicyFile(filename) {
  return evaluateImagePolicy(JSON.parse(readFileSync(filename, 'utf8')));
}
