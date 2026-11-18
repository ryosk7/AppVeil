import { readFileSync } from 'node:fs';

export function summarizeImageAudit(data) {
  if (!data || !Array.isArray(data.findings)) throw new TypeError('Expected AppVeil findings array');
  const prefixes = ['app/apps/server/dist/', 'app/packages/contracts/dist/', 'app/packages/db/dist/', 'app/web/'];
  const counts = {};
  for (const f of data.findings) {
    counts[f.rule] = (counts[f.rule] || 0) + 1;
  }
  const firstParty = {};
  for (const prefix of prefixes) {
    firstParty[prefix] = data.findings.filter(f => f.rule === 'SOURCE_MAP' && f.path.startsWith(prefix)).length;
  }
  return { schemaVersion: 1, totalFindings: data.findings.length, countsByRule: counts, firstPartySourceMaps: firstParty, limitations: 'First-party is approximated by known path prefixes. Vendor packages may also be proprietary. Source map contents and leaked secrets are not examined.' };
}
export function summarizeImageAuditFile(filename) {
  return summarizeImageAudit(JSON.parse(readFileSync(filename, 'utf8')));
}
