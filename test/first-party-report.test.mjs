import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeImageAudit } from '../src/first-party-report.mjs';
test('separates known first-party distribution paths from vendor modules', () => {
  const result = summarizeImageAudit({ findings: [
    { rule:'SOURCE_MAP', path:'app/apps/server/dist/main.js.map' },
    { rule:'SOURCE_MAP', path:'app/node_modules/some-package/dist/main.js.map' },
    { rule:'NPMRC', path:'app/.npmrc' }
  ]});
  assert.equal(result.totalFindings, 3);
  assert.equal(result.countsByRule.SOURCE_MAP, 2);
  assert.equal(result.firstPartySourceMaps['app/apps/server/dist/'], 1);
});
