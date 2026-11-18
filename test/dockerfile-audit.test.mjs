import test from 'node:test';
import assert from 'node:assert/strict';
import { auditDockerfileText } from '../src/dockerfile-audit.mjs';

test('finds copied npmrc in final stage without treating build stages as shipped', () => {
  const src = 'FROM node:24 AS build\nCOPY . .\nFROM node:24\nCOPY --from=build /src/.npmrc ./\nUSER 1000\n';
  const rules = auditDockerfileText(src).map(f => f.rule);
  assert.deepEqual(rules, ['NPMRC_IN_RUNTIME']);
});
test('flags root and full build context in runtime', () => {
  const src = 'FROM node:24\nCOPY . .\nCMD ["node", "app.js"]';
  const rules = auditDockerfileText(src).map(f => f.rule);
  assert.ok(rules.includes('COPY_ALL_IN_RUNTIME'));
  assert.ok(rules.includes('ROOT_RUNTIME'));
});
