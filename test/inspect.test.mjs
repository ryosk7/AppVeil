import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanTree } from '../src/inspect.mjs';

test('finds source maps, TypeScript, npmrc, and env files', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'appveil-test-'));
  try {
    mkdirSync(path.join(root, 'app'));
    writeFileSync(path.join(root, 'app', 'server.ts'), 'console.log(1)');
    writeFileSync(path.join(root, 'app', 'server.js.map'), '{}');
    writeFileSync(path.join(root, '.npmrc'), 'registry=example');
    writeFileSync(path.join(root, '.env.production'), 'PLACEHOLDER=1');
    writeFileSync(path.join(root, 'app', 'index.js'), '//# sourceMappingURL=index.js.map');
    const ids = scanTree(root).map(x => x.rule);
    for (const id of ['TYPESCRIPT_SOURCE', 'SOURCE_MAP', 'NPMRC', 'ENV_FILE', 'SOURCEMAP_REFERENCE']) assert.ok(ids.includes(id), id);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test('does not follow symlinks', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'appveil-test-'));
  try {
    symlinkSync('/etc', path.join(root, 'outside'));
    assert.deepEqual(scanTree(root), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
