import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanTree } from '../src/inspect.mjs';

test('finds embedded first-party source without printing its contents', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'appveil-map-'));
  try {
    const dir = path.join(root, 'app/apps/server/dist');
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'main.js.map'), JSON.stringify({
      version: 3, sources: ['../src/main.ts'], sourcesContent: ['SECRET_SYNTHETIC_TEST_MARKER']
    }));
    const results = scanTree(root);
    assert.ok(results.some(f => f.rule === 'EMBEDDED_SOURCE_CONTENT'));
    assert.ok(!JSON.stringify(results).includes('SECRET_SYNTHETIC_TEST_MARKER'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
