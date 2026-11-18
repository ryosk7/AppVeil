import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { compareArtifacts } from '../src/benchmark.mjs';

test('reports reproducible artifact metrics without declaring security', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'appveil-bench-'));
  try {
    const a = path.join(dir, 'a.js'), b = path.join(dir, 'b.wasm');
    writeFileSync(a, 'function secretAlgorithm(){return 42;}');
    writeFileSync(b, Buffer.from([0,97,115,109,1,0,0,0]));
    const result = compareArtifacts([a,b], ['secretAlgorithm']);
    assert.equal(result.samples.length, 2);
    assert.deepEqual(result.samples[0].visibleMarkers, ['secretAlgorithm']);
    assert.deepEqual(result.samples[1].visibleMarkers, []);
    assert.match(result.warning, /NOT AI/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
